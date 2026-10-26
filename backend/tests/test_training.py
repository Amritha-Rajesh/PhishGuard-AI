import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

import train
from tests.helpers import REAL_CSV, make_tiny_dataset


class LabelMappingTests(unittest.TestCase):
    def test_map_labels(self):
        # dataset: 1 = legitimate, 0 = phishing  ->  model: 1 = phishing
        self.assertEqual(train.map_labels(pd.Series([1, 0, 1, 0])).tolist(), [0, 1, 0, 1])


class CleaningTests(unittest.TestCase):
    def setUp(self):
        self.raw = make_tiny_dataset()
        self.clean, self.stats = train.clean_dataset(self.raw)

    def test_problems_are_removed_and_counted(self):
        self.assertEqual(self.stats["dropped_duplicate_urls"], 1)
        self.assertEqual(self.stats["dropped_invalid_urls"], 2)
        self.assertEqual(self.stats["hostnames_with_conflicting_labels"], 1)
        self.assertNotIn("conflict.com", set(self.clean["host"]))
        self.assertTrue(self.clean["host"].is_unique)
        self.assertFalse(self.clean.isna().any().any())

    def test_target_is_phishing_positive(self):
        legit = self.clean[self.clean.host.str.endswith(".com")]
        phish = self.clean[self.clean.host.str.endswith(".xyz")]
        self.assertTrue((legit.y == 0).all() and (phish.y == 1).all())

    def test_missing_columns_and_bad_labels_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.csv"
            pd.DataFrame({"URL": ["http://a.com"], "other": [1]}).to_csv(p, index=False)
            with self.assertRaisesRegex(ValueError, "missing required"):
                train.load_dataset(p)
            pd.DataFrame({"URL": ["http://a.com"], "label": [7]}).to_csv(p, index=False)
            with self.assertRaisesRegex(ValueError, "label values"):
                train.load_dataset(p)
            with self.assertRaises(FileNotFoundError):
                train.load_dataset(Path(d) / "nope.csv")


class EndToEndTrainingTests(unittest.TestCase):
    """Trains on the tiny synthetic file: checks plumbing (saving, report, split), not model quality."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        make_tiny_dataset().to_csv(d / "tiny.csv", index=False)
        cls.report = train.run_training(d / "tiny.csv", d / "models", d / "reports")
        cls.dir = d

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_artifacts_saved(self):
        for rel in ("models/phishguard_model.joblib", "models/model_meta.json", "reports/training_report.json"):
            self.assertTrue((self.dir / rel).is_file(), rel)

    def test_no_leakage_between_train_and_test(self):
        s = self.report["split"]
        self.assertEqual((s["overlapping_hostnames"], s["overlapping_groups"]), (0, 0))
        self.assertEqual(s["train_rows"] + s["test_rows"], self.report["cleaning"]["rows_clean"])

    def test_report_contents(self):
        r = json.loads((self.dir / "reports/training_report.json").read_text())
        self.assertEqual(len(r["candidates"]), 3)
        self.assertEqual(sum(c["selected"] for c in r["candidates"]), 1)
        cm = r["final_model"]["confusion_matrix"]
        self.assertEqual(sum(cm.values()), r["split"]["test_rows"])
        t = r["final_model"]["test"]
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            self.assertTrue(0.0 <= t[k] <= 1.0, k)
        self.assertEqual(r["class_distribution"]["train"]["phishing"] + r["class_distribution"]["test"]["phishing"],
                         r["class_distribution"]["after_cleaning"]["phishing"])

    def test_metrics_helper_matches_confusion_matrix(self):
        m = train.compute_metrics([1, 1, 0, 0, 1], [0.9, 0.2, 0.1, 0.8, 0.7])
        self.assertEqual((m["tp"], m["fn"], m["fp"], m["tn"]), (2, 1, 1, 1))
        self.assertAlmostEqual(m["recall"], 2 / 3)
        self.assertAlmostEqual(m["precision"], 2 / 3)


@unittest.skipUnless(REAL_CSV.is_file(), "real dataset not present")
class RealDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = train.load_dataset(REAL_CSV)

    def test_shape_and_labels(self):
        self.assertEqual(self.df.shape, (235795, 56))
        self.assertEqual(set(self.df.label.unique()), {0, 1})
        counts = train.class_counts(train.map_labels(self.df.label))
        self.assertEqual(counts, {"legitimate": 134850, "phishing": 100945})

    def test_label_mapping_on_real_urls(self):
        y = train.map_labels(self.df.label)
        phish_urls = self.df.loc[y == 1, "URL"]
        self.assertGreater(phish_urls.str.startswith("http://").mean(), 0.3)   # phishing rows include plain http
        self.assertTrue(self.df.loc[y == 0, "URL"].str.match(r"^https://www\.").all())  # legit rows are https://www.


if __name__ == "__main__":
    unittest.main()
