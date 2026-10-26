import json
import logging
import os
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

os.environ["PHISHGUARD_NO_AUTOCREATE"] = "1"
from app import create_app  # noqa: E402
from predictor import ModelNotAvailableError, ModelService  # noqa: E402
from tests.helpers import MODEL_DIR, REAL_CSV, REAL_MODEL_AVAILABLE, REPORT_DIR  # noqa: E402

ORIGIN = "http://localhost:5173"


class StubPipeline:
    """Stands in for the trained pipeline so we can prove the API returns whatever the MODEL says."""
    def __init__(self, p_phish):
        self.p, self.calls = p_phish, []

    def predict_proba(self, frame):
        self.calls.append(frame)
        return np.array([[1 - self.p, self.p]] * len(frame))


def stub_service(p_phish):
    svc = ModelService("unused")
    svc.pipeline, svc._pos_idx = StubPipeline(p_phish), 1
    svc.meta = {"model_name": "Stub", "model_version": "0", "decision_threshold": 0.5, "analysis_scope": "hostname_only"}
    return svc


class ApiWithStubModel(unittest.TestCase):
    def client(self, p, **kw):
        svc = stub_service(p)
        return create_app(service=svc, frontend_origin=ORIGIN, **kw).test_client(), svc

    def test_health(self):
        c, _ = self.client(0.5)
        r = c.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json["status"], r.json["model_loaded"]), ("ok", True))

    def test_prediction_comes_from_model_probability(self):
        c, svc = self.client(0.9123)
        r = c.post("/api/predict", json={"url": "https://never-seen-before.example.xyz/login"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["phishing_probability"], 0.9123)
        self.assertEqual((r.json["prediction"], r.json["label"]), ("phishing", "Potential Phishing"))
        self.assertEqual(r.json["analyzed_host"], "never-seen-before.example.xyz")
        self.assertEqual(len(svc.pipeline.calls), 1)                        # model really was called
        self.assertEqual(svc.pipeline.calls[0]["tld"].iloc[0], "xyz")        # ... with the extracted features
        c2, _ = self.client(0.0123)
        r2 = c2.post("/api/predict", json={"url": "https://never-seen-before.example.xyz/login"})
        self.assertEqual((r2.json["prediction"], r2.json["label"]), ("legitimate", "Likely Legitimate"))

    def test_response_documents_scope(self):
        c, _ = self.client(0.2)
        j = c.post("/api/predict", json={"url": "https://www.example.com/a?b=1"}).json
        self.assertTrue(j["www_removed"] and j["path_or_query_ignored"])
        self.assertTrue(any("not a guarantee" in n for n in j["notes"]))

    def test_validation_errors(self):
        c, _ = self.client(0.5)
        cases = [({"url": ""}, 422, "invalid_url"), ({"url": "not a url"}, 422, "invalid_url"),
                 ({"url": "javascript:alert(1)"}, 422, "invalid_url"), ({"url": "x" * 3000}, 422, "invalid_url"),
                 ({"url": 5}, 400, "bad_request"), ({"nope": 1}, 400, "bad_request"), ([1, 2], 400, "bad_request")]
        for body, status, code in cases:
            with self.subTest(body=str(body)[:30]):
                r = c.post("/api/predict", json=body)
                self.assertEqual((r.status_code, r.json["error"]["code"]), (status, code))
                self.assertTrue(r.json["error"]["message"])
        r = c.post("/api/predict", data="not json", content_type="text/plain")
        self.assertEqual(r.status_code, 400)
        r = c.post("/api/predict", data=b"x" * 40000, content_type="application/json")
        self.assertEqual(r.status_code, 413)

    def test_routes_and_methods(self):
        c, _ = self.client(0.5)
        self.assertEqual(c.get("/api/predict").status_code, 405)
        r = c.get("/api/nothing")
        self.assertEqual((r.status_code, r.json["error"]["code"]), (404, "not_found"))

    def test_cors_only_for_configured_origin(self):
        c, _ = self.client(0.5)
        ok = c.get("/api/health", headers={"Origin": ORIGIN})
        self.assertEqual(ok.headers.get("Access-Control-Allow-Origin"), ORIGIN)
        bad = c.get("/api/health", headers={"Origin": "http://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", bad.headers)
        pre = c.options("/api/predict", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST",
                                                 "Access-Control-Request-Headers": "content-type"})
        self.assertIn(pre.status_code, (200, 204))
        self.assertEqual(pre.headers.get("Access-Control-Allow-Origin"), ORIGIN)
        self.assertIn("POST", pre.headers.get("Access-Control-Allow-Methods", ""))

    def test_submitted_url_is_not_logged(self):
        c, _ = self.client(0.7)
        secret = "very-secret-host-12345.example.org"
        with self.assertLogs("phishguard", level="INFO") as cm:
            c.post("/api/predict", json={"url": f"https://{secret}/token=abc"})
        self.assertTrue(cm.output)
        self.assertFalse(any(secret in line for line in cm.output))

    def test_report_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            c = create_app(service=stub_service(0.5), report_dir=d, frontend_origin=ORIGIN).test_client()
            r = c.get("/api/report")
            self.assertEqual((r.status_code, r.json["error"]["code"]), (404, "report_not_available"))
            (Path(d) / "training_report.json").write_text(json.dumps({"hello": "world"}))
            self.assertEqual(c.get("/api/report").json, {"hello": "world"})
            (Path(d) / "training_report.json").write_text("{broken")
            self.assertEqual(c.get("/api/report").status_code, 500)


class ApiWithMissingModel(unittest.TestCase):
    def test_missing_model_files(self):
        with tempfile.TemporaryDirectory() as d:
            c = create_app(model_dir=d, frontend_origin=ORIGIN).test_client()
            h = c.get("/api/health")
            self.assertEqual(h.status_code, 200)
            self.assertFalse(h.json["model_loaded"])
            self.assertIn("train.py", h.json["message"])
            r = c.post("/api/predict", json={"url": "https://example.com"})
            self.assertEqual((r.status_code, r.json["error"]["code"]), (503, "model_not_available"))
            self.assertIn("python train.py", r.json["error"]["message"])

    def test_corrupt_model_file(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "phishguard_model.joblib").write_bytes(b"garbage")
            (Path(d) / "model_meta.json").write_text("{}")
            with self.assertRaises(ModelNotAvailableError):
                ModelService(d).load()

    def test_predict_before_load_raises(self):
        with self.assertRaises(ModelNotAvailableError):
            ModelService("nowhere").predict("https://example.com")


@unittest.skipUnless(REAL_MODEL_AVAILABLE, "trained model not found - run python train.py first")
class ApiWithRealModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app(model_dir=MODEL_DIR, report_dir=REPORT_DIR, frontend_origin=ORIGIN)
        cls.client = cls.app.test_client()
        cls.svc = cls.app.extensions["model_service"]

    def test_real_model_loaded_and_health(self):
        j = self.client.get("/api/health").json
        self.assertTrue(j["model_loaded"])

    def test_new_url_uses_saved_model_not_dataset_lookup(self):
        url = "https://totally-new-host-qz81x7.example-brand-login.top/verify"
        host = "totally-new-host-qz81x7.example-brand-login.top"
        if REAL_CSV.is_file():  # confirm the host is genuinely unseen
            urls = pd.read_csv(REAL_CSV, usecols=["URL"])["URL"]
            self.assertFalse(urls.str.contains("totally-new-host-qz81x7", regex=False).any())
        # independent computation with the saved pipeline
        from feature_extractor import features_frame
        expected = float(self.svc.pipeline.predict_proba(features_frame([host]))[0][self.svc._pos_idx])
        # prove no dataset file is read while predicting
        orig = pd.read_csv
        pd.read_csv = lambda *a, **k: (_ for _ in ()).throw(AssertionError("dataset was read during prediction"))
        try:
            r = self.client.post("/api/predict", json={"url": url})
        finally:
            pd.read_csv = orig
        self.assertEqual(r.status_code, 200)
        self.assertAlmostEqual(r.json["phishing_probability"], expected, places=4)
        self.assertEqual(r.json["analyzed_host"], host)

    def test_different_urls_give_different_scores(self):
        a = self.client.post("/api/predict", json={"url": "https://wikipedia.org"}).json["phishing_probability"]
        b = self.client.post("/api/predict", json={"url": "http://secure-paypal-login.verify-account.xyz"}).json["phishing_probability"]
        self.assertNotEqual(a, b)
        self.assertGreater(b, a)

    def test_scheme_www_path_are_ignored(self):
        probs = {self.client.post("/api/predict", json={"url": u}).json["phishing_probability"]
                 for u in ("example.org", "http://example.org", "https://www.example.org/a/b?c=d#e", "HTTPS://EXAMPLE.ORG:8443")}
        self.assertEqual(len(probs), 1)

    def test_report_available(self):
        r = self.client.get("/api/report")
        self.assertEqual(r.status_code, 200)
        self.assertIn("final_model", r.json)


@unittest.skipUnless(REAL_MODEL_AVAILABLE, "trained model not found - run python train.py first")
class TrainingInferenceConsistency(unittest.TestCase):
    def test_feature_names_and_order_match(self):
        from feature_extractor import FEATURE_COLUMNS
        svc = ModelService(MODEL_DIR)
        svc.load()
        self.assertEqual(list(svc.pipeline.feature_names_in_), FEATURE_COLUMNS)
        self.assertEqual(svc.meta["feature_columns"], FEATURE_COLUMNS)

    @unittest.skipUnless(REAL_CSV.is_file(), "real dataset not present")
    def test_dataset_urls_get_identical_features_in_training_and_inference(self):
        import train
        from feature_extractor import features_frame, parse_url
        sample = pd.read_csv(REAL_CSV, usecols=["URL", "label"]).sample(300, random_state=3)
        clean, _ = train.clean_dataset(sample)
        training_frame = features_frame(clean["host"])             # path used by train.py
        svc = ModelService(MODEL_DIR)
        svc.load()
        for host, (_, train_row) in zip(clean["host"], training_frame.iterrows()):
            api_row = svc.predict(f"https://{host}/")["features"]   # path used by the API
            for k, v in api_row.items():
                if isinstance(v, str):
                    self.assertEqual(v, train_row[k])
                else:
                    self.assertAlmostEqual(v, float(train_row[k]), places=3)


if __name__ == "__main__":
    unittest.main()
