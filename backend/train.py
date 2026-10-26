#!/usr/bin/env python
"""
train.py - trains PhishGuard AI and writes the model + real evaluation report.

    python train.py                                  (uses data/PhiUSIIL_Phishing_URL_Dataset.csv)
    python train.py --data path\\to\\file.csv

Pipeline
  1. Load the CSV and check columns / label values.
  2. Map labels:  dataset label 1 = legitimate, 0 = phishing  ->  model target y: 1 = PHISHING, 0 = legitimate.
  3. Clean: drop missing + duplicate URLs, drop URLs that are not valid http(s) hostnames,
     drop hostnames that carry BOTH labels, keep one row per hostname.
  4. Features: hostname-only lexical features from feature_extractor.py (same code used at prediction time).
  5. Split 80/20 with GroupShuffleSplit; the group is the registered domain (example.com),
     so related hostnames never sit in both train and test.
  6. Compare 3 models with 3-fold StratifiedGroupKFold CV on the TRAINING part only.
     The winner is the one with the best mean phishing F2 (recall counts twice as much as precision).
  7. Refit the winner on the full training part, evaluate ONCE on the untouched test part.
  8. Save model, metadata and report (reports/training_report.json).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, fbeta_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from feature_extractor import (CATEGORICAL_COLUMNS, FEATURE_COLUMNS, FEATURE_DESCRIPTIONS,
                               NUMERIC_COLUMNS, InvalidURLError, features_frame,
                               parse_url, registered_domain_key)

HERE = Path(__file__).resolve().parent
DEFAULT_DATA = HERE / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_FILE = "phishguard_model.joblib"
META_FILE = "model_meta.json"
REPORT_FILE = "training_report.json"
EXPECTED_ROWS, EXPECTED_COLS = 235_795, 56
MODEL_VERSION = "1.0.0"
DECISION_THRESHOLD = 0.5
# Features that describe "how many parts does the hostname have" - used only for the ablation check.
STRUCTURE_FEATURES = ["num_dots", "num_labels"]

log = logging.getLogger("phishguard.train")


# ------------------------------------------------------------------ data loading
def load_dataset(path: Path) -> pd.DataFrame:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}. Put the CSV in backend/data/ or use --data.")
    df = pd.read_csv(path)
    missing = {"URL", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required column(s): {sorted(missing)}")
    bad = set(df["label"].dropna().unique()) - {0, 1}
    if bad:
        raise ValueError(f"Unexpected label values {sorted(bad)}; expected only 0 and 1.")
    if df.shape != (EXPECTED_ROWS, EXPECTED_COLS):
        log.warning("Dataset shape is %s, the PhiUSIIL file normally is (%d, %d).", df.shape, EXPECTED_ROWS, EXPECTED_COLS)
    return df


def map_labels(label: pd.Series) -> pd.Series:
    """Dataset: 1 = legitimate, 0 = phishing.  Model target: 1 = phishing, 0 = legitimate."""
    return (1 - label.astype(int)).astype(int)


def class_counts(y: pd.Series) -> dict:
    return {"legitimate": int((y == 0).sum()), "phishing": int((y == 1).sum())}


def clean_dataset(raw: pd.DataFrame):
    """Returns (clean_df with columns host,y,group ; stats dict)."""
    stats: dict = {"rows_raw": int(len(raw))}
    df = raw[["URL", "label"]].copy()
    df["y"] = map_labels(df["label"]) if df["label"].notna().all() else None
    stats["raw_class_counts"] = class_counts(df["y"]) if df["y"].notna().all() else {}

    before = len(df)
    df = df.dropna(subset=["URL", "label"]).copy()
    df["y"] = map_labels(df["label"])
    df["URL"] = df["URL"].astype(str).str.strip()
    stats["dropped_missing"] = before - len(df)

    # exact duplicate URLs (and URLs that appear with different labels)
    conflict_urls = df.groupby("URL")["y"].nunique()
    conflict_urls = set(conflict_urls[conflict_urls > 1].index)
    stats["urls_with_conflicting_labels"] = len(conflict_urls)
    df = df[~df["URL"].isin(conflict_urls)]
    before = len(df)
    df = df.drop_duplicates(subset="URL")
    stats["dropped_duplicate_urls"] = before - len(df)

    # normalize to hostnames; invalid URLs are dropped
    hosts, reasons = [], Counter()
    for u in df["URL"]:
        try:
            hosts.append(parse_url(u).host)
        except InvalidURLError as exc:
            hosts.append(None)
            reasons[str(exc)] += 1
    df["host"] = hosts
    stats["dropped_invalid_urls"] = int(df["host"].isna().sum())
    stats["invalid_url_reasons"] = dict(reasons.most_common(5))
    df = df.dropna(subset=["host"])

    # the same hostname with both labels cannot be learned by a hostname-only model
    host_labels = df.groupby("host")["y"].nunique()
    conflict_hosts = set(host_labels[host_labels > 1].index)
    stats["hostnames_with_conflicting_labels"] = len(conflict_hosts)
    stats["rows_removed_for_conflicting_hostnames"] = int(df["host"].isin(conflict_hosts).sum())
    df = df[~df["host"].isin(conflict_hosts)]

    before = len(df)
    df = df.drop_duplicates(subset="host")  # one row per hostname
    stats["dropped_duplicate_hostnames"] = before - len(df)

    df = df[["host", "y"]].reset_index(drop=True)
    df["group"] = df["host"].map(registered_domain_key)
    stats["rows_clean"] = int(len(df))
    stats["clean_class_counts"] = class_counts(df["y"])
    return df, stats


# ------------------------------------------------------------------ models
def make_preprocessor(scale: bool, min_tld_freq: int, numeric=None) -> ColumnTransformer:
    """Learned parts (scaler, TLD vocabulary) are fitted on training data only, inside the Pipeline."""
    return ColumnTransformer([
        ("num", StandardScaler() if scale else "passthrough", list(numeric or NUMERIC_COLUMNS)),
        ("tld", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=min_tld_freq,
                              sparse_output=False), CATEGORICAL_COLUMNS),
    ])


def make_candidates(seed: int, min_tld_freq: int, numeric=None) -> dict:
    return {
        "Logistic Regression": Pipeline([
            ("prep", make_preprocessor(True, min_tld_freq, numeric)),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed))]),
        "Random Forest": Pipeline([
            ("prep", make_preprocessor(False, min_tld_freq, numeric)),
            ("clf", RandomForestClassifier(n_estimators=100, min_samples_leaf=50, class_weight="balanced_subsample",
                                           n_jobs=-1, random_state=seed))]),
        "Gradient Boosting": Pipeline([
            ("prep", make_preprocessor(False, min_tld_freq, numeric)),
            ("clf", HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08, max_leaf_nodes=31,
                                                   class_weight="balanced", random_state=seed))]),
    }


CANDIDATE_NOTES = {
    "Logistic Regression": "Simple linear baseline; easy to explain; needs scaled inputs.",
    "Random Forest": "Many decision trees voting together; handles non-linear patterns and mixed features.",
    "Gradient Boosting": "Trees built one after another, each fixing the previous errors; strong on tabular data.",
}


# ------------------------------------------------------------------ metrics
def compute_metrics(y_true, y_prob, threshold=DECISION_THRESHOLD) -> dict:
    y_true = np.asarray(y_true)
    y_pred = (np.asarray(y_prob) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "f2": fbeta_score(y_true, y_pred, beta=2, zero_division=0),
        "roc_auc": roc_auc_score(y_true, y_prob) if len(set(y_true)) == 2 else float("nan"),
        "specificity": tn / (tn + fp) if (tn + fp) else float("nan"),
        "false_negative_rate": fn / (fn + tp) if (fn + tp) else float("nan"),
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else float("nan"),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def summarize_folds(fold_metrics: list) -> dict:
    keys = ["accuracy", "precision", "recall", "f1", "f2", "roc_auc", "false_negative_rate"]
    return {k: {"mean": float(np.mean([m[k] for m in fold_metrics])),
                "std": float(np.std([m[k] for m in fold_metrics]))} for k in keys}


def cross_validate_candidate(pipe, X, y, groups, seed, n_splits=3) -> list:
    out = []
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    for fold, (tr, va) in enumerate(cv.split(X, y, groups), 1):
        m = clone(pipe).fit(X.iloc[tr], y.iloc[tr])
        out.append(compute_metrics(y.iloc[va], m.predict_proba(X.iloc[va])[:, 1]))
        log.info("    fold %d: recall=%.3f precision=%.3f f2=%.3f", fold, out[-1]["recall"], out[-1]["precision"], out[-1]["f2"])
    return out


def thin_roc(y_true, y_prob, max_points=200) -> dict:
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    if len(fpr) > max_points:
        idx = np.unique(np.linspace(0, len(fpr) - 1, max_points).astype(int))
        fpr, tpr = fpr[idx], tpr[idx]
    return {"fpr": [round(float(v), 4) for v in fpr], "tpr": [round(float(v), 4) for v in tpr]}


ILLUSTRATIVE_HOSTS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "mail.python.org", "accounts.google.com",
    "paypal-secure-login.verify-account.xyz", "secure-update.bank-login.top", "xj3k9q2vz.top", "192.168.10.5",
]


# ------------------------------------------------------------------ main routine
def run_training(data_path, models_dir, reports_dir, seed=42, max_rows=None, test_size=0.2) -> dict:
    t0 = time.time()
    models_dir, reports_dir = Path(models_dir), Path(reports_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    raw = load_dataset(data_path)
    log.info("Loaded %s: %d rows x %d columns", Path(data_path).name, *raw.shape)
    if max_rows and max_rows < len(raw):
        raw = raw.sample(max_rows, random_state=seed)
        log.warning("--max-rows used: training on a SAMPLE of %d rows (for quick tests only).", len(raw))

    sha = hashlib.sha256(Path(data_path).read_bytes()).hexdigest()
    clean, cstats = clean_dataset(raw)
    log.info("Cleaning: %s", json.dumps({k: v for k, v in cstats.items() if k != "invalid_url_reasons"}))
    if min(cstats["clean_class_counts"].values()) < 10:
        raise ValueError("Too few examples of one class after cleaning to train a model.")

    X = features_frame(clean["host"])
    y = clean["y"].reset_index(drop=True)
    groups = clean["group"].reset_index(drop=True)

    # shortcut check: how many hostname parts does each class have?
    structure = {cls: float((X.loc[y == v, "num_labels"] <= 2).mean()) for cls, v in (("legitimate", 0), ("phishing", 1))}
    log.info("Share of hostnames with <= 2 labels (e.g. example.com): %s", structure)

    # ---- grouped split
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    tr_idx, te_idx = next(splitter.split(X, y, groups))
    Xtr, Xte, ytr, yte = X.iloc[tr_idx], X.iloc[te_idx], y.iloc[tr_idx], y.iloc[te_idx]
    gtr = groups.iloc[tr_idx]
    host_overlap = set(clean["host"].iloc[tr_idx]) & set(clean["host"].iloc[te_idx])
    group_overlap = set(gtr) & set(groups.iloc[te_idx])
    assert not host_overlap and not group_overlap, "Train/test leakage detected!"
    log.info("Split: train=%d test=%d | train groups=%d test groups=%d | overlap hosts=%d groups=%d",
             len(Xtr), len(Xte), gtr.nunique(), groups.iloc[te_idx].nunique(), len(host_overlap), len(group_overlap))

    min_tld = max(5, int(len(Xtr) * 0.001))
    candidates = make_candidates(seed, min_tld)

    # ---- model comparison (training data only)
    results = []
    for name, pipe in candidates.items():
        log.info("Cross-validating %s ...", name)
        folds = cross_validate_candidate(pipe, Xtr, ytr, gtr, seed)
        results.append({"name": name, "description": CANDIDATE_NOTES[name], "cv": summarize_folds(folds)})
    best = max(results, key=lambda r: r["cv"]["f2"]["mean"])
    for r in results:
        r["selected"] = r["name"] == best["name"]
    log.info("Selected model: %s (mean CV phishing F2 = %.4f)", best["name"], best["cv"]["f2"]["mean"])

    # ---- final fit + single test evaluation
    final = clone(candidates[best["name"]]).fit(Xtr, ytr)
    p_test = final.predict_proba(Xte)[:, 1]
    test = compute_metrics(yte, p_test)
    log.info("TEST: acc=%.4f precision=%.4f recall=%.4f f1=%.4f auc=%.4f FNR=%.4f | TN=%d FP=%d FN=%d TP=%d",
             test["accuracy"], test["precision"], test["recall"], test["f1"], test["roc_auc"],
             test["false_negative_rate"], test["tn"], test["fp"], test["fn"], test["tp"])

    # ---- ablation: same model type without the hostname-structure features
    numeric_wo = [c for c in NUMERIC_COLUMNS if c not in STRUCTURE_FEATURES]
    abl = clone(make_candidates(seed, min_tld, numeric_wo)[best["name"]]).fit(Xtr, ytr)
    abl_m = compute_metrics(yte, abl.predict_proba(Xte)[:, 1])
    log.info("ABLATION (without %s): acc=%.4f recall=%.4f auc=%.4f", STRUCTURE_FEATURES, abl_m["accuracy"], abl_m["recall"], abl_m["roc_auc"])

    # ---- feature importance (permutation, on a test sample)
    n_imp = min(10_000, len(Xte))
    sample = np.random.RandomState(seed).choice(len(Xte), n_imp, replace=False)
    imp = permutation_importance(final, Xte.iloc[sample], yte.iloc[sample], scoring="roc_auc",
                                 n_repeats=3, random_state=seed, n_jobs=1)
    importance = sorted(({"feature": f, "importance": float(m)} for f, m in zip(FEATURE_COLUMNS, imp.importances_mean)),
                        key=lambda d: -d["importance"])

    # ---- illustrative predictions (NOT an evaluation)
    ill_p = final.predict_proba(features_frame(ILLUSTRATIVE_HOSTS))[:, 1]
    illustrative = [{"host": h, "phishing_probability": round(float(p), 4)} for h, p in zip(ILLUSTRATIVE_HOSTS, ill_p)]
    for row in illustrative:
        log.info("  illustrative: %-42s P(phishing)=%.3f", row["host"], row["phishing_probability"])

    # ---- save artefacts
    joblib.dump(final, models_dir / MODEL_FILE, compress=3)
    clf = final.named_steps["clf"]
    meta = {
        "model_name": best["name"], "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__, "python_version": platform.python_version(),
        "analysis_scope": "hostname_only",
        "target": {"positive_class": "phishing", "negative_class": "legitimate", "classes_": [int(c) for c in clf.classes_]},
        "dataset_label_mapping": {"1": "legitimate", "0": "phishing"},
        "decision_threshold": DECISION_THRESHOLD,
        "feature_columns": FEATURE_COLUMNS, "numeric_columns": NUMERIC_COLUMNS, "categorical_columns": CATEGORICAL_COLUMNS,
    }
    (models_dir / META_FILE).write_text(json.dumps(meta, indent=2))

    report = {
        "generated_at": meta["trained_at"], "training_seconds": round(time.time() - t0, 1), "seed": seed,
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                     "pandas": pd.__version__, "numpy": np.__version__},
        "dataset": {"file": Path(data_path).name, "sha256": sha, "rows_raw": int(raw.shape[0]), "columns_raw": int(raw.shape[1]),
                    "label_mapping": {"dataset_1": "legitimate", "dataset_0": "phishing"},
                    "used_columns": ["URL", "label"], "sampled": bool(max_rows)},
        "cleaning": cstats,
        "class_distribution": {
            "raw": cstats["raw_class_counts"], "after_cleaning": cstats["clean_class_counts"],
            "train": class_counts(ytr), "test": class_counts(yte)},
        "hostname_structure_check": {"share_with_two_or_fewer_labels": structure},
        "split": {"strategy": "GroupShuffleSplit by registered domain (e.g. example.com)", "test_size": test_size,
                  "train_rows": int(len(Xtr)), "test_rows": int(len(Xte)),
                  "train_groups": int(gtr.nunique()), "test_groups": int(groups.iloc[te_idx].nunique()),
                  "overlapping_hostnames": len(host_overlap), "overlapping_groups": len(group_overlap)},
        "features": [{"name": c, "type": "categorical" if c in CATEGORICAL_COLUMNS else "numeric",
                      "description": FEATURE_DESCRIPTIONS[c]} for c in FEATURE_COLUMNS],
        "selection": {"method": "3-fold StratifiedGroupKFold on the training part", "criterion": "highest mean phishing F2 (recall-weighted)",
                      "selected": best["name"]},
        "candidates": results,
        "final_model": {"name": best["name"], "decision_threshold": DECISION_THRESHOLD, "test": test,
                        "confusion_matrix": {"tn": test["tn"], "fp": test["fp"], "fn": test["fn"], "tp": test["tp"]},
                        "roc": {**thin_roc(yte, p_test), "auc": test["roc_auc"]}},
        "baselines": {"majority_class_accuracy": float(max(class_counts(yte).values()) / len(yte))},
        "ablation": {"description": f"Same model without {STRUCTURE_FEATURES} (checks reliance on hostname-structure features)",
                     "removed_features": STRUCTURE_FEATURES, "test": abl_m},
        "feature_importance": importance,
        "illustrative_examples": {"note": "A handful of hand-picked hostnames to sanity-check behaviour. NOT an evaluation.", "rows": illustrative},
    }
    (reports_dir / REPORT_FILE).write_text(json.dumps(report, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    log.info("Saved model -> %s, report -> %s (%.1f s)", models_dir / MODEL_FILE, reports_dir / REPORT_FILE, time.time() - t0)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Train the PhishGuard AI model.")
    ap.add_argument("--data", default=str(DEFAULT_DATA))
    ap.add_argument("--models-dir", default=str(HERE / "models"))
    ap.add_argument("--reports-dir", default=str(HERE / "reports"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-rows", type=int, default=None, help="train on a random sample (quick tests only)")
    args = ap.parse_args(argv)

    Path(args.reports_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S", force=True,
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(Path(args.reports_dir) / "training_log.txt", mode="w", encoding="utf-8")])
    try:
        run_training(args.data, args.models_dir, args.reports_dir, args.seed, args.max_rows)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Training stopped: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
