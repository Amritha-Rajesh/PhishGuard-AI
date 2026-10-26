# PhishGuard AI
**A Machine Learning-Based Phishing URL Detection System** (college Machine Learning and Data Mining project)

A user types a URL, clicks **Scan URL**, and a trained model estimates whether it is **Likely Legitimate** or **Potential Phishing**. The model reads only the **hostname text** of the URL. It never opens, downloads or follows the link, and it does not use any blocklist or threat-intelligence service.

> **Honest summary of the results:** on hostnames it never saw, the final model reaches **85.0% accuracy, 85.5% precision and 65.4% recall** for phishing (ROC-AUC 0.871). It misses about **1 in 3** phishing hostnames, and it tends to flag legitimate hostnames that have subdomains (e.g. `accounts.google.com`). It is an estimate, not a safety guarantee. See [Limitations](#10-limitations).

---
## 1. Problem statement and objectives
Phishing links imitate trusted sites to steal passwords and money. Blocklists only contain sites that were already reported. A model that recognises suspicious patterns in the link itself can help with new ones.

Objectives: (1) train and compare ML models on a real dataset, (2) predict **new** URLs using exactly the same feature code as in training, (3) report honest evaluation results and limitations, (4) provide a working web application (React + Flask).

## 2. Dataset inspection and suitability findings
Dataset: **PhiUSIIL Phishing URL Dataset** (UCI repository), file `PhiUSIIL_Phishing_URL_Dataset.csv`.

| Item | Finding |
|---|---|
| Size | 235,795 rows x 56 columns, no missing values |
| Label column | `label`: **1 = legitimate (134,850)**, **0 = phishing (100,945)** |
| Used columns | only `URL` and `label` |
| Excluded columns | page-content columns (HTML, forms, JavaScript, title ...) cannot be calculated without visiting the site; some URL-based columns (e.g. `URLSimilarityIndex`, `TLDLegitimateProb`) depend on undisclosed reference data or labels |

**Important finding (shortcut):** every legitimate URL in the file has the exact shape `https://www.<domain>` with no path, while only 0.6% of phishing URLs do. A rule "https + www + no path = legitimate" scores 99.7% accuracy without machine learning. A model on full URLs would therefore learn this formatting shortcut and fail on real links. **Fix:** this project analyses only the **normalized hostname** (scheme, `www.`, port, path and query removed).

Remaining weakness: legitimate hostnames in the file are mostly plain registered domains (85% have two labels or fewer, against 43% of phishing hostnames), so hostnames with subdomains look "more phishing" to the model.

## 3. Technologies
Python 3.11+, pandas, NumPy, scikit-learn, joblib, Flask (backend); React 18 + Vite (frontend); `unittest` and Node's built-in test runner for tests.

## 4. Preprocessing and feature extraction
`backend/feature_extractor.py` is used by **both** training and prediction.

1. **Normalize** the URL: trim, add `http://` if missing, accept only http/https, lowercase the hostname, convert international names to punycode, remove a leading `www.`, drop port/path/query/fragment. Invalid input (empty, spaces, no dot, bad characters, > 2048 characters, `javascript:` ...) raises a clear error.
2. **Cleaning of the dataset** (`train.py`): label mapping (model target: **1 = phishing**), 425 duplicate URLs removed, 8 invalid URLs removed (all longer than 2048 characters), 58 hostnames that appeared with *both* labels removed (159 rows), and 16,170 repeated hostnames collapsed so each hostname counts once. Result: **219,033 hostnames (134,792 legitimate, 84,241 phishing)**.
3. **Features** (17 numeric + 1 category, all from the hostname string): host length, dots, hyphens, digits, digit ratio, number of labels, longest / average / first label length, character entropy, is-IP, TLD length, has punycode, vowel ratio, longest consonant run, longest digit run, count of suspicious keywords (login, secure, verify ...), and the **TLD** as a category (rare TLDs are grouped by the encoder; learned on training data only).

## 5. Algorithms and training procedure
`python train.py` does:
1. Split 80 / 20 with **GroupShuffleSplit**; the group is the registered domain (`example.com`, `shop.co.uk`), so related hostnames never appear in both parts (0 overlapping hostnames, 0 overlapping groups). This is stricter than splitting by hostname.
2. Compare **Logistic Regression**, **Random Forest** and **Gradient Boosting** with 3-fold grouped cross-validation on the training part only. The scaler and TLD encoder are inside the pipeline, so they are fitted on training folds only.
3. Choose the model with the best mean **phishing F2** (recall counts twice as much as precision).
4. Refit the winner on the whole training part and evaluate **once** on the test part.
5. Save the model, metadata, report and log.

## 6. Actual evaluation results (from `backend/reports/training_report.json`)
Split: train 178,705 hostnames, test 40,328 (13,238 phishing, 27,090 legitimate). Phishing is the positive class. Always predicting "legitimate" would score 67.2% accuracy.

**Cross-validation on the training part (mean of 3 folds)**

| Model | Accuracy | Precision | Recall | F1 | F2 | ROC-AUC |
|---|---|---|---|---|---|---|
| Logistic Regression | 85.3% | 89.2% | 71.7% | 79.5% | 74.7% | 0.891 |
| Random Forest | 85.3% | 88.8% | 72.1% | 79.6% | 74.9% | 0.889 |
| **Gradient Boosting (selected)** | 86.0% | 89.6% | 73.1% | 80.5% | 75.9% | 0.899 |

**Final model on the untouched test set**

| Accuracy | Precision | Recall | F1 | ROC-AUC | Missed phishing (FNR) | False alarms (FPR) |
|---|---|---|---|---|---|---|
| 85.0% | 85.5% | 65.4% | 74.1% | 0.871 | 34.6% | 5.4% |

Confusion matrix (rows = actual): legitimate -> 25,624 correct, 1,466 false alarms; phishing -> 4,580 missed, 8,658 caught.

Notes: test recall (65.4%) is lower than cross-validation recall (73.1%); the test groups are a different random sample with a different class mix (33% phishing vs 40% in training) and I did not investigate the gap further. Removing the dot-count and label-count features changed accuracy only from 85.0% to 84.9%. The most important feature is the **TLD** (such as `.xyz`, `.top`), then dot count.

## 7. Architecture and prediction workflow
```
React (Vite)  --POST /api/predict {"url": "..."}-->  Flask (app.py)
                                                       |  parse_url()  -> hostname
                                                       |  features_frame() -> 18 features   (same code as training)
                                                       |  saved model.predict_proba()
React  <-- {label, phishing_probability, analyzed_host, features, notes} --
```
* The model is loaded **once** when Flask starts; nothing is retrained per request.
* The dataset is **not** opened during prediction; the result is never a lookup of the URL.
* The score is the model's phishing probability estimate (not calibrated). Threshold: 0.5.
* Endpoints: `GET /api/health`, `POST /api/predict`, `GET /api/report` (feeds the dashboard).
* Errors: 400 bad request, 422 invalid URL, 503 model not trained, 404/405/413 JSON errors. CORS allows only `FRONTEND_ORIGIN`. Submitted URLs are not logged.

## 8. Install and run on Windows (PowerShell)
Needs **Python 3.11+** (python.org, tick "Add to PATH") and **Node.js 18+** (nodejs.org).

```powershell
# 1) Backend
cd PhishGuard-AI\backend
python -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements.txt
python app.py                       # API on http://127.0.0.1:5000  (leave this window open)
```
```powershell
# 2) Frontend (second PowerShell window)
cd PhishGuard-AI\frontend
npm install
npm run dev                         # open http://localhost:5173
```
A trained model is already included in `backend\models\`, so the app works immediately. Shortcut: double-click `start_backend.bat` and `start_frontend.bat`.

**Retrain the model** (needs the CSV in `backend\data\`, see `backend\data\README.md`; about 3 to 6 minutes):
```powershell
cd PhishGuard-AI\backend
python train.py
```
Retraining on your own computer also avoids scikit-learn version mismatches. Restart `python app.py` afterwards.

**Test a new URL without the website:**
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/predict -ContentType "application/json" -Body '{"url":"http://secure-login.example.xyz/verify"}'
```
**Run the tests:** `cd backend; python -m unittest discover -s tests -t .` and `cd frontend; npm test` (with the backend running: `npm run test:integration`). See `docs/TEST_REPORT.md` for what was and was not executed.

## 9. Deployment (separate hosting; instructions not yet tried)
* **Backend (e.g. Render, Railway)**: root directory `backend`, build `pip install -r requirements.txt`, start `gunicorn app:app`, environment `FRONTEND_ORIGIN=https://your-frontend-url`. Commit `backend/models/` (the model is under 1 MB) or the API answers 503.
* **Frontend (e.g. Vercel, Netlify)**: root `frontend`, build `npm run build`, output `dist`, environment `VITE_API_BASE_URL=https://your-backend-url`.
* Free tiers may sleep; the first request can be slow. Never set `FRONTEND_ORIGIN` to `*`.

## 10. Limitations
* **Hostname only.** Paths, queries and page content are ignored, so phishing on legitimate or shared domains, shortened links and path tricks can be missed.
* **Misses about 35% of phishing hostnames** in the test set, and raises false alarms on about 5% of legitimate ones.
* **Dataset bias.** Legitimate examples are mostly plain registered domains, so legitimate hostnames with subdomains are more likely to be flagged. Illustrative checks (not an evaluation) from the training run: `wikipedia.org` 10%, `google.com` 26%, `github.com` 26% phishing score, but `mail.python.org` 81% and `accounts.google.com` 97%.
* The test set comes from the same source as the training data; real-world performance can be lower.
* No live reputation, WHOIS or blocklist checks. A low score never proves a site is safe.

**Future scope:** train on a dataset with full legitimate URLs to analyse paths; character n-gram features; exact registered-domain parsing (public suffix list); threshold tuning and probability calibration; evaluation on fresh phishing feeds; optional, clearly separated threat-intelligence lookup; rate limiting.

## 11. Folder structure
```
PhishGuard-AI/
  backend/  app.py  train.py  feature_extractor.py  predictor.py  requirements.txt
            models/ (phishguard_model.joblib, model_meta.json)   reports/ (training_report.json, training_log.txt)
            data/ (put the CSV here)   tests/
  frontend/ index.html  package.json  vite.config.js  .env.example
            src/ (App.jsx, api.js, scanState.js, format.js, styles.css, components/)   tests/
  docs/     VIVA_QA.md  TEST_REPORT.md
  README.md  .gitignore  start_backend.bat  start_frontend.bat
```
