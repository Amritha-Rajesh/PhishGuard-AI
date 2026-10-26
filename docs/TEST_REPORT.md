# Test report

Run on 26 Oct 2026 in the build sandbox (Linux, Python 3.12.3, scikit-learn 1.8.0, Node 22). Results below are what actually happened.

## Passed

| Suite | Command | Result |
|---|---|---|
| Backend (39 tests) | `cd backend` then `python -m unittest discover -s tests -t .` | **39 passed, 0 failed** |
| Frontend logic (15 tests) | `cd frontend` then `npm test` | **15 passed, 0 failed** |
| Frontend -> Flask -> model integration (7 tests) | start `python app.py`, then `npm run test:integration` | **7 passed, 0 failed** |

What the backend tests cover: URL normalization and invalid input (empty, spaces, `javascript:`, too long, bad hostnames); hand-computed feature values; label mapping (dataset 1 = legitimate -> model 0); cleaning (duplicates, invalid URLs, conflicting hostnames); no train/test overlap; a complete training run on a tiny fixture that saves model + report; the real dataset (235,795 x 56, 134,850 / 100,945); API success, validation errors (400/413/422), 404/405 JSON errors; missing and corrupt model files (503); CORS allowed/blocked origins; submitted URLs not written to logs; identical features in training and inference for 300 real dataset URLs; a brand-new URL scored by the saved model (checked against an independent calculation, with `pandas.read_csv` disabled to prove no dataset lookup); scheme / `www.` / path differences giving the same score.

What the frontend tests cover: the API client (success, 422 and 503 errors, network failure, timeout, unreadable response), the scan state machine (idle / loading / success / error / reset, double submit, late answers), URL anatomy splitting, wording that never claims safety. The integration run calls the real Flask server over HTTP through the same `api.js` the React app uses.

## Not executed

- **The React components were not compiled or rendered.** The sandbox has no internet, so `npm install` (React, Vite) was impossible. `.jsx` files passed only a structural check (balanced brackets, imports resolve). Please run `npm install` and `npm run dev` and look at every page once; if something fails, send me the exact error.
- No browser-level (click-through) test of loading / result / error screens. The *logic* behind those states is tested (scan state machine and API error mapping), the visual rendering is not.
- Deployment (Render / Vercel) was not attempted.
- Windows was not available; commands in the README follow standard PowerShell usage but were not run on Windows.
