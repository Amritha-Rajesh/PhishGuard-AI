# Viva questions and answers (PhishGuard AI)

Numbers are from the real training run (`backend/reports/training_report.json`). If you retrain, your numbers may differ slightly; read them from your own report.

**1. What is your project about?**
A web app that takes a URL and uses a trained machine learning model to say "Likely Legitimate" or "Potential Phishing". It analyses only the hostname text, never opens the link.

**2. Where and how was the model trained?**
On my computer by running `python train.py` in the `backend` folder. The script loads the dataset, cleans it, extracts features, compares three algorithms, picks the best, tests it, and saves it as `models/phishguard_model.joblib`. The website never retrains; it only loads this saved file.

**3. Which dataset was used?**
The PhiUSIIL Phishing URL Dataset (UCI repository): 235,795 URLs, 56 columns. I use only the `URL` and `label` columns. In the file 1 = legitimate and 0 = phishing; in my model I flip this so 1 = phishing (the class we want to catch).

**4. Why not use all 56 columns?**
Most columns come from the web page (HTML, forms, JavaScript). To get them for a new URL I would have to visit the site, which is unsafe and which I decided not to do. Some URL columns need hidden reference data or leak the label, so I excluded them.

**5. What problem did you find in the dataset?**
Every legitimate URL looks like `https://www.something.com` with no path, while almost all phishing URLs don't. A simple rule on that gets 99.7% accuracy, so a model on full URLs would just learn the formatting, not phishing. That is why I analyse only the normalized hostname.

**6. What are the input features?**
18 values from the hostname: length, number of dots, hyphens and digits, digit ratio, number of labels, longest/average/first label length, entropy, is-IP, TLD length, punycode flag, vowel ratio, longest consonant run, longest digit run, count of suspicious keywords, and the TLD itself. They are defined in `feature_extractor.py`.

**7. What is entropy here?**
A measure of randomness of the characters. Random-looking names like `xj3k9q2vz.top` have higher entropy than normal words.

**8. Which algorithm was selected and why?**
Gradient Boosting. It had the best cross-validation phishing F2 score (75.9%, against 74.9% for Random Forest and 74.7% for Logistic Regression). Differences are small. I chose by F2 because missing a phishing site is worse than a false alarm.

**9. Briefly, how do the three algorithms work?**
Logistic Regression draws a weighted straight-line boundary. Random Forest builds many decision trees on random parts of the data and lets them vote. Gradient Boosting builds trees one after another, each correcting the previous trees' mistakes.

**10. What are training and testing data?**
Training data (80%, 178,705 hostnames) is what the model learns from. Testing data (20%, 40,328 hostnames) is kept hidden until the end to measure how it does on unseen data. I also used cross-validation inside the training part to compare models fairly.

**11. How did you avoid data leakage?**
(a) Split by registered domain, so `a.example.com` and `b.example.com` can't be on both sides (0 overlap). (b) The scaler and TLD encoder are fitted on training data only, inside the pipeline. (c) I removed duplicate hostnames and hostnames with both labels. (d) I excluded features that use hidden data or the label. (e) The test set was used once, after choosing the model.

**12. What are accuracy, precision, recall and F1?**
With phishing as the positive class: *Accuracy* = share of all predictions that are correct (85.0%). *Precision* = of the URLs I flagged as phishing, how many really were (85.5%). *Recall* = of all real phishing URLs, how many I caught (65.4%). *F1* = balance of precision and recall (74.1%). *F2* is like F1 but recall counts double.

**13. Accuracy is 85% but recall is only 65%. Why does that matter?**
Because about 1 in 3 phishing hostnames is missed (false-negative rate 34.6%). Accuracy hides this: predicting "legitimate" for everything would already give 67% accuracy because there are more legitimate examples.

**14. What is a confusion matrix? What does yours show?**
A table of correct and wrong predictions. Mine: 25,624 legitimate correctly cleared, 1,466 legitimate wrongly flagged (false positives), 4,580 phishing missed (false negatives), 8,658 phishing caught (true positives).

**15. What is ROC-AUC?**
It measures how well the model ranks phishing above legitimate across all thresholds. 0.5 is random guessing and 1.0 is perfect. Mine is 0.871.

**16. How does the system predict a new URL?**
The text goes to Flask. `parse_url` validates it and extracts the hostname. `features_frame` calculates the same 18 features used in training. The saved model's `predict_proba` gives a phishing score; if it is at least 0.5 the label is "Potential Phishing", otherwise "Likely Legitimate". It is not looked up in the dataset and not hardcoded.

**17. How does the frontend talk to Flask?**
React sends `POST /api/predict` with JSON `{"url": "..."}` using `fetch` (code in `frontend/src/api.js`). Flask replies with JSON containing the label, score and the analysed hostname. CORS allows only the frontend's address.

**18. What does the percentage on the result mean?**
It is the model's phishing score. It is not a calibrated guarantee. A low score does not prove a site is safe.

**19. Why do you ignore the path and query string?**
Because in the dataset the legitimate examples have no paths, so paths would only teach the model the shortcut. A consequence is that phishing pages on legitimate domains are missed.

**20. What are the limitations?**
Hostname only; misses about 35% of phishing hostnames in the test set; legitimate hostnames with subdomains (e.g. `accounts.google.com`) can be flagged because the dataset's legitimate examples are mostly plain domains; the test data comes from the same source as training data; no live blocklists or domain age checks.

**21. How would you improve it?**
Use a dataset with full legitimate URLs to analyse paths, add character n-gram features, use a public-suffix list, tune the threshold and calibrate probabilities, test on fresh phishing feeds, and optionally add a separate threat-intelligence lookup.

**22. Is it safe to submit a URL? Does the server visit it?**
The server never visits it; it only analyses the text. URLs are not written to the logs.

**23. What are class imbalance and how did you handle it?**
When one class has more examples. After cleaning there are 134,792 legitimate and 84,241 phishing hostnames. I used class weights in the models so the smaller class is not ignored, and I report precision and recall, not just accuracy.

**24. How do you retrain?**
Put the CSV in `backend/data/`, run `python train.py`, restart `python app.py`. The dashboard then shows the new report automatically.
