export default function About() {
  return (
    <div className="page about">
      <h1>About PhishGuard AI</h1>
      <p className="lede">A college Machine Learning and Data Mining project that classifies a URL&apos;s hostname as likely legitimate or potential phishing.</p>

      <section>
        <h2>Problem statement</h2>
        <p>Phishing links imitate trusted websites to steal passwords and money. Blocklists only know about sites that have already been reported, so a model that recognises suspicious patterns in the link itself can help catch new ones.</p>
      </section>

      <section>
        <h2>Objectives</h2>
        <ul className="plain">
          <li>Train and compare machine learning models on a real labelled URL dataset.</li>
          <li>Predict brand-new URLs by extracting the same features at training time and prediction time.</li>
          <li>Report honest evaluation results, including limitations.</li>
        </ul>
      </section>

      <section>
        <h2>Dataset</h2>
        <p>The PhiUSIIL Phishing URL Dataset (University of California Irvine repository) contains URLs labelled legitimate or phishing. Only the URL and label columns are used. Its many page-content columns cannot be calculated without visiting the site, so they are excluded. The exact counts after cleaning are on the Model performance page.</p>
      </section>

      <section>
        <h2>Preprocessing and features</h2>
        <p>Each URL is reduced to its hostname: the scheme, <code>www.</code>, port, path and query are removed and the text is lowercased. Duplicate URLs, invalid URLs and hostnames with conflicting labels are removed. From the hostname the system calculates 17 numeric features, such as length, dots, hyphens, digits, entropy, longest label, vowel ratio and suspicious keywords, plus the top-level domain as a category. The same code is used when you scan a URL.</p>
      </section>

      <section>
        <h2>Machine learning and evaluation</h2>
        <p>Logistic Regression, Random Forest and Gradient Boosting are compared with grouped cross-validation. The final model is picked mainly by how many phishing hostnames it catches without too many false alarms, then tested once on hostnames from registered domains it never saw. Metrics are accuracy, precision, recall, F1-score, ROC-AUC and a confusion matrix.</p>
      </section>

      <section>
        <h2>How a scan works</h2>
        <ol className="flow">
          <li><strong>Browser</strong><span>React page sends the text you typed</span></li>
          <li><strong>Flask API</strong><span>Validates it and extracts the hostname features</span></li>
          <li><strong>Saved model</strong><span>Scores the features; nothing is retrained</span></li>
          <li><strong>Result</strong><span>Label and score are sent back and shown</span></li>
        </ol>
      </section>

      <section className="callout">
        <h2>Limitations</h2>
        <ul className="plain">
          <li>Hostname only: phishing pages on legitimate domains, shortened links and path-based tricks are not detected.</li>
          <li>The legitimate examples in the dataset are mostly plain registered domains, so legitimate hostnames with subdomains are more likely to be flagged.</li>
          <li>New phishing styles, or links unlike the training data, may be misjudged.</li>
          <li>No live blocklist, reputation or domain-age check is used.</li>
          <li>A low phishing score never proves a website is safe.</li>
        </ul>
      </section>

      <section>
        <h2>Future improvements</h2>
        <ul className="plain">
          <li>Train on a second dataset with full legitimate URLs so paths and queries can be analysed.</li>
          <li>Add character n-gram features and a public-suffix list for exact registered domains.</li>
          <li>Test on newly collected phishing feeds and add probability calibration.</li>
          <li>Optionally add a verified threat-intelligence lookup, clearly labelled as separate from the model.</li>
        </ul>
      </section>
    </div>
  )
}
