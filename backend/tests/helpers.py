"""Shared test helpers. Synthetic data here is ONLY used to test plumbing (cleaning, splitting, saving)."""
import random
from pathlib import Path

import pandas as pd

BACKEND = Path(__file__).resolve().parents[1]
REAL_CSV = BACKEND / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_DIR = BACKEND / "models"
REPORT_DIR = BACKEND / "reports"
REAL_MODEL_AVAILABLE = (MODEL_DIR / "phishguard_model.joblib").is_file() and (MODEL_DIR / "model_meta.json").is_file()


def make_tiny_dataset(n=400, seed=1) -> pd.DataFrame:
    """Dataset-shaped DataFrame (URL, label) with legit rows, phishing rows and deliberate problems."""
    rnd = random.Random(seed)
    words = ["alpha", "bravo", "delta", "echo", "foxtrot", "golf", "hotel", "india", "kilo", "lima", "metro", "nova"]
    rows = []
    for i in range(n):
        rows.append((f"https://www.{rnd.choice(words)}{i}.com", 1))                       # legit (dataset label 1)
        junk = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randint(6, 14)))
        rows.append((f"http://{junk}-login{i}.secure-{junk[:4]}.xyz/index.php?x=1", 0))   # phishing (dataset label 0)
    rows += [
        rows[0],                                        # exact duplicate URL (same URL, same label)
        ("https://www.conflict.com", 1),                # same hostname, both labels
        ("http://conflict.com/evil", 0),
        ("not a url", 0),                               # invalid
        ("javascript:alert(1)", 0),                     # invalid
    ]
    return pd.DataFrame(rows, columns=["URL", "label"])
