"""
PhishShield ML trainer
Trains a small MLP on phishing URLs and exports weights to JSON for in-browser inference.
Run: python train.py
Output: ../public/model/weights.json
"""

import json
import math
import os
import re
import sys
from io import StringIO
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import requests
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '..', 'public', 'model')

SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.work', '.gq', '.cf', '.tk', '.ml', '.ga', '.pw'}
SUSPICIOUS_KW = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'confirm', 'password', 'signin', 'webscr']
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly'}

DATASET_URLS = [
    'https://raw.githubusercontent.com/pirocheto/phishing-url-detection/main/data/selected_data.csv',
    'https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv',
]


def url_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum(f / n * math.log2(f / n) for f in freq.values())


def extract_features(url):
    """18 normalized features from a raw URL string. Must match mlAnalysis.js exactly."""
    try:
        if '://' not in url:
            url = 'http://' + url
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
        parts = hostname.split('.')
        tld = '.' + parts[-1] if parts else ''

        return [
            min(len(url), 200) / 200,
            min(len(hostname), 100) / 100,
            min(len(parts) - 1, 10) / 10,
            min(len(re.findall(r'-', hostname)), 10) / 10,
            1.0 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0.0,
            1.0 if parsed.scheme == 'https' else 0.0,
            min(max(0, len(parts) - 2), 5) / 5,
            1.0 if tld in SUSPICIOUS_TLDS else 0.0,
            1.0 if '@' in url else 0.0,
            min(url_entropy(url), 6) / 6,
            min(len(path), 100) / 100,
            min(len(re.findall(r'\d', hostname)), 10) / 10,
            1.0 if any(kw in url.lower() for kw in SUSPICIOUS_KW) else 0.0,
            min(url.count('/'), 10) / 10,
            1.0 if re.search(r'%[0-9a-fA-F]{2}', hostname) else 0.0,
            1.0 if hostname in SHORTENERS else 0.0,
            min(len(query.split('&')) if query else 0, 5) / 5,
            1.0 if re.search(r'\.\w{2,4}\.\w{2,4}$', path) else 0.0,
        ]
    except Exception:
        return [0.0] * 18


def generate_synthetic_dataset(n=12000):
    """Fallback: generate synthetic phishing + legitimate URLs."""
    import random
    random.seed(42)

    legit_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'github.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com', 'dropbox.com',
        'paypal.com', 'ebay.com', 'stackoverflow.com', 'nytimes.com', 'bbc.com',
        'cnn.com', 'yahoo.com', 'bing.com', 'adobe.com', 'salesforce.com',
        'zoom.us', 'slack.com', 'notion.so', 'shopify.com', 'stripe.com',
    ]
    legit_paths = ['/', '/about', '/home', '/news', '/products', '/help', '/contact',
                   '/login', '/search', '/profile', '/settings', '/docs', '/blog']
    phish_keywords = SUSPICIOUS_KW
    bad_tlds = list(SUSPICIOUS_TLDS)
    phish_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook',
                    'netflix', 'instagram', 'linkedin', 'chase', 'wellsfargo', 'bankofamerica']
    phish_domains = ['secure-login', 'account-verify', 'update-info', 'signin-confirm',
                     'banking-secure', 'password-reset', 'verify-account', 'support-team']

    rows = []
    half = n // 2

    # Legitimate
    for _ in range(half):
        scheme = random.choice(['https', 'https', 'https', 'http'])
        domain = random.choice(legit_domains)
        sub = random.choice(['', 'www.', 'mail.', 'docs.', 'support.'])
        path = random.choice(legit_paths)
        url = f"{scheme}://{sub}{domain}{path}"
        rows.append({'url': url, 'label': 0})

    # Phishing
    for _ in range(half):
        style = random.randint(0, 5)
        if style == 0:
            # IP-based
            ip = '.'.join(str(random.randint(1, 254)) for _ in range(4))
            kw = random.choice(phish_keywords)
            url = f"http://{ip}/{kw}/index.php"
        elif style == 1:
            # Suspicious TLD
            brand = random.choice(phish_brands)
            tld = random.choice(bad_tlds)
            kw = random.choice(phish_keywords)
            url = f"http://{brand}-{kw}{tld}/secure/{kw}.html"
        elif style == 2:
            # Long URL with keywords
            brand = random.choice(phish_brands)
            kw = random.choice(phish_keywords)
            junk = ''.join(random.choices('abcdefghijklmnop0123456789', k=random.randint(8, 20)))
            url = f"http://www.{brand}-{kw}-{junk}.com/{kw}/verify?token={junk}&id=12345"
        elif style == 3:
            # Subdomain abuse
            brand = random.choice(phish_brands)
            kw = random.choice(phish_keywords)
            attacker = random.choice(phish_domains)
            url = f"http://{brand}.{kw}.{attacker}.com/login.php"
        elif style == 4:
            # @ symbol
            brand = random.choice(phish_brands)
            ip = '.'.join(str(random.randint(1, 254)) for _ in range(4))
            url = f"http://{brand}.com@{ip}/phishing/page"
        else:
            # URL shortener style
            shortener = random.choice(list(SHORTENERS))
            junk = ''.join(random.choices('abcdefghijklmnop', k=6))
            url = f"http://{shortener}/{junk}"
        rows.append({'url': url, 'label': 1})

    random.shuffle(rows)
    return pd.DataFrame(rows)


def load_dataset():
    for url in DATASET_URLS:
        try:
            print(f'Downloading: {url}')
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            df = pd.read_csv(StringIO(r.text))
            df.columns = [c.strip().lower() for c in df.columns]
            # Reject datasets that don't have an actual URL column (pre-extracted features)
            url_col = next((c for c in df.columns if c == 'url' or c == 'url_string' or c == 'website'), None)
            if url_col is None:
                print(f'Dataset has no raw URL column, skipping.')
                continue
            print(f'Loaded {len(df)} rows, columns: {df.columns.tolist()}')
            return df
        except Exception as e:
            print(f'Failed ({e}), trying next source...')

    print('All dataset sources failed or had no raw URL column — using synthetic dataset.')
    return generate_synthetic_dataset()


def find_columns(df):
    url_col = next((c for c in df.columns if c in ['url', 'url_string', 'website']), None)
    label_col = next((c for c in df.columns if c in ['label', 'status', 'class', 'phishing', 'result', 'type']), None)
    if not url_col or not label_col:
        raise ValueError(f"Could not find url/label columns in: {df.columns.tolist()}")
    return url_col, label_col


def main():
    df = load_dataset()
    url_col, label_col = find_columns(df)

    print(f'\nUsing: url="{url_col}", label="{label_col}"')
    print(f'Label distribution:\n{df[label_col].value_counts().to_string()}\n')

    # label encoding: phishing=1, legitimate=0
    phishing_values = {'phishing', '1', 'malicious', 'bad', 'yes'}
    y = df[label_col].astype(str).str.strip().str.lower().isin(phishing_values).astype(int).values

    print('Extracting features...')
    X = np.array([extract_features(str(u)) for u in df[url_col]], dtype=np.float32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f'Training on {len(X_train)} samples...')
    clf = MLPClassifier(
        hidden_layer_sizes=(32, 16),
        activation='relu',
        solver='adam',
        max_iter=200,
        random_state=42,
        verbose=False,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=15,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f'\nTest accuracy: {acc:.4f}')
    print(classification_report(y_test, y_pred, target_names=['legitimate', 'phishing']))

    # Export: layer weights + scaler params
    layers = [
        {'W': clf.coefs_[i].tolist(), 'b': clf.intercepts_[i].tolist()}
        for i in range(len(clf.coefs_))
    ]
    output = {
        'layers': layers,
        'scaler_mean': scaler.mean_.tolist(),
        'scaler_std': scaler.scale_.tolist(),
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, 'weights.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, separators=(',', ':'))

    size_kb = os.path.getsize(out_path) / 1024
    print(f'Weights saved → {out_path} ({size_kb:.1f} KB)')
    print(f'Layers: {[str(len(l["b"])) + " units" for l in layers]}')
    print('\nDone. Run "npm run build" to bundle the model into the extension.')


if __name__ == '__main__':
    main()
