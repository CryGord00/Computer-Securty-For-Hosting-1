from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
import json
import mimetypes
import pickle
import re


ROOT_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT_DIR / "frontend"
HTML_DIR = FRONTEND_DIR / "html"

FEATURE_IMPORTANCE = {
    "path_length": 0.313255,
    "url_length": 0.303933,
    "num_dots": 0.161288,
    "num_digits": 0.140252,
    "num_hyphens": 0.071038,
    "has_https": 0.005450,
    "has_ip": 0.004072,
    "num_at": 0.000712,
}

FEATURE_COLUMNS = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_digits",
    "has_https",
    "has_ip",
    "path_length",
]

MODEL_PATHS = [
    Path(__file__).resolve().parent / "phishing_model.pkl",
    Path(__file__).resolve().parent / "models" / "phishing_model.pkl",
]

MODEL = None
MODEL_ERROR = None

SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "password",
    "paypal",
    "wallet",
    "confirm",
    "billing",
    "signin",
)

SUSPICIOUS_TLDS = (
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".icu",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
)

TRUSTED_DOMAINS = (
    "youtube.com",
    "youtu.be",
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "x.com",
    "example.com",
)


def normalize_url(url):
    return (url or "").strip()


def is_trusted_domain(host):
    return any(host == domain or host.endswith(f".{domain}") for domain in TRUSTED_DOMAINS)


def extract_features(url):
    clean_url = normalize_url(url)
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"

    return {
        "url_length": len(clean_url),
        "num_dots": clean_url.count("."),
        "num_hyphens": clean_url.count("-"),
        "num_at": clean_url.count("@"),
        "num_digits": sum(char.isdigit() for char in clean_url),
        "has_https": 1 if "https" in clean_url.lower() else 0,
        "has_ip": 1 if re.search(ip_pattern, clean_url) else 0,
        "path_length": len(urlparse(clean_url).path),
    }


def load_model():
    global MODEL, MODEL_ERROR
    if MODEL is not None:
        return MODEL

    for model_path in MODEL_PATHS:
        if model_path.exists():
            try:
                with model_path.open("rb") as file:
                    MODEL = pickle.load(file)
                return MODEL
            except Exception as exc:
                MODEL_ERROR = str(exc)
                return None

    MODEL_ERROR = "phishing_model.pkl belum ditemukan"
    return None


def predict_with_saved_model(features):
    model = load_model()
    if model is None:
        return None

    try:
        try:
            import pandas as pd

            model_input = pd.DataFrame([{column: features[column] for column in FEATURE_COLUMNS}])
        except Exception:
            model_input = [[features[column] for column in FEATURE_COLUMNS]]

        prediction = int(model.predict(model_input)[0])
        probability = None
        phishing_probability = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(model_input)[0]
            class_indexes = {int(label): index for index, label in enumerate(model.classes_)}
            probability = float(probabilities[class_indexes[prediction]])
            phishing_probability = float(probabilities[class_indexes.get(1, prediction)])

        return {
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(probability, 2) if probability is not None else None,
            "phishing_probability": (
                round(phishing_probability, 2) if phishing_probability is not None else None
            ),
        }
    except Exception:
        return None


def analyze_url(url):
    clean_url = normalize_url(url)
    if not clean_url:
        raise ValueError("URL wajib diisi.")

    lower_url = clean_url.lower()
    parsed_for_host = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    host = parsed_for_host.netloc.lower()
    features = extract_features(clean_url)
    model_prediction = predict_with_saved_model(features)

    score = 0
    reasons = []

    if features["url_length"] >= 75:
        score += 24
        reasons.append("URL terlalu panjang")
    elif features["url_length"] >= 45:
        score += 12
        reasons.append("URL cukup panjang")

    if features["path_length"] >= 45:
        score += 22
        reasons.append("Path URL panjang")
    elif features["path_length"] >= 18:
        score += 10
        reasons.append("Path URL cukup kompleks")

    if features["num_dots"] >= 4:
        score += 16
        reasons.append("Terlalu banyak titik/subdomain")
    elif features["num_dots"] >= 3:
        score += 8
        reasons.append("Banyak titik/subdomain")

    if features["num_hyphens"] >= 2:
        score += 14
        reasons.append("Banyak tanda hubung")
    elif features["num_hyphens"] == 1:
        score += 7
        reasons.append("Mengandung tanda hubung")

    if features["num_digits"] >= 6:
        score += 14
        reasons.append("Mengandung banyak angka")
    elif features["num_digits"] >= 2:
        score += 6
        reasons.append("Mengandung angka")

    if features["num_at"] > 0:
        score += 18
        reasons.append("Mengandung simbol @")

    if features["has_ip"]:
        score += 25
        reasons.append("Menggunakan alamat IP")

    keyword_hits = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]
    if keyword_hits:
        score += min(24, 8 * len(keyword_hits))
        reasons.append("Mengandung kata kunci mencurigakan: " + ", ".join(keyword_hits[:4]))

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 12
        reasons.append("Menggunakan domain yang sering disalahgunakan")

    if not features["has_https"]:
        score += 7
        reasons.append("Tidak menggunakan HTTPS")

    if features["has_https"] and score > 0:
        score -= 4

    score = max(0, min(100, score))
    is_phishing = score >= 45
    prediction_engine = "lexical-fallback"
    display_risk_score = score
    final_confidence = round(score / 100 if is_phishing else (100 - score) / 100, 2)

    if model_prediction is not None:
        is_phishing = model_prediction["prediction"] == "phishing"
        prediction_engine = "saved-random-forest-model"
        if model_prediction["phishing_probability"] is not None:
            display_risk_score = int(round(model_prediction["phishing_probability"] * 100))
        if model_prediction["confidence"] is not None:
            final_confidence = model_prediction["confidence"]

    trusted_domain_override = (
        model_prediction is not None
        and model_prediction["prediction"] == "phishing"
        and is_trusted_domain(host)
        and score <= 10
        and features["has_ip"] == 0
        and features["num_at"] == 0
    )

    if trusted_domain_override:
        is_phishing = False
        prediction_engine = "saved-random-forest-model+trusted-domain-check"
        display_risk_score = score
        final_confidence = round((100 - score) / 100, 2)
        reasons.append("Domain resmi/trusted dan fitur URL tidak menunjukkan pola phishing kuat")

    if (
        model_prediction is not None
        and model_prediction["prediction"] == "phishing"
        and score < 45
        and not trusted_domain_override
    ):
        reasons.append("Model Random Forest mendeteksi pola yang mirip URL phishing")

    if not reasons:
        reasons.append("Tidak ada pola mencurigakan kuat dari fitur URL")

    return {
        "url": clean_url,
        "prediction": "phishing" if is_phishing else "legitimate",
        "label": "Phishing" if is_phishing else "Legitimate",
        "risk_score": display_risk_score,
        "lexical_risk_score": score,
        "confidence": final_confidence,
        "model_prediction": model_prediction,
        "prediction_engine": prediction_engine,
        "model_status": "loaded" if model_prediction is not None else MODEL_ERROR,
        "features": features,
        "feature_importance": FEATURE_IMPORTANCE,
        "reasons": reasons,
        "flow": [
            "User Input",
            "Feature Extraction",
            "URL Feature Analysis",
            "Random Forest-ready Prediction",
            "Detection Result",
        ],
    }


class AppHandler(BaseHTTPRequestHandler):
    server_version = "PhishingDetectionServer/1.0"

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/health":
            self.send_json({"status": "ok", "message": "Backend phishing detection aktif"})
            return

        if self.path in ("/", "/index.html"):
            self.serve_file(HTML_DIR / "index.html")
            return

        if self.path in ("/detection", "/detection.html"):
            self.serve_file(HTML_DIR / "detection.html")
            return

        if self.path in ("/about", "/about.html"):
            self.serve_file(HTML_DIR / "about.html")
            return

        if self.path.startswith("/css/"):
            self.serve_file(FRONTEND_DIR / self.path.lstrip("/"))
            return

        if self.path.startswith("/js/"):
            self.serve_file(FRONTEND_DIR / self.path.lstrip("/"))
            return

        self.send_error(404, "Halaman tidak ditemukan")

    def do_POST(self):
        if self.path != "/api/predict":
            self.send_error(404, "Endpoint tidak ditemukan")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            result = analyze_url(payload.get("url", ""))
            self.send_json(result)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except json.JSONDecodeError:
            self.send_json({"error": "Format JSON tidak valid."}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Terjadi masalah di server: {exc}"}, status=500)

    def send_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_file(self, path):
        try:
            safe_path = path.resolve()
            allowed_roots = [FRONTEND_DIR.resolve()]
            if not any(str(safe_path).startswith(str(root)) for root in allowed_roots):
                self.send_error(403, "Akses ditolak")
                return

            if not safe_path.exists() or not safe_path.is_file():
                self.send_error(404, "File tidak ditemukan")
                return

            content = safe_path.read_bytes()
            content_type = mimetypes.guess_type(str(safe_path))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as exc:
            self.send_error(500, f"Gagal membaca file: {exc}")

    def log_message(self, format, *args):
        print("[%s] %s" % (self.log_date_time_string(), format % args))


def run(host="127.0.0.1", port=5000):
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"Backend berjalan di http://{host}:{port}")
    print(f"Buka frontend di http://{host}:{port}/detection")
    server.serve_forever()


if __name__ == "__main__":
    run()
