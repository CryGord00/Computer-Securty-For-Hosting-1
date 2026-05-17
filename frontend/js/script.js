const apiBase = window.location.protocol === "file:" ? "http://127.0.0.1:5000" : window.location.origin;

const detectButton = document.getElementById("detectButton");
const urlInput = document.getElementById("urlInput");
const loadingBox = document.getElementById("loadingBox");
const resultBox = document.getElementById("resultBox");
const resultAlert = document.getElementById("resultAlert");
const threatLevel = document.getElementById("threatLevel");
const predictionText = document.getElementById("predictionText");
const confidenceText = document.getElementById("confidenceText");
const httpsStatus = document.getElementById("httpsStatus");
const analysisText = document.getElementById("analysisText");
const indicatorSection = document.getElementById("indicatorSection");

function setText(element, value) {
  if (element) {
    element.textContent = value;
  }
}

function setResultClass(element, className) {
  if (!element) return;
  element.classList.remove("safe", "danger");
  if (className) {
    element.classList.add(className);
  }
}

function formatPercent(value) {
  if (typeof value !== "number") return "-";
  return `${Math.round(value * 100)}%`;
}

function getThreatLevel(score, isPhishing) {
  if (!isPhishing) return "Low";
  if (score >= 75) return "High";
  if (score >= 45) return "Medium";
  return "Low";
}

function renderResult(data) {
  const isPhishing = data.prediction === "phishing";
  const resultClass = isPhishing ? "danger" : "safe";
  const alertClass = isPhishing ? "warning-box" : "success-box";
  const threat = getThreatLevel(data.risk_score, isPhishing);
  const features = data.features || {};
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];

  if (resultAlert) {
    resultAlert.className = alertClass;
    resultAlert.textContent = isPhishing
      ? "WARNING: This URL is detected as a phishing website and may contain malicious activity."
      : "SAFE: This URL is classified as legitimate by the detection system.";
  }

  setText(threatLevel, threat);
  setText(predictionText, isPhishing ? "Phishing" : "Legitimate");
  setText(confidenceText, formatPercent(data.confidence));
  setText(httpsStatus, features.has_https ? "Detected" : "Not Detected");

  setResultClass(threatLevel, isPhishing ? "danger" : "safe");
  setResultClass(predictionText, resultClass);
  setResultClass(confidenceText, resultClass);
  setResultClass(httpsStatus, features.has_https ? "safe" : "danger");

  const engineText = data.prediction_engine === "saved-random-forest-model"
    ? "Random Forest model"
    : "lexical fallback detector";
  const reasonText = reasons.length ? reasons.join(" ") : "No strong suspicious pattern was found.";
  setText(
    analysisText,
    `Engine: ${engineText}. Risk score: ${data.risk_score}%. ${reasonText}`
  );

  if (indicatorSection) {
    indicatorSection.classList.remove("hidden");
  }
}

function renderError(message) {
  if (resultAlert) {
    resultAlert.className = "warning-box";
    resultAlert.textContent = message;
  }

  setText(threatLevel, "-");
  setText(predictionText, "Error");
  setText(confidenceText, "-");
  setText(httpsStatus, "-");
  setText(analysisText, "Backend is not responding. Make sure the backend server is running.");

  setResultClass(threatLevel, "");
  setResultClass(predictionText, "danger");
  setResultClass(confidenceText, "");
  setResultClass(httpsStatus, "");
}

if (detectButton && urlInput) {
  detectButton.addEventListener("click", async () => {
    const url = urlInput.value.trim();

    if (!url) {
      alert("Please enter a URL first.");
      return;
    }

    if (loadingBox) loadingBox.classList.remove("hidden");
    if (resultBox) resultBox.classList.add("hidden");
    detectButton.disabled = true;
    detectButton.textContent = "Analyzing...";

    try {
      const response = await fetch(`${apiBase}/api/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to analyze URL.");
      }

      renderResult(data);
    } catch (error) {
      renderError(error.message || "Failed to connect to backend.");
    } finally {
      if (loadingBox) loadingBox.classList.add("hidden");
      if (resultBox) resultBox.classList.remove("hidden");
      detectButton.disabled = false;
      detectButton.textContent = "Analyze URL";
    }
  });
}
