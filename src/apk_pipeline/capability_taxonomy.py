from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CapabilityPattern:
    name: str
    label: str
    keywords: tuple[str, ...]
    strong_keywords: tuple[str, ...] = ()


CAPABILITY_PATTERNS: tuple[CapabilityPattern, ...] = (
    CapabilityPattern(
        name="document_pdf",
        label="Document/PDF",
        keywords=(
            "pdf", "pddoc", "pdpage", "pde", "acrobat", "document",
            "annotation", "annot", "bookmark", "form", "signature",
            "xmp", "jp2k", "jpeg", "render", "page",
        ),
        strong_keywords=("pddoc", "pdpage", "pde", "pdfium", "pdf"),
    ),
    CapabilityPattern(
        name="ocr",
        label="OCR/Text Recognition",
        keywords=(
            "ocr", "recognize", "recognition", "glyph", "deskew",
            "fontmetrics", "ilex", "text layer", "hidden text",
            "language", "latin.ocr",
        ),
        strong_keywords=("ocr", "glyph", "deskew", "ilex", "latin.ocr"),
    ),
    CapabilityPattern(
        name="scan_image",
        label="Scan/Image Processing",
        keywords=(
            "scan", "camera", "opencv", "image", "bitmap", "crop",
            "clean", "dewarp", "edge", "detect", "filter", "jpeg",
            "png", "shadow", "glare", "document detection",
        ),
        strong_keywords=("opencv", "dewarp", "edge", "magicclean", "cropandclean"),
    ),
    CapabilityPattern(
        name="local_ml",
        label="Local ML",
        keywords=(
            "tflite", "tensorflow", "onnx", "mediapipe", "ncnn", "mnn",
            "model", "inference", "interpreter", "tensor", "classifier",
            "segment", "segmentation", "quantized",
        ),
        strong_keywords=("tflite", "interpreter", "mediapipe", "inference"),
    ),
    CapabilityPattern(
        name="audio_voice",
        label="Audio/Voice",
        keywords=(
            "audio", "voice", "speech", "tts", "read aloud", "podcast",
            "yamnet", "vad", "mediarecorder", "sound", "waveform",
        ),
        strong_keywords=("yamnet", "vad", "audio", "speech"),
    ),
    CapabilityPattern(
        name="crypto_security",
        label="Crypto/Security",
        keywords=(
            "aes", "rsa", "sha", "hmac", "pbkdf", "cipher", "decrypt",
            "encrypt", "keystore", "signature", "certificate", "ssl",
            "tls", "crypto",
        ),
        strong_keywords=("aes", "rsa", "cipher", "decrypt", "encrypt", "hmac"),
    ),
    CapabilityPattern(
        name="cloud_network",
        label="Cloud/Network",
        keywords=(
            "http", "https", "retrofit", "okhttp", "upload", "download",
            "cloud", "sync", "asset", "job", "endpoint", "socket",
            "firebase", "api", "oauth", "token",
        ),
        strong_keywords=("upload", "cloud", "sync", "endpoint", "retrofit", "okhttp"),
    ),
    CapabilityPattern(
        name="ads_analytics",
        label="Ads/Analytics",
        keywords=(
            "adservices", "ad_id", "ads", "analytics", "marketing",
            "measurement", "attribution", "install referrer", "firebase",
            "crashlytics", "inmobi", "facebook",
        ),
        strong_keywords=("analytics", "attribution", "adservices", "crashlytics"),
    ),
    CapabilityPattern(
        name="maps_location",
        label="Maps/Location",
        keywords=(
            "location", "gps", "map", "geofence", "latitude", "longitude",
            "places", "navigation",
        ),
        strong_keywords=("location", "gps", "geofence"),
    ),
    CapabilityPattern(
        name="billing_payment",
        label="Billing/Payment",
        keywords=(
            "billing", "purchase", "subscription", "iap", "payment",
            "stripe", "paypal", "license", "entitlement",
        ),
        strong_keywords=("billing", "subscription", "purchase", "payment"),
    ),
)


def classify_text(text: str) -> dict[str, dict[str, object]]:
    lowered = text.lower()
    results: dict[str, dict[str, object]] = {}
    for pattern in CAPABILITY_PATTERNS:
        hits = sorted({kw for kw in pattern.keywords if kw.lower() in lowered})
        strong_hits = sorted({kw for kw in pattern.strong_keywords if kw.lower() in lowered})
        if hits:
            score = len(hits) + (2 * len(strong_hits))
            results[pattern.name] = {
                "label": pattern.label,
                "score": score,
                "hits": hits[:25],
                "strong_hits": strong_hits[:25],
            }
    return results


def classify_path(path: str) -> dict[str, dict[str, object]]:
    return classify_text(path.replace("/", " ").replace("_", " ").replace("-", " "))


def capability_names(names: object | None = None) -> list[str]:
    ordered = [pattern.name for pattern in CAPABILITY_PATTERNS]
    if names is None:
        return ordered
    selected = {str(name) for name in names}
    return [name for name in ordered if name in selected]
