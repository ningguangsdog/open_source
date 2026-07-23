from __future__ import annotations

import re
from collections.abc import Iterable as IterableABC
from dataclasses import dataclass
from typing import Iterable


CAMEL_PART_RE = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[A-Z]+|[0-9]+"
)
ALNUM_PART_RE = re.compile(r"[A-Za-z0-9]+")
SYMBOL_AFFIX_KEYWORDS = {"ocr", "pdf"}


@dataclass(frozen=True, slots=True)
class CapabilityPattern:
    name: str
    label: str
    keywords: tuple[str, ...]
    strong_keywords: tuple[str, ...] = ()
    min_regular_hits: int = 2


CAPABILITY_PATTERNS: tuple[CapabilityPattern, ...] = (
    CapabilityPattern(
        name="document_pdf",
        label="Document/PDF",
        keywords=(
            "document",
            "annotation",
            "annot",
            "bookmark",
            "signature",
            "xmp",
            "jp2k",
            "jpeg",
            "render",
        ),
        strong_keywords=("pddoc", "pdpage", "pde", "pdfium", "pdf", "acrobat"),
    ),
    CapabilityPattern(
        name="ocr",
        label="OCR/Text Recognition",
        keywords=(
            "recognize",
            "recognition",
            "fontmetrics",
            "text layer",
            "hidden text",
        ),
        strong_keywords=("ocr", "glyph", "deskew", "ilex", "latin ocr"),
    ),
    CapabilityPattern(
        name="scan_image",
        label="Scan/Image Processing",
        keywords=(
            "image",
            "bitmap",
            "crop",
            "clean",
            "detect",
            "filter",
            "jpeg",
            "png",
            "shadow",
            "glare",
            "document detection",
        ),
        strong_keywords=(
            "scan",
            "camera",
            "opencv",
            "dewarp",
            "edge detection",
            "magicclean",
            "cropandclean",
        ),
    ),
    CapabilityPattern(
        name="local_ml",
        label="Local ML",
        keywords=(
            "model",
            "tensor",
            "classifier",
            "segment",
            "segmentation",
            "quantized",
        ),
        strong_keywords=(
            "tflite",
            "tensorflow",
            "onnx",
            "mediapipe",
            "ncnn",
            "mnn",
            "inference",
            "interpreter",
        ),
    ),
    CapabilityPattern(
        name="audio_voice",
        label="Audio/Voice",
        keywords=(
            "audio",
            "voice",
            "speech",
            "tts",
            "read aloud",
            "podcast",
            "sound",
            "waveform",
        ),
        strong_keywords=("yamnet", "vad", "mediarecorder"),
    ),
    CapabilityPattern(
        name="crypto_security",
        label="Crypto/Security",
        keywords=(
            "sha",
            "signature",
            "certificate",
            "ssl",
            "tls",
            "crypto",
            "keystore",
        ),
        strong_keywords=(
            "aes",
            "rsa",
            "hmac",
            "pbkdf",
            "cipher",
            "decrypt",
            "encrypt",
        ),
    ),
    CapabilityPattern(
        name="cloud_network",
        label="Cloud/Network",
        keywords=(
            "http",
            "https",
            "download",
            "cloud",
            "sync",
            "endpoint",
            "socket",
            "firebase",
            "oauth",
        ),
        strong_keywords=("upload", "retrofit", "okhttp", "grpc", "websocket"),
    ),
    CapabilityPattern(
        name="ads_analytics",
        label="Ads/Analytics",
        keywords=(
            "ads",
            "analytics",
            "marketing",
            "measurement",
            "install referrer",
            "firebase",
            "inmobi",
            "facebook",
        ),
        strong_keywords=(
            "attribution",
            "adservices",
            "ad id",
            "crashlytics",
            "appsflyer",
            "adjust",
        ),
    ),
    CapabilityPattern(
        name="maps_location",
        label="Maps/Location",
        keywords=("places", "navigation"),
        strong_keywords=(
            "location",
            "gps",
            "geofence",
            "latitude",
            "longitude",
        ),
    ),
    CapabilityPattern(
        name="billing_payment",
        label="Billing/Payment",
        keywords=("iap", "stripe", "paypal", "license", "entitlement"),
        strong_keywords=("billing", "purchase", "subscription", "payment"),
    ),
)


def _split_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for raw_part in ALNUM_PART_RE.findall(text):
        camel_parts = CAMEL_PART_RE.findall(raw_part)
        if camel_parts:
            tokens.extend(part.lower() for part in camel_parts)
        else:
            tokens.append(raw_part.lower())
    return tokens


def _contains_sequence(tokens: list[str], wanted: tuple[str, ...]) -> bool:
    if not wanted or len(wanted) > len(tokens):
        return False
    width = len(wanted)
    return any(tuple(tokens[index : index + width]) == wanted for index in range(len(tokens) - width + 1))


def _keyword_match(
    tokens: list[str],
    keyword: str,
    *,
    allow_symbol_affix: bool,
) -> tuple[bool, str | None]:
    wanted = tuple(_split_tokens(keyword))
    if not wanted:
        return False, None
    if _contains_sequence(tokens, wanted):
        return True, "token_sequence"
    if allow_symbol_affix and len(wanted) == 1 and len(wanted[0]) >= 3:
        needle = wanted[0]
        for token in tokens:
            if len(token) > len(needle) and (
                token.startswith(needle) or token.endswith(needle)
            ):
                return True, "symbol_affix"
    return False, None


def classify_texts(texts: Iterable[str]) -> dict[str, dict[str, object]]:
    regular_by_name: dict[str, set[str]] = {
        pattern.name: set() for pattern in CAPABILITY_PATTERNS
    }
    strong_by_name: dict[str, set[str]] = {
        pattern.name: set() for pattern in CAPABILITY_PATTERNS
    }
    modes_by_name: dict[str, dict[str, str]] = {
        pattern.name: {} for pattern in CAPABILITY_PATTERNS
    }
    for text in texts:
        tokens = _split_tokens(text)
        for pattern in CAPABILITY_PATTERNS:
            regular_hits = regular_by_name[pattern.name]
            strong_hits = strong_by_name[pattern.name]
            match_modes = modes_by_name[pattern.name]
            for keyword in pattern.keywords:
                matched, mode = _keyword_match(
                    tokens,
                    keyword,
                    allow_symbol_affix=False,
                )
                if matched:
                    regular_hits.add(keyword)
                    if mode:
                        match_modes[keyword] = mode
            for keyword in pattern.strong_keywords:
                matched, mode = _keyword_match(
                    tokens,
                    keyword,
                    allow_symbol_affix=keyword in SYMBOL_AFFIX_KEYWORDS,
                )
                if matched:
                    strong_hits.add(keyword)
                    if mode:
                        match_modes[keyword] = mode

    results: dict[str, dict[str, object]] = {}
    for pattern in CAPABILITY_PATTERNS:
        regular_hits = regular_by_name[pattern.name]
        strong_hits = strong_by_name[pattern.name]
        match_modes = modes_by_name[pattern.name]
        if not strong_hits and len(regular_hits) < pattern.min_regular_hits:
            continue
        score = len(regular_hits) + (3 * len(strong_hits))
        results[pattern.name] = {
            "label": pattern.label,
            "score": score,
            "hits": sorted(regular_hits | strong_hits)[:25],
            "strong_hits": sorted(strong_hits)[:25],
            "match_modes": {
                keyword: match_modes[keyword]
                for keyword in sorted(match_modes)[:25]
            },
        }
    return results


def classify_text(text: str) -> dict[str, dict[str, object]]:
    return classify_texts([text])


def keyword_matches_text(
    text: str,
    keyword: str,
    *,
    allow_symbol_affix: bool = False,
) -> bool:
    matched, _ = _keyword_match(
        _split_tokens(text),
        keyword,
        allow_symbol_affix=allow_symbol_affix,
    )
    return matched


def classify_path(path: str) -> dict[str, dict[str, object]]:
    return classify_text(path)


def capability_names(names: Iterable[object] | object | None = None) -> list[str]:
    ordered = [pattern.name for pattern in CAPABILITY_PATTERNS]
    if names is None:
        return ordered
    if isinstance(names, (str, bytes)):
        selected = {str(names)}
    elif isinstance(names, IterableABC):
        selected = {str(name) for name in names}
    else:
        selected = {str(names)}
    return [name for name in ordered if name in selected]
