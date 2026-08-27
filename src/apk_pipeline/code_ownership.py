"""Deterministic ownership attribution for decompiled Java/Kotlin sources."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLATFORM_PREFIXES = (
    "android.",
    "androidx.",
    "com.android.",
    "dalvik.",
    "java.",
    "javax.",
    "jdk.",
    "kotlin.",
    "kotlinx.",
    "org.w3c.",
    "org.xml.",
    "sun.",
)

KNOWN_THIRD_PARTY_PREFIXES = (
    "com.adjust.",
    "com.airbnb.",
    "com.android.billingclient.",
    "com.appsflyer.",
    "com.bumptech.glide.",
    "com.facebook.",
    "com.google.",
    "com.mixpanel.",
    "com.squareup.",
    "com.stripe.",
    "com.unity3d.",
    "dagger.",
    "io.branch.",
    "io.fabric.",
    "io.grpc.",
    "io.reactivex.",
    "okhttp3.",
    "okio.",
    "org.apache.",
    "org.bouncycastle.",
    "org.chromium.",
    "org.jetbrains.",
    "org.json.",
    "org.mozilla.",
    "retrofit2.",
)

KNOWN_PLATFORM_NATIVE_NAMES = {
    "libandroid.so",
    "libbinder.so",
    "libdl.so",
    "libjnigraphics.so",
    "liblog.so",
    "libm.so",
    "libnativewindow.so",
    "libz.so",
}

KNOWN_THIRD_PARTY_NATIVE_NAMES = {
    "libc++_shared.so",
    "libcrypto.so",
    "libfbjni.so",
    "libflutter.so",
    "libjpeg.so",
    "libmediapipe_jni.so",
    "libncnn.so",
    "libonnxruntime.so",
    "libpng.so",
    "libpdfium.so",
    "libfreetype.so",
    "libtesseract.so",
    "libreactnativejni.so",
    "libsqlite.so",
    "libsqlite3.so",
    "libssl.so",
    "libtensorflowlite.so",
    "libtensorflowlite_jni.so",
    "libwebp.so",
}

KNOWN_THIRD_PARTY_NATIVE_PREFIXES = (
    "libavcodec",
    "libavfilter",
    "libavformat",
    "libavutil",
    "libcrashlytics",
    "libgrpc",
    "libmediapipe_",
    "libopencv_",
    "libswresample",
    "libswscale",
    "libtensorflowlite_",
)

DEPENDENCY_PATH_MARKERS = (
    "meta-inf/maven/",
    "meta-inf/services/",
    "/third_party/",
    "/third-party/",
    "/vendor/",
)

GENERIC_ORGANIZATION_TOKENS = {
    "app",
    "apps",
    "application",
    "mobile",
    "software",
    "android",
    "example",
}


@dataclass(frozen=True, slots=True)
class OwnershipResult:
    category: str
    confidence: float
    reason: str
    matched_prefix: str | None = None
    vendor: str | None = None
    component: str | None = None
    attribution_kind: str | None = None
    corroboration: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "confidence": self.confidence,
            "reason": self.reason,
            "matched_prefix": self.matched_prefix,
            "vendor": self.vendor,
            "component": self.component,
            "attribution_kind": self.attribution_kind,
            "corroboration": list(self.corroboration),
        }


@dataclass(frozen=True, slots=True)
class NativeComponentRule:
    names: tuple[str, ...]
    vendor: str
    component: str
    confidence: float
    name_prefixes: tuple[str, ...] = ()
    evidence_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ManagedComponentRule:
    prefixes: tuple[str, ...]
    vendor: str
    component: str
    confidence: float


MANAGED_COMPONENT_RULES = (
    ManagedComponentRule(
        prefixes=("com.pdftron.", "com.apryse."),
        vendor="Apryse",
        component="PDFNet SDK",
        confidence=0.99,
    ),
    ManagedComponentRule(
        prefixes=("com.osano.",),
        vendor="Osano",
        component="Osano Consent Management SDK",
        confidence=0.98,
    ),
    ManagedComponentRule(
        prefixes=("org.opencv.",),
        vendor="OpenCV",
        component="OpenCV Java bindings",
        confidence=0.99,
    ),
    ManagedComponentRule(
        prefixes=("com.google.mlkit.",),
        vendor="Google",
        component="Google ML Kit",
        confidence=0.98,
    ),
    ManagedComponentRule(
        prefixes=("com.google.firebase.",),
        vendor="Google",
        component="Firebase SDK",
        confidence=0.98,
    ),
    ManagedComponentRule(
        prefixes=("com.google.android.gms.",),
        vendor="Google",
        component="Google Play services",
        confidence=0.97,
    ),
    ManagedComponentRule(
        prefixes=("org.tensorflow.",),
        vendor="Google",
        component="TensorFlow runtime",
        confidence=0.98,
    ),
    ManagedComponentRule(
        prefixes=("ai.onnxruntime.",),
        vendor="Microsoft",
        component="ONNX Runtime",
        confidence=0.98,
    ),
    ManagedComponentRule(
        prefixes=("org.pytorch.",),
        vendor="PyTorch",
        component="PyTorch runtime",
        confidence=0.98,
    ),
)


NATIVE_COMPONENT_RULES = (
    NativeComponentRule(
        names=("libpdfnetc.so",),
        vendor="Apryse",
        component="PDFNet SDK",
        confidence=0.99,
    ),
    NativeComponentRule(
        names=("libmlkit_google_ocr_pipeline.so",),
        vendor="Google",
        component="Google ML Kit OCR",
        confidence=0.99,
    ),
    NativeComponentRule(
        names=("libtranslate_jni.so",),
        vendor="Google",
        component="Google ML Kit Translation",
        confidence=0.98,
    ),
    NativeComponentRule(
        names=("liblanguage_id_l2c_jni.so",),
        vendor="Google",
        component="Google ML Kit Language Identification",
        confidence=0.98,
    ),
    NativeComponentRule(
        names=("libdatastore_shared_counter.so",),
        vendor="AndroidX",
        component="AndroidX DataStore Shared Counter",
        confidence=0.96,
        evidence_markers=(
            "androidx.datastore",
            "androidx/datastore",
            "datastore_shared_counter",
            "datastore shared counter",
        ),
    ),
    NativeComponentRule(
        names=(),
        name_prefixes=("libmlkit_",),
        vendor="Google",
        component="Google ML Kit native runtime",
        confidence=0.96,
    ),
)


def normalize_prefixes(values: Iterable[str]) -> tuple[str, ...]:
    normalized = {
        value.strip().strip(".") + "."
        for value in values
        if value and value.strip().strip(".")
    }
    return tuple(sorted(normalized))


def _matches_prefix(package: str, prefix: str) -> bool:
    bare = prefix.rstrip(".")
    return package == bare or package.startswith(prefix)


def infer_first_party_prefixes(app_package: str | None) -> tuple[str, ...]:
    if not app_package:
        return ()
    package = app_package.strip().strip(".")
    if not package:
        return ()
    parts = package.split(".")
    prefixes = {package + "."}
    if len(parts) >= 3 and parts[0] in {"com", "org", "net", "io"}:
        organization = parts[1].lower()
        if organization not in GENERIC_ORGANIZATION_TOKENS:
            prefixes.add(".".join(parts[:2]) + ".")
    return tuple(sorted(prefixes, key=lambda item: (-len(item), item)))


def _managed_component_match(
    package: str,
) -> tuple[ManagedComponentRule, str] | None:
    normalized_package = package.casefold()
    for rule in MANAGED_COMPONENT_RULES:
        for prefix in rule.prefixes:
            if _matches_prefix(normalized_package, prefix):
                return rule, prefix
    return None


def classify_code_ownership(
    package: str | None,
    file_path: str | Path,
    *,
    app_package: str | None = None,
    first_party_prefixes: Iterable[str] = (),
    third_party_prefixes: Iterable[str] = (),
) -> OwnershipResult:
    normalized_package = (package or "").strip().strip(".")
    normalized_path = str(file_path).replace("\\", "/").lower()
    explicit_first = normalize_prefixes(first_party_prefixes)
    inferred_first = infer_first_party_prefixes(app_package)
    explicit_third = normalize_prefixes(third_party_prefixes)
    normalized_app_package = (app_package or "").strip().strip(".")

    if normalized_package:
        for prefix in explicit_first:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "first_party",
                    1.0,
                    "Matched an explicitly configured first-party package prefix.",
                    prefix,
                )
        if normalized_app_package and (
            normalized_package == normalized_app_package
            or normalized_package.startswith(normalized_app_package + ".")
        ):
            return OwnershipResult(
                "first_party",
                0.98,
                "Matched the exact application package namespace.",
                normalized_app_package + ".",
            )
        for prefix in PLATFORM_PREFIXES:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "platform",
                    0.98,
                    "Matched an Android, Java, or Kotlin platform package.",
                    prefix,
                )
        for prefix in explicit_third:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "third_party",
                    1.0,
                    "Matched an explicitly configured third-party package prefix.",
                    prefix,
                )
        component_match = _managed_component_match(normalized_package)
        if component_match is not None:
            rule, prefix = component_match
            return OwnershipResult(
                "third_party",
                rule.confidence,
                "Matched the audited managed SDK component registry.",
                prefix,
                vendor=rule.vendor,
                component=rule.component,
                attribution_kind="managed_component_registry",
                corroboration=(f"package_prefix:{prefix}",),
            )
        for prefix in KNOWN_THIRD_PARTY_PREFIXES:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "third_party",
                    0.92,
                    "Matched the built-in SDK and dependency package registry.",
                    prefix,
                )
        for prefix in inferred_first:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "unknown",
                    0.45,
                    "Matched only the inferred organization root; retained as uncertain ownership.",
                    prefix,
                )

    if any(marker in normalized_path for marker in DEPENDENCY_PATH_MARKERS):
        return OwnershipResult(
            "third_party",
            0.75,
            "Source path contains a dependency or vendor marker.",
        )
    return OwnershipResult(
        "unknown",
        0.25,
        "No reliable ownership indicator was available.",
    )


def normalize_hashes(values: Iterable[str]) -> frozenset[str]:
    return frozenset(
        value.strip().lower()
        for value in values
        if value and SHA256_RE.fullmatch(value.strip().lower())
    )


def _native_component_match(
    normalized_name: str,
    evidence_tokens: Iterable[str],
) -> tuple[NativeComponentRule, tuple[str, ...], bool] | None:
    normalized_evidence = tuple(
        sorted(
            {
                str(value).strip().casefold()
                for value in evidence_tokens
                if str(value).strip()
            }
        )
    )
    for rule in NATIVE_COMPONENT_RULES:
        name_match = normalized_name in rule.names or any(
            normalized_name.startswith(prefix)
            for prefix in rule.name_prefixes
        )
        if not name_match:
            continue
        corroboration = tuple(
            marker
            for marker in rule.evidence_markers
            if any(marker in value for value in normalized_evidence)
        )
        corroborated = not rule.evidence_markers or bool(corroboration)
        return rule, corroboration, corroborated
    return None


def classify_native_ownership(
    name: str | None,
    sha256: str | None,
    *,
    app_package: str | None = None,
    jni_symbols: Iterable[str] = (),
    first_party_hashes: Iterable[str] = (),
    third_party_hashes: Iterable[str] = (),
    evidence_tokens: Iterable[str] = (),
) -> OwnershipResult:
    normalized_name = Path(name or "").name.lower()
    normalized_sha = (sha256 or "").strip().lower()
    if normalized_sha and normalized_sha in normalize_hashes(first_party_hashes):
        return OwnershipResult(
            "first_party",
            1.0,
            "Matched an explicitly configured first-party native SHA-256.",
            normalized_sha,
            attribution_kind="explicit_hash",
        )
    if normalized_sha and normalized_sha in normalize_hashes(third_party_hashes):
        return OwnershipResult(
            "third_party",
            1.0,
            "Matched an explicitly configured third-party native SHA-256.",
            normalized_sha,
            attribution_kind="explicit_hash",
        )
    if normalized_name in KNOWN_PLATFORM_NATIVE_NAMES:
        return OwnershipResult(
            "platform",
            0.95,
            "Matched a known Android system library name.",
            normalized_name,
            attribution_kind="platform_registry",
        )
    component_match = _native_component_match(
        normalized_name,
        evidence_tokens,
    )
    if component_match is not None:
        rule, corroboration, corroborated = component_match
        if corroborated:
            return OwnershipResult(
                "third_party",
                rule.confidence,
                "Matched an audited native vendor-component rule.",
                normalized_name,
                vendor=rule.vendor,
                component=rule.component,
                attribution_kind="vendor_component_registry",
                corroboration=corroboration,
            )
        return OwnershipResult(
            "unknown",
            0.45,
            "Library name suggests a dependency, but required cross-layer corroboration was absent.",
            normalized_name,
            vendor=rule.vendor,
            component=rule.component,
            attribution_kind="unconfirmed_component_name",
        )
    if normalized_name in KNOWN_THIRD_PARTY_NATIVE_NAMES or any(
        normalized_name.startswith(prefix)
        for prefix in KNOWN_THIRD_PARTY_NATIVE_PREFIXES
    ):
        return OwnershipResult(
            "third_party",
            0.9,
            "Matched a conservative built-in registry of native runtime names.",
            normalized_name,
            attribution_kind="dependency_name_registry",
        )
    if app_package:
        jni_prefix = f"Java_{app_package.strip('.').replace('.', '_')}_"
        if any(str(symbol).startswith(jni_prefix) for symbol in jni_symbols):
            return OwnershipResult(
                "first_party",
                0.9,
                "Exported JNI symbols match the application package after dependency rules were excluded.",
                jni_prefix,
                attribution_kind="app_jni_namespace",
            )
    return OwnershipResult(
        "unknown",
        0.3,
        "No reliable native ownership indicator was available; SHA-256 is retained for batch attribution.",
        normalized_sha or None,
        attribution_kind="unresolved",
    )
