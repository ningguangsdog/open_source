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
    "libgrpc",
    "libopencv_",
    "libswresample",
    "libswscale",
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

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "confidence": self.confidence,
            "reason": self.reason,
            "matched_prefix": self.matched_prefix,
        }


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

    if normalized_package:
        for prefix in explicit_first:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "first_party",
                    1.0,
                    "Matched an explicitly configured first-party package prefix.",
                    prefix,
                )
        for prefix in inferred_first:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "first_party",
                    0.95 if prefix.rstrip(".") == (app_package or "").strip(".") else 0.85,
                    "Matched the application package or its inferred organization root.",
                    prefix,
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
        for prefix in KNOWN_THIRD_PARTY_PREFIXES:
            if _matches_prefix(normalized_package, prefix):
                return OwnershipResult(
                    "third_party",
                    0.92,
                    "Matched the built-in SDK and dependency package registry.",
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


def classify_native_ownership(
    name: str | None,
    sha256: str | None,
    *,
    app_package: str | None = None,
    jni_symbols: Iterable[str] = (),
    first_party_hashes: Iterable[str] = (),
    third_party_hashes: Iterable[str] = (),
) -> OwnershipResult:
    normalized_name = Path(name or "").name.lower()
    normalized_sha = (sha256 or "").strip().lower()
    if normalized_sha and normalized_sha in normalize_hashes(first_party_hashes):
        return OwnershipResult(
            "first_party",
            1.0,
            "Matched an explicitly configured first-party native SHA-256.",
            normalized_sha,
        )
    if normalized_sha and normalized_sha in normalize_hashes(third_party_hashes):
        return OwnershipResult(
            "third_party",
            1.0,
            "Matched an explicitly configured third-party native SHA-256.",
            normalized_sha,
        )
    if app_package:
        jni_prefix = f"Java_{app_package.strip('.').replace('.', '_')}_"
        if any(str(symbol).startswith(jni_prefix) for symbol in jni_symbols):
            return OwnershipResult(
                "first_party",
                0.9,
                "Exported JNI symbols match the application package.",
                jni_prefix,
            )
    if normalized_name in KNOWN_PLATFORM_NATIVE_NAMES:
        return OwnershipResult(
            "platform",
            0.95,
            "Matched a known Android system library name.",
            normalized_name,
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
        )
    return OwnershipResult(
        "unknown",
        0.3,
        "No reliable native ownership indicator was available; SHA-256 is retained for batch attribution.",
        normalized_sha or None,
    )
