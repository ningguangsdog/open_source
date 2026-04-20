from __future__ import annotations

import logging


def configure_logging(level: str = "INFO") -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    for noisy in ["androguard", "androguard.core", "androguard.core.axml"]:
        logging.getLogger(noisy).setLevel(logging.ERROR)
