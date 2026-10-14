"""Synthetic dataset generator for evaluation.

No real report data is ever included. Everything here is fabricated and targets
the intentionally vulnerable lab apps only.
"""

from .builders import VALID_BUILDERS, build_valid
from .generator import generate_dataset
from .lab import CWE_BY_CLASS, LAB_ACCOUNTS, LAB_BASE_URL, OOB_BASE_URL
from .schema import Attachment, DatasetManifest, Label, SyntheticReport

__all__ = [
    "Attachment",
    "CWE_BY_CLASS",
    "DatasetManifest",
    "LAB_ACCOUNTS",
    "LAB_BASE_URL",
    "Label",
    "OOB_BASE_URL",
    "SyntheticReport",
    "VALID_BUILDERS",
    "build_valid",
    "generate_dataset",
]
