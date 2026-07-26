"""Public API for Prooflint."""

from prooflint.manifest import build_manifest, verify_manifest
from prooflint.models import (
    Diagnostic,
    EvidenceItem,
    EvidenceState,
    Finding,
    FindingStatus,
    ManifestVerification,
    Reproduction,
    Scope,
    ValidationResult,
)
from prooflint.parser import load_finding
from prooflint.rules import validate_finding

__all__ = [
    "Diagnostic",
    "EvidenceItem",
    "EvidenceState",
    "Finding",
    "FindingStatus",
    "ManifestVerification",
    "Reproduction",
    "Scope",
    "ValidationResult",
    "build_manifest",
    "load_finding",
    "validate_finding",
    "verify_manifest",
]

__version__ = "0.1.0"
