"""Project-specific errors."""


class CloudReconError(Exception):
    """Base error for expected operational failures."""


class CredentialError(CloudReconError):
    """AWS credentials are missing or rejected. Never includes the secret."""


class ScopeError(CloudReconError):
    """The requested action is outside the configured authorization boundary."""


class IntelError(CloudReconError):
    """Vulnerability intelligence could not be retrieved or parsed."""


class CollectionError(CloudReconError):
    """Host collection failed or returned data that cannot be trusted as complete."""


class VersionCompareError(CloudReconError):
    """Two versions could not be compared with the selected algorithm."""
