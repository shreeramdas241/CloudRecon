"""Package version comparison for Debian, RPM, and PEP 440.

Debian comparison follows the Debian Policy ordering (epoch, upstream, revision),
including the tilde rule. RPM comparison covers epoch, version, and release with
tilde pre-release ordering. These are matching primitives, not a claim that a
distribution has or has not backported a fix.
"""

from __future__ import annotations

from cloudrecon.errors import VersionCompareError

STYLES = ("deb", "rpm", "pep440")


def version_compare(left: str, right: str, style: str) -> int:
    """Return -1, 0, or 1 when left is older, equal, or newer than right."""
    if style == "deb":
        return cmp_debian(left, right)
    if style == "rpm":
        return cmp_rpm_evr(left, right)
    if style == "pep440":
        return cmp_pep440(left, right)
    raise VersionCompareError(f"Unsupported version style: {style}")


def cmp_debian(left: str, right: str) -> int:
    left_epoch, left_rest = _split_epoch(left)
    right_epoch, right_rest = _split_epoch(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    left_up, left_rev = _split_debian_revision(left_rest)
    right_up, right_rev = _split_debian_revision(right_rest)
    compared = _cmp_debian_part(left_up, right_up)
    if compared != 0:
        return compared
    return _cmp_debian_part(left_rev, right_rev)


def cmp_rpm_evr(left: str, right: str) -> int:
    left_epoch, left_version, left_release = _split_rpm(left)
    right_epoch, right_version, right_release = _split_rpm(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    compared = _cmp_rpm_part(left_version, right_version)
    if compared != 0:
        return compared
    return _cmp_rpm_part(left_release, right_release)


def cmp_pep440(left: str, right: str) -> int:
    try:
        from packaging.version import Version
    except ImportError as exc:  # pragma: no cover
        raise VersionCompareError("packaging is required for PEP 440 comparison") from exc
    try:
        parsed_left = Version(left)
        parsed_right = Version(right)
    except Exception as exc:
        raise VersionCompareError(f"Not a PEP 440 version: {left!r} or {right!r}") from exc
    return (parsed_left > parsed_right) - (parsed_left < parsed_right)


def style_for_manager(manager: str) -> str:
    normalized = (manager or "").lower()
    if normalized in {"deb", "apt", "dpkg"}:
        return "deb"
    if normalized in {"rpm", "yum", "dnf"}:
        return "rpm"
    if normalized in {"pep440", "python", "maven", "npm", "application"}:
        return "pep440"
    raise VersionCompareError(f"No version style for package manager {manager!r}")


def style_for_ecosystem(ecosystem: str) -> str:
    name = (ecosystem or "").split(":", 1)[0].lower()
    if name in {"ubuntu", "debian"}:
        return "deb"
    if name in {"amazonlinux", "rhel", "amzn", "alma", "rocky", "fedora"}:
        return "rpm"
    if name in {"maven", "pypi", "npm", "application"}:
        return "pep440"
    raise VersionCompareError(f"No version style for ecosystem {ecosystem!r}")


def upstream_version(raw: str, manager: str) -> str:
    """Drop epoch and distro revision so NVD-style upstream ranges can be compared."""
    style = style_for_manager(manager)
    if style == "pep440":
        return raw
    rest = raw.split(":", 1)[1] if _has_epoch(raw) else raw
    if style == "deb":
        upstream, _revision = _split_debian_revision(rest)
        return upstream
    version, _release = _split_rpm_version_release(rest)
    return version


def _has_epoch(value: str) -> bool:
    head, sep, _tail = value.partition(":")
    return bool(sep) and head.isdigit()


def _split_epoch(value: str) -> tuple[int, str]:
    if not value:
        raise VersionCompareError("Empty version")
    if _has_epoch(value):
        epoch, rest = value.split(":", 1)
        return int(epoch), rest
    return 0, value


def _split_debian_revision(value: str) -> tuple[str, str]:
    if "-" in value:
        upstream, revision = value.rsplit("-", 1)
        return upstream, revision
    return value, ""


def _deb_order(char: str) -> int:
    if char == "":
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _cmp_nondigit(left: str, right: str) -> int:
    length = max(len(left), len(right))
    for index in range(length):
        left_char = left[index] if index < len(left) else ""
        right_char = right[index] if index < len(right) else ""
        left_order = _deb_order(left_char)
        right_order = _deb_order(right_char)
        if left_order != right_order:
            return -1 if left_order < right_order else 1
    return 0


def _cmp_debian_part(left: str, right: str) -> int:
    while left or right:
        left_text = ""
        right_text = ""
        while left and not left[0].isdigit():
            left_text += left[0]
            left = left[1:]
        while right and not right[0].isdigit():
            right_text += right[0]
            right = right[1:]
        compared = _cmp_nondigit(left_text, right_text)
        if compared != 0:
            return compared
        left_digits = ""
        right_digits = ""
        while left and left[0].isdigit():
            left_digits += left[0]
            left = left[1:]
        while right and right[0].isdigit():
            right_digits += right[0]
            right = right[1:]
        left_number = int(left_digits) if left_digits else 0
        right_number = int(right_digits) if right_digits else 0
        if left_number != right_number:
            return -1 if left_number < right_number else 1
    return 0


def _split_rpm(value: str) -> tuple[int, str, str]:
    if not value:
        raise VersionCompareError("Empty RPM version")
    epoch, rest = _split_epoch(value)
    version, release = _split_rpm_version_release(rest)
    return epoch, version, release


def _split_rpm_version_release(value: str) -> tuple[str, str]:
    if "-" in value:
        version, release = value.split("-", 1)
        return version, release
    return value, ""


def _rpm_segments(value: str) -> list[tuple[str, object]]:
    segments: list[tuple[str, object]] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "~":
            segments.append(("tilde", ""))
            index += 1
        elif char == "^":
            segments.append(("caret", ""))
            index += 1
        elif char.isdigit():
            end = index
            while end < len(value) and value[end].isdigit():
                end += 1
            segments.append(("num", int(value[index:end])))
            index = end
        elif char.isalpha():
            end = index
            while end < len(value) and value[end].isalpha():
                end += 1
            segments.append(("alpha", value[index:end]))
            index = end
        else:
            index += 1
    return segments


def _cmp_rpm_part(left: str, right: str) -> int:
    if left == right:
        return 0
    left_parts = _rpm_segments(left)
    right_parts = _rpm_segments(right)
    length = max(len(left_parts), len(right_parts))
    for index in range(length):
        if index >= len(left_parts):
            return 1 if right_parts[index][0] == "tilde" else -1
        if index >= len(right_parts):
            return -1 if left_parts[index][0] == "tilde" else 1
        left_part = left_parts[index]
        right_part = right_parts[index]
        if left_part == right_part:
            continue
        if left_part[0] == "tilde" and right_part[0] != "tilde":
            return -1
        if right_part[0] == "tilde" and left_part[0] != "tilde":
            return 1
        rank = {"num": 3, "alpha": 2, "caret": 1, "tilde": 0}
        if left_part[0] != right_part[0]:
            left_rank = rank[left_part[0]]
            right_rank = rank[right_part[0]]
            return -1 if left_rank < right_rank else 1
        if left_part[1] != right_part[1]:
            return -1 if left_part[1] < right_part[1] else 1
    return 0
