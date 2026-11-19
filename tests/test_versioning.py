from cloudrecon.errors import VersionCompareError
from cloudrecon.versioning import cmp_debian, cmp_pep440, cmp_rpm_evr, version_compare


def test_debian_ordering() -> None:
    assert cmp_debian("1.0", "1.0") == 0
    assert cmp_debian("1.0", "1.1") < 0
    assert cmp_debian("1:1.0", "2.0") > 0
    assert cmp_debian("1.0~rc1", "1.0") < 0
    assert cmp_debian("1.0-1ubuntu1", "1.0-1ubuntu2") < 0
    assert cmp_debian("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15") < 0
    assert cmp_debian("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.15") == 0
    assert cmp_debian("1.0", "1.0-0") == 0
    assert cmp_debian("1.0", "1.0-1") < 0
    assert cmp_debian("7.81.0-1ubuntu1.14", "7.81.0-1ubuntu1.16") < 0
    assert cmp_debian("7.81.0-1ubuntu1.20", "7.81.0-1ubuntu1.16") > 0


def test_debian_tilde_sorts_before_empty() -> None:
    assert cmp_debian("1.0~rc1-1", "1.0-1") < 0


def test_rpm_ordering() -> None:
    assert cmp_rpm_evr("1.2.3-1", "1.2.3-2") < 0
    assert cmp_rpm_evr("1:0.1-1", "2.0-1") > 0
    assert cmp_rpm_evr("1.0~rc1", "1.0") < 0
    assert cmp_rpm_evr("2.4.58-1.amzn2023.0.1", "2.4.58-1.amzn2023.0.5") < 0
    assert cmp_rpm_evr("1.0.2k-19.amzn2.0.8", "1.0.2k-19.amzn2.0.10") < 0


def test_pep440_and_style_dispatch() -> None:
    assert cmp_pep440("2.14.1", "2.15.0") < 0
    assert version_compare("2.14.1", "2.15.0", "pep440") < 0
    try:
        version_compare("not a version", "1", "pep440")
    except VersionCompareError:
        pass
    else:
        raise AssertionError("expected VersionCompareError")
