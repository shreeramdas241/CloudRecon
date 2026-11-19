from cloudrecon.models import PackageRecord
from cloudrecon.normalize import canonical_product, normalize_package_name, version_key


def test_alias_and_version_key() -> None:
    assert normalize_package_name("LibSSL3.amd64") == "libssl3"
    assert canonical_product("libssl3") == "openssl"
    deb = PackageRecord(name="libssl3", version="3.0.2-0ubuntu1.10", manager="deb")
    assert version_key(deb) == "3.0.2-0ubuntu1.10"
    rpm = PackageRecord(name="httpd", version="2.4.58", release="1.amzn2023.0.1", manager="rpm", epoch="0")
    assert version_key(rpm) == "2.4.58-1.amzn2023.0.1"
