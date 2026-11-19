import json
from pathlib import Path

import yaml
from cloudrecon.demo.fixtures import ACCOUNT
from cloudrecon.discovery.ec2 import RegionFailure, discover, parse_instance
from cloudrecon.discovery.host import parse_host_document
from cloudrecon.discovery.nmap_probe import authorize_probe, parse_nmap_xml
from cloudrecon.discovery.ssm import build_ssm_request, load_collector_script
from cloudrecon.errors import CollectionError, ScopeError
from cloudrecon.models import LoadBalancerRef
from cloudrecon.scope import Scope
from cloudrecon.security import safe_nmap_argv
from cloudrecon.util import project_root


class FakeBackend:
    def __init__(self, fail_region: str | None = None) -> None:
        self.fail_region = fail_region

    def account_id(self) -> str:
        return ACCOUNT

    def instances(self, region: str) -> list[dict]:
        if region == self.fail_region:
            raise RegionFailure(region, "UnauthorizedOperation", "denied")
        if region == "us-east-1":
            return [_instance("i-0abc000000000001"), _instance("i-0abc000000000002")]
        return []

    def ssm_status(self, region: str) -> dict[str, str] | None:
        if region == "eu-west-1":
            return None
        return {"i-0abc000000000001": "Online"}

    def security_groups(self, region: str, group_ids: list[str]) -> dict:
        return {
            "sg-1": {
                "GroupId": "sg-1",
                "GroupName": "web",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        }

    def route_has_igw(self, region: str, subnet_id: str) -> bool:
        return True

    def load_balancers_for_instances(self, region: str) -> dict:
        return {"i-0abc000000000001": [LoadBalancerRef(name="edge", scheme="internet-facing", ports=[443])]}


def _instance(instance_id: str) -> dict:
    return {
        "InstanceId": instance_id,
        "InstanceType": "t3.micro",
        "State": {"Name": "running"},
        "PrivateIpAddress": "10.0.0.5",
        "PublicIpAddress": "203.0.113.5",
        "ImageId": "ami-123",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-1",
        "LaunchTime": "2024-01-01T00:00:00+00:00",
        "IamInstanceProfile": {"Arn": "arn:aws:iam::111122223333:instance-profile/app"},
        "Tags": [{"Key": "Name", "Value": "web"}, {"Key": "Environment", "Value": "production"}],
        "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web"}],
    }


def test_pagination_shape_and_region_failure_are_preserved() -> None:
    bundle = discover(FakeBackend(fail_region="eu-west-1"), ["us-east-1", "eu-west-1"])
    assert len(bundle.assets) == 2
    assert any("UnauthorizedOperation" in error for error in bundle.errors)
    managed = next(asset for asset in bundle.assets if asset.instance_id == "i-0abc000000000001")
    unmanaged = next(asset for asset in bundle.assets if asset.instance_id == "i-0abc000000000002")
    assert managed.ssm_managed is True
    assert unmanaged.ssm_managed is False
    assert managed.sg_collected is True
    assert managed.security_groups[0].ingress[0].cidrs == ["0.0.0.0/0"]
    assert managed.load_balancers[0].scheme == "internet-facing"
    assert managed.environment == "production"


def test_ssm_unknown_is_not_false() -> None:
    asset = parse_instance(
        _instance("i-0abc000000000009"),
        account_id=ACCOUNT,
        region="eu-west-1",
        ssm=None,
        groups={},
        balancers={},
    )
    assert asset.ssm_managed is None
    assert asset.sg_collected is False


def test_host_parser_rejects_bad_json_and_redacts() -> None:
    sample = json.loads((project_root() / "examples" / "sample_host_ubuntu.json").read_text(encoding="utf-8"))
    parsed = parse_host_document(sample)
    assert parsed.packages_complete is True
    assert parsed.packages[0].name == "libssl3"
    sample["processes"] = [{"pid": 1, "command": "java -Dpassword=supersecret"}]
    redacted = parse_host_document(sample)
    assert "supersecret" not in redacted.processes[0]["command"]
    try:
        parse_host_document("{")
    except CollectionError:
        pass
    else:
        raise AssertionError("expected CollectionError")
    failed = dict(sample)
    failed["collection_status"] = "failed"
    failed["packages_complete"] = True
    assert parse_host_document(failed).packages_complete is False


def test_nmap_stays_gated() -> None:
    scope = Scope(accounts=["111122223333"], regions=["us-east-1"], allow_nmap=False, nmap_targets=[])
    try:
        authorize_probe(scope, False, "203.0.113.10")
    except ScopeError:
        pass
    else:
        raise AssertionError("nmap should be blocked")
    ports = parse_nmap_xml((project_root() / "examples" / "sample_nmap.xml").read_text(encoding="utf-8"))
    assert ports == [{"address": "203.0.113.10", "protocol": "tcp", "port": 443, "state": "open"}]
    argv = safe_nmap_argv("203.0.113.10", [443, 22])
    assert argv[0] == "nmap"
    assert "-sT" in argv


def test_ssm_command_uses_static_script() -> None:
    script = load_collector_script()
    request = build_ssm_request("i-0abc000000000001", script)
    assert request["DocumentName"] == "AWS-RunShellScript"
    assert request["Parameters"]["commands"] == [script]
    assert "eval " not in script.lower()
    text = Path(project_root() / "ansible" / "playbooks" / "discover.yml").read_text(encoding="utf-8")
    playbook = yaml.safe_load(text)
    assert playbook[0]["become"] is False
    assert "collect_host.sh" in playbook[0]["tasks"][0]["ansible.builtin.script"]
