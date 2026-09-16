"""AWS STS, per operation: a session that can do one thing, for minutes.

Stage 1 for AWS. The vault stops holding an access key an agent could use
and holds a *seed*: an IAM user or role whose only permission is
`sts:AssumeRole` on one role. Every cleared operation calls AssumeRole with
a session policy built from the request's own values - this bucket, this
prefix - so the credential that comes back is narrower than the role, is
named after the clearance and the human, and expires in fifteen minutes,
which is the shortest STS allows. It is handed to the executor once and
reaches the process as environment variables and nothing else.

Signature Version 4 is written out here rather than pulled from boto3,
because the tower's dependency list is the thing a reviewer reads first and
the request is one POST. The endpoint is a parameter so the tests can stand
up a fake STS and prove what was asked for.

verified-by: tests/test_tower.py::TestAWSClearance::test_the_session_policy_names_only_the_requests_values
verified-by: tests/test_tower.py::TestAWSClearance::test_the_request_to_sts_is_signed_and_scoped
verified-by: tests/test_tower.py::TestAWSClearance::test_a_session_reaches_the_process_as_environment_once
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional

SESSION_SECONDS = 900          # the minimum STS accepts; the most we want
_ROLE_ARN = re.compile(r"^arn:aws(-[a-z]+)?:iam::\d{12}:role/[\w+=,.@/-]{1,512}\Z")
_ACTION = re.compile(r"^[a-z0-9-]{1,32}:[A-Za-z0-9*]{1,128}\Z")
_SESSION_NAME = re.compile(r"[^\w+=,.@-]")


@dataclass(frozen=True)
class AWSSession:
    """One operation's AWS credential: three values and a clock."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    serial: int
    not_after: float

    def env(self) -> dict[str, str]:
        return {"AWS_ACCESS_KEY_ID": self.access_key_id,
                "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
                "AWS_SESSION_TOKEN": self.session_token}


# --------------------------------------------------------------- the policy

def session_policy(spec: dict) -> dict:
    """The IAM session policy for one operation, from the declaration's
    `aws` block after the request's values were substituted.

    Only Allow statements, only the actions the declaration lists, only the
    resources it names - already filled in with this request's values by
    the adapter, so `arn:aws:s3:::{bucket}` arrived here as one bucket. The
    session can do nothing the role cannot (STS intersects), and nothing
    this request did not ask for (this policy).
    """
    actions = list(spec.get("actions", []))
    resources = list(spec.get("resources", []))
    conditions = spec.get("conditions") or {}
    for a in actions:
        if not _ACTION.match(a):
            raise ValueError(f"aws action {a!r} is not well formed")
    if not actions or not resources:
        raise ValueError("an aws block needs at least one action and one resource")
    statement = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if conditions:
        statement["Condition"] = conditions
    return {"Version": "2012-10-17", "Statement": [statement]}


# ------------------------------------------------------------------- sigv4

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = _sign(("AWS4" + secret).encode(), date)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


class STS:
    """The seed and the call. `assume()` is what the tower invokes."""

    def __init__(self, access_key_id: str, secret_access_key: str,
                 region: str = "us-east-1", endpoint: Optional[str] = None,
                 session_token: Optional[str] = None, opener=None, timeout: float = 10.0):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.region = region
        self.endpoint = endpoint or f"https://sts.{region}.amazonaws.com/"
        self.opener = opener or urllib.request.urlopen
        self.timeout = timeout

    def assume(self, role_arn: str, policy: dict, clearance_id: str, subject: str,
               now: Optional[float] = None, seconds: int = SESSION_SECONDS) -> AWSSession:
        if not _ROLE_ARN.match(role_arn):
            raise ValueError(f"role arn {role_arn!r} is not well formed")
        at = dt.datetime.fromtimestamp(now, dt.timezone.utc) if now is not None \
            else dt.datetime.now(dt.timezone.utc)
        amz_date = at.strftime("%Y%m%dT%H%M%SZ")
        date = at.strftime("%Y%m%d")
        # The session name is on every CloudTrail line the session produces:
        # the clearance id and the human, so the AWS side reads like the tape.
        who = _SESSION_NAME.sub("_", subject or "nobody")[:32]
        session_name = f"taper-{clearance_id[:16]}-{who}"[:64]
        params = {
            "Action": "AssumeRole",
            "Version": "2011-06-15",
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": str(seconds),
            "Policy": json.dumps(policy, separators=(",", ":")),
        }
        body = urllib.parse.urlencode(sorted(params.items()), quote_via=urllib.parse.quote)
        host = urllib.parse.urlsplit(self.endpoint).netloc
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "host": host,
            "x-amz-date": amz_date,
        }
        if self.session_token:
            headers["x-amz-security-token"] = self.session_token
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers))
        payload_hash = hashlib.sha256(body.encode()).hexdigest()
        canonical_request = "\n".join([
            "POST", urllib.parse.urlsplit(self.endpoint).path or "/", "",
            canonical_headers, signed_headers, payload_hash])
        scope = f"{date}/{self.region}/sts/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical_request.encode()).hexdigest()])
        signature = hmac.new(
            _signing_key(self.secret_access_key, date, self.region, "sts"),
            string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")

        request = urllib.request.Request(self.endpoint, data=body.encode(),
                                         headers=headers, method="POST")
        with self.opener(request, timeout=self.timeout) as response:
            text = response.read().decode()
        return _parse(text, clearance_id)


def _parse(text: str, clearance_id: str) -> AWSSession:
    root = ET.fromstring(text)
    ns = {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"}
    creds = root.find(".//sts:Credentials", ns)
    if creds is None:
        creds = root.find(".//Credentials")        # a fake without the namespace
    if creds is None:
        raise ValueError("no Credentials in the STS response")

    def get(name: str) -> str:
        node = creds.find(f"sts:{name}", ns)
        if node is None:
            node = creds.find(name)
        if node is None or not node.text:
            raise ValueError(f"STS response lacks {name}")
        return node.text.strip()

    expiration = get("Expiration").replace("Z", "+00:00")
    not_after = dt.datetime.fromisoformat(expiration).timestamp()
    serial = int.from_bytes(hashlib.sha256(clearance_id.encode()).digest()[:8], "big") \
        & 0x7FFFFFFFFFFFFFFF
    return AWSSession(get("AccessKeyId"), get("SecretAccessKey"), get("SessionToken"),
                      serial, not_after)
