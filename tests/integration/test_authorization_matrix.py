"""Canonical authorization regression matrix for PowerDNS-Admin.

This file is the QA specification for authorization behavior. Each matrix row
links to an executable regression test, and the validator below detects missing
or renamed references.
"""

from pathlib import Path

import pytest

AUTHORIZATION_MATRIX = [
    {
        "priority": 1,
        "actor": "User",
        "credential_type": "basic_auth",
        "target": "unowned zone",
        "scope": "none",
        "expected": "deny",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_basic_auth_user_zone_list_respects_direct_and_account_grants",
        "reason": "Core tenant isolation; ordinary users must not access zones outside their grant scope.",
    },
    {
        "priority": 2,
        "actor": "User",
        "credential_type": "basic_auth",
        "target": "unrelated account",
        "scope": "none",
        "expected": "deny",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_basic_auth_user_zone_list_excludes_unrelated_account",
        "reason": "Prevents cross-account leakage and privilege drift via account membership.",
    },
    {
        "priority": 3,
        "actor": "User",
        "credential_type": "basic_auth",
        "target": "owned zone",
        "scope": "domain ACL",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_basic_auth_user_zone_list_respects_direct_and_account_grants",
        "reason": "Positive validation of direct domain grant access.",
    },
    {
        "priority": 4,
        "actor": "User",
        "credential_type": "basic_auth",
        "target": "account-owned zone",
        "scope": "account ACL",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_basic_auth_user_zone_list_respects_direct_and_account_grants",
        "reason": "Validates the distinct account inheritance path for zone access.",
    },
    {
        "priority": 5,
        "actor": "User API key",
        "credential_type": "api_key",
        "target": "other zone",
        "scope": "domain scope",
        "expected": "deny",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_user_apikey_cannot_access_another_tenants_zone_subpath",
        "reason": "API-key ACL enforcement must match the user authorization boundary.",
    },
    {
        "priority": 6,
        "actor": "User API key",
        "credential_type": "api_key",
        "target": "permitted zone",
        "scope": "domain scope",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_user_apikey_can_access_its_own_zone_subpath",
        "reason": "Positive validation of a valid scoped API key.",
    },
    {
        "priority": 7,
        "actor": "User API key",
        "credential_type": "api_key",
        "target": "account zone",
        "scope": "account scope",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_account_scoped_user_apikey_can_access_account_zone",
        "reason": "Account-scoped User keys inherit access to domains attached to the account.",
    },
    {
        "priority": 8,
        "actor": "User",
        "credential_type": "basic_auth",
        "target": "account assignment",
        "scope": "—",
        "expected": "deny",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_user_cannot_assign_account_scope_to_apikey",
        "reason": "Mutation guard: this is a common privilege-escalation path if mis-scoped.",
    },
    {
        "priority": 9,
        "actor": "User",
        "credential_type": "basic_auth",
        "target": "Administrator key creation",
        "scope": "—",
        "expected": "deny",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_user_cannot_create_administrator_apikey",
        "reason": "Prevents ordinary keys from creating high-privilege keys.",
    },
    {
        "priority": 10,
        "actor": "Operator",
        "credential_type": "basic_auth",
        "target": "Administrator key creation",
        "scope": "—",
        "expected": "deny",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_operator_cannot_create_administrator_apikey",
        "reason": "Prevents operator-level API keys from escalating to admin keys.",
    },
    {
        "priority": 11,
        "actor": "Operator",
        "credential_type": "basic_auth",
        "target": "Administrator user mutation",
        "scope": "—",
        "expected": "deny",
        "test_ref": "tests/integration/test_user_role_authorization.py::test_api_operator_cannot_modify_administrator",
        "reason": "Protects the Administrator role from operator-level tampering.",
    },
    {
        "priority": 12,
        "actor": "Operator",
        "credential_type": "api_key",
        "target": "zone",
        "scope": "operator",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_operator_apikey_bypasses_zone_scope",
        "reason": "Validates legitimate operator access while maintaining the role boundary.",
    },
    {
        "priority": 13,
        "actor": "Admin",
        "credential_type": "api_key",
        "target": "own zone",
        "scope": "admin",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_administrator_apikey_bypasses_zone_scope",
        "reason": "Baseline privileged access for the managing admin role.",
    },
    {
        "priority": 14,
        "actor": "Admin",
        "credential_type": "api_key",
        "target": "other zone",
        "scope": "admin",
        "expected": "allow",
        "test_ref": "tests/integration/api/test_security_exfiltration.py::test_administrator_apikey_bypasses_zone_scope",
        "reason": "Confirms admin scope is not incorrectly constrained to a single tenant or zone.",
    },
]

# Supplemental parameter metadata for matrix-driven test organization.
AUTHORIZATION_MATRIX_CASES = [
    pytest.param(
        {
            "actor": "User",
            "credential_type": "basic_auth",
            "target": "unowned zone",
            "scope": "none",
            "expected": "deny",
            "setup": "user without domain or account grant",
            "action": "zone access request",
        },
        id="user-unowned-zone-deny",
    ),
    pytest.param(
        {
            "actor": "User",
            "credential_type": "basic_auth",
            "target": "unrelated account",
            "scope": "none",
            "expected": "deny",
            "setup": "different account membership",
            "action": "account-scoped access request",
        },
        id="user-unrelated-account-deny",
    ),
    pytest.param(
        {
            "actor": "User",
            "credential_type": "basic_auth",
            "target": "owned zone",
            "scope": "domain ACL",
            "expected": "allow",
            "setup": "explicit domain grant",
            "action": "zone access request",
        },
        id="user-owned-zone-domain-acl-allow",
    ),
    pytest.param(
        {
            "actor": "User",
            "credential_type": "basic_auth",
            "target": "account-owned zone",
            "scope": "account ACL",
            "expected": "allow",
            "setup": "account membership grant",
            "action": "zone access request",
        },
        id="user-account-owned-zone-account-acl-allow",
    ),
    pytest.param(
        {
            "actor": "User API key",
            "credential_type": "api_key",
            "target": "other zone",
            "scope": "domain scope",
            "expected": "deny",
            "setup": "key scoped to different domain",
            "action": "zone access request via API key",
        },
        id="user-apikey-other-zone-domain-scope-deny",
    ),
    pytest.param(
        {
            "actor": "User API key",
            "credential_type": "api_key",
            "target": "permitted zone",
            "scope": "domain scope",
            "expected": "allow",
            "setup": "key scoped to permitted domain",
            "action": "zone access request via API key",
        },
        id="user-apikey-permitted-zone-domain-scope-allow",
    ),
    pytest.param(
        {
            "actor": "User API key",
            "credential_type": "api_key",
            "target": "account zone",
            "scope": "account scope",
            "expected": "allow",
            "setup": "account-scoped API key",
            "action": "account-owned zone access via API key",
        },
        id="user-apikey-account-zone-account-scope-allow",
    ),
    pytest.param(
        {
            "actor": "User",
            "credential_type": "basic_auth",
            "target": "account assignment",
            "scope": "—",
            "expected": "deny",
            "setup": "key assignment mutation attempt",
            "action": "account assignment mutation",
        },
        id="user-basic-auth-account-assignment-deny",
    ),
    pytest.param(
        {
            "actor": "User",
            "credential_type": "basic_auth",
            "target": "Administrator key creation",
            "scope": "—",
            "expected": "deny",
            "setup": "ordinary user key creating admin key",
            "action": "API key creation",
        },
        id="user-basic-auth-create-admin-key-deny",
    ),
    pytest.param(
        {
            "actor": "Operator",
            "credential_type": "basic_auth",
            "target": "Administrator key creation",
            "scope": "—",
            "expected": "deny",
            "setup": "operator key creating admin key",
            "action": "API key creation",
        },
        id="operator-basic-auth-create-admin-key-deny",
    ),
    pytest.param(
        {
            "actor": "Operator",
            "credential_type": "basic_auth",
            "target": "Administrator user mutation",
            "scope": "—",
            "expected": "deny",
            "setup": "operator attempting admin user mutation",
            "action": "user role or profile mutation",
        },
        id="operator-admin-user-mutation-deny",
    ),
    pytest.param(
        {
            "actor": "Operator",
            "credential_type": "api_key",
            "target": "zone",
            "scope": "operator",
            "expected": "allow",
            "setup": "operator access to supported zone",
            "action": "zone access request",
        },
        id="operator-zone-allow",
    ),
    pytest.param(
        {
            "actor": "Admin",
            "credential_type": "api_key",
            "target": "own zone",
            "scope": "admin",
            "expected": "allow",
            "setup": "admin access to self-managed zone",
            "action": "zone access request",
        },
        id="admin-own-zone-allow",
    ),
    pytest.param(
        {
            "actor": "Admin",
            "credential_type": "api_key",
            "target": "other zone",
            "scope": "admin",
            "expected": "allow",
            "setup": "admin access to another zone",
            "action": "zone access request",
        },
        id="admin-other-zone-allow",
    ),
]


@pytest.mark.parametrize(
    "matrix_case",
    AUTHORIZATION_MATRIX,
    ids=lambda case: "matrix-{}".format(case["priority"]),
)
def test_authorization_matrix_rows_have_valid_test_references(matrix_case):
    assert matrix_case["credential_type"] in {"basic_auth", "api_key"}
    assert matrix_case["expected"] in {"allow", "deny"}

    test_path, test_name = matrix_case["test_ref"].split("::", 1)
    repository_root = Path(__file__).resolve().parents[2]
    source_path = repository_root / test_path

    assert source_path.is_file(), matrix_case["test_ref"]
    assert "def {}(".format(test_name) in source_path.read_text()

__all__ = ["AUTHORIZATION_MATRIX", "AUTHORIZATION_MATRIX_CASES"]
