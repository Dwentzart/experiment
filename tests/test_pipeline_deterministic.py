"""Regression tests for the deterministic layer of pipeline_final.py.

Every test asserts the CORRECT behaviour for a bug that was found by an
audit and then fixed; each one fails on the pre-fix code.

Requirements: the same imports as the pipeline itself (crewai, pydantic).
Run from the repository root:

    python3 tests/test_pipeline_deterministic.py

Exit code 0 = all checks passed. No forge binary, no network and no LLM
call is required: everything here is pure Python.
"""
import json
import os
import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

try:
    import pipeline_final as P
except ImportError as exc:  # pragma: no cover - dependency gate
    print(
        "SKIP: cannot import pipeline_final "
        f"({exc}). Install the pipeline dependencies "
        "(pip install crewai pydantic) and run this file from the "
        "repository root."
    )
    raise SystemExit(2)

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not condition else ""))

# ---------------------------------------------------------------- A1/A2
SRC = "\n".join(f"line{i}" for i in range(400)) + "\n"

def test_diff_gap():
    diff = (
        "--- a/C.sol\n+++ b/C.sol\n"
        "@@ -1,1 +1,1 @@\n-line0\n+line0_fixed\n"
        "@@ -301,1 +301,1 @@\n-line300\n+line300_fixed\n"
    )
    try:
        out = P.apply_unified_diff(SRC, diff)
        ok = "line0_fixed" in out["patched"] and "line300_fixed" in out["patched"]
        check("A1 far-apart hunks apply", ok)
    except P.PatchApplyError as exc:
        check("A1 far-apart hunks apply", False, f"raised {exc}")


def test_diff_out_of_order():
    diff = (
        "--- a/C.sol\n+++ b/C.sol\n"
        "@@ -6,1 +6,1 @@\n-line5\n+line5_fixed\n"
        "@@ -2,1 +2,1 @@\n-line1\n+line1_fixed\n"
    )
    try:
        out = P.apply_unified_diff(SRC[:120], diff)
        check("A2 out-of-order hunk rejected", False, f"silently produced {out['patched']!r}")
    except P.PatchApplyError as exc:
        check("A2 out-of-order hunk rejected", "out of order" in str(exc), str(exc))


def test_diff_normal_and_drift():
    src = "\n".join(f"line{i}" for i in range(10)) + "\n"
    good = "--- a/C.sol\n+++ b/C.sol\n@@ -3,1 +3,1 @@\n-line2\n+line2_fixed\n"
    out = P.apply_unified_diff(src, good)
    check("A3 normal single hunk", "line2_fixed" in out["patched"] and out["patched"].count("line7") == 1)
    drift = "--- a/C.sol\n+++ b/C.sol\n@@ -9,1 +9,1 @@\n-line2\n+line2_fixed\n"
    out = P.apply_unified_diff(src, drift)
    check("A4 declared offset drift tolerated", "line2_fixed" in out["patched"])
    missing = "--- a/C.sol\n+++ b/C.sol\n@@ -3,1 +3,1 @@\n-nonexistent_line\n+x\n"
    try:
        P.apply_unified_diff(src, missing)
        check("A5 absent context raises", False, "no error")
    except P.PatchApplyError:
        check("A5 absent context raises", True)


# ---------------------------------------------------------------- B
GATE_NARRATIVE = """
## Findings
attacker_type: unprivileged
Observed result: [PASS]
user funds were drained
Severity: High
"""


def test_gate_fail_closed_without_block():
    res = P.BountyEligibilityGate.evaluate(
        {"severity": ["high"]},
        GATE_NARRATIVE,
        verdicts={},
        authz_map={"HYP-001": {"has_authz_boundary": True}},
        role_grants={},
        patch_map={"HYP-001": "PATCH_NO_EFFECT"},
    )
    check(
        "B1 no structured block -> NON_REPORTABLE",
        res["decision"] == "NON_REPORTABLE" and not res["eligible"],
        f"decision={res['decision']} codes={res['reason_codes']}",
    )
    check(
        "B2 reason code names the missing block",
        any("GATING" in c or "DETERMINISTIC" in c for c in res["reason_codes"]),
        str(res["reason_codes"]),
    )


def test_gate_structured_still_works():
    good = json.dumps({"findings": [{
        "hypothesis_id": "HYP-001", "reportable": True,
        "attacker_type": "unprivileged", "poc_validated": True,
        "integrity_ok": True, "impact_type": "fund_loss",
        "severity": "high",
    }], "overall_decision": "REPORTABLE"})
    res = P.BountyEligibilityGate.evaluate(
        {"severity": ["high"]},
        f"text\n```json:bounty-gating\n{good}\n```\n",
        verdicts={"HYP-001": "BUG_VALIDATED"},
        authz_map={}, role_grants={},
        patch_map={"HYP-001": "PATCH_CONFIRMED"},
    )
    check("B3 structured path still REPORTABLE", res["decision"] == "REPORTABLE", str(res))


# ---------------------------------------------------------------- C
AUG = (
    'report\n```json:judge-verdicts\n[{"hypothesis_id":"HYP-001","verdict":"BUG_VALIDATED"}]\n```\n'
    '\n\n--- 11_reporter.log ---\nreporter text\n'
    '\n\n--- 08_judge.log ---\n'
    '```json:judge-verdicts\n[{"hypothesis_id":"HYP-001","verdict":"NOT_A_BUG"}]\n```\n'
)


def test_judge_verdict_authority():
    v = P.parse_judge_verdicts(AUG)
    check("C1 judge log wins over reporter claim", v.get("HYP-001") == "NOT_A_BUG", str(v))


# ---------------------------------------------------------------- D
class _FakeServices:
    test_bindings = {}

    class evidence:
        root = "/tmp/definitely-not-here"


def test_reconcile_missing_block():
    recon = P.reconcile_findings(_FakeServices(), "no gating block")
    check("D1 missing gating block fails reconciliation", recon["clean"] is False, str(recon))


# ---------------------------------------------------------------- E
PSEUDO_BASE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
contract XTest is Test {
  function test_inv() public {
    uint256 a = 100;
    uint256 b = 250;
    uint256 c = a + b;
    assertEq(c, 350);
  }
}
'''


def test_pseudo_comment_bypass():
    with_comment = PSEUDO_BASE.replace("  function test_inv", "  // real target: new Vault();\n  function test_inv")
    res = P.PseudoTestValidator.validate(with_comment)
    check("E1 deployment in a comment does not count", res["valid"] is False, str(res))
    res2 = P.PseudoTestValidator.validate(PSEUDO_BASE)
    check("E2 plain pseudo-test still rejected", res2["valid"] is False)


def test_pseudo_real_test_still_accepted():
    real = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
contract Vault { function total() public pure returns (uint256) { return 1; } }
contract VaultTest is Test {
  function test_total() public {
    Vault v = new Vault();
    assertEq(v.total(), 1);
  }
}
'''
    check("E3 real deploying test accepted", P.PseudoTestValidator.validate(real)["valid"] is True)


# ---------------------------------------------------------------- F
WRITE_CONTENT = PSEUDO_BASE


def test_writer_symlink_escape():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        proj = tmp / "proj"
        (proj / "src").mkdir(parents=True)
        (proj / "test").mkdir()
        os.symlink(proj / "src", proj / "test" / "security_pipeline")
        writer = P.TestFileWriter(root=proj, project=proj, max_bytes=100000)
        res = writer.write("test/security_pipeline/evil.t.sol", WRITE_CONTENT)
        landed = sorted(p.name for p in (proj / "src").iterdir())
        check(
            "F1 symlinked sandbox dir refuses the write",
            res.get("success") is False and not landed,
            f"result={res.get('result_type')} src={landed}",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_writer_normal_write():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        proj = tmp / "proj"
        (proj / "test").mkdir(parents=True)
        writer = P.TestFileWriter(root=proj, project=proj, max_bytes=100000)
        res = writer.write("test/security_pipeline/ok.t.sol", WRITE_CONTENT)
        check(
            "F2 normal write still succeeds",
            res.get("success") is True
            and (proj / "test" / "security_pipeline" / "ok.t.sol").is_file(),
            str(res),
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- G


def test_focus_does_not_expand_scope():
    enf = P.BountyScopeEnforcer(spec={"scope": {"contracts": ["Vault"]}})
    enf.focus_contracts(["Vault", "OutOfScopeTarget"])
    check("G1 focus cannot widen a bounty whitelist", enf.is_in_scope("OutOfScopeTarget") is False)
    check("G2 focus keeps in-scope contract", enf.is_in_scope("Vault") is True)
    enf2 = P.BountyScopeEnforcer(spec=None)
    enf2.focus_contracts(["OnlyThis"])
    check("G3 focus alone restricts when no spec", enf2.is_in_scope("OnlyThis") and not enf2.is_in_scope("Other"))


# ---------------------------------------------------------------- H


def test_budget_refund():
    b = P.ValidationBudget(4, 2, 1, 1, 2)
    err = b.consume_write()
    check("H1 consume_write succeeds while budget remains", err is None)
    b.refund_write()
    check("H2 refund_write restores the budget", b.writes_used == 0 and b.snapshot()["writes_remaining"] == 2)


# ---------------------------------------------------------------- I (batch 2)


def test_idiom_whitespace():
    for spelling in (
        "require(msg.sender == owner);",
        "require(msg.sender==owner);",
        "require(msg.sender  ==  owner);",
    ):
        masked = P._mask_comments_and_strings(spelling)
        check(
            f"I1 authz idiom matches {spelling!r}",
            P._idiom_matches("msg.sender ==", masked),
        )
    for spelling in ("require(tx.origin==owner);", "require(tx.origin == owner);"):
        masked = P._mask_comments_and_strings(spelling)
        check(f"I2 tx.origin idiom matches {spelling!r}", P._idiom_matches("tx.origin ==", masked))
    # word-boundary semantics must be preserved
    check("I3 'authority' does not match 'authorityFee'", not P._idiom_matches("authority", "authorityFee"))
    check("I4 'authority' matches bare use", P._idiom_matches("authority", "authority.call("))


def test_redos_probe():
    for pattern in ("(a+)+$", "(a|b)*c", "(a{1,})+$", "(a{2,})*", "(a{1,}){2,}"):
        check(f"I5 ReDoS probe flags {pattern!r}", P._looks_catastrophic(pattern))
    for pattern in ("^foo(bar)+$", "msg\\.sender\\s*==", "(abc)", "a{1,3}"):
        check(f"I6 ReDoS probe allows {pattern!r}", not P._looks_catastrophic(pattern))


def test_pseudo_report_fences():
    body = "uint256 a = 1;\nassertEq(a, 1);"
    for fence in ("```", "```solidity", "```Sol", "```solidity ", "```solidity\r"):
        text = f"{fence}\n{body}\n```\n"
        found = P.audit_pseudo_in_report(text)
        check(f"I7 pseudo block audited under fence {fence!r}", len(found) == 1, str(found))


def test_role_grant_comment_bypass():
    comment_bypass = "// no expectRevert needed\ntarget.grantRole(ADMIN_ROLE, attacker);"
    check("I8 comment cannot suppress a real role grant", bool(P.detect_role_grant_to_attacker(comment_bypass)))
    real_negative = "vm.expectRevert();\ntarget.grantRole(ADMIN_ROLE, attacker);"
    check("I9 a real expectRevert still suppresses", not P.detect_role_grant_to_attacker(real_negative))
    bare = "target.grantRole(ADMIN_ROLE, attacker);"
    check("I10 bare grant still detected", bool(P.detect_role_grant_to_attacker(bare)))


def test_slither_failure():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        prepass = P.StaticAnalysisPrepass(tmp, tmp)
        prepass.slither = "/usr/bin/true"
        prepass._run_tool = lambda *a, **k: json.dumps({
            "success": False, "error": "compilation failed", "results": None,
        })
        findings, err = prepass._run_slither()
        check("I11 slither failure surfaced as an error", bool(err) and not findings, f"err={err} findings={findings}")
        prepass._run_tool = lambda *a, **k: json.dumps({"success": True, "results": {"detectors": []}})
        findings, err = prepass._run_slither()
        check("I12 clean slither run stays clean", err is None and findings == [], f"err={err}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_fs_permissions():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        proj = tmp / "proj"
        (proj / "data").mkdir(parents=True)
        def audit(toml):
            (proj / "foundry.toml").write_text(toml)
            return P.FoundryConfigAudit.audit(proj)
        res = audit('[profile.default]\nfs_permissions = [{ access = "write", path = "./data" }]\n')
        check("I13 fs_permissions write refused", res["safe_to_execute"] is False, str(res["errors"]))
        res = audit('[profile.default]\nfs_permissions = [{ access = "read-write", path = "./data" }]\n')
        check("I14 fs_permissions read-write refused", res["safe_to_execute"] is False)
        res = audit('[profile.default]\nfs_permissions = [{ access = "read", path = "./data" }]\n')
        check("I15 fs_permissions read inside project allowed", res["safe_to_execute"] is True, str(res["errors"]))
        res = audit('[profile.default]\nfs_permissions = [{ access = "read", path = "/" }]\n')
        check("I16 fs_permissions read on / refused", res["safe_to_execute"] is False)
        res = audit('[profile.default]\nsrc = "src"\n')
        check("I17 clean foundry.toml passes", res["safe_to_execute"] is True, str(res["errors"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- J (batch 3)


def test_out_of_order_duplicate():
    src = "X\nA\nB\nC\nY\nA\nB\nC\nZ\nA\nB\nC\nW\n"
    diff = (
        "--- a/C.sol\n+++ b/C.sol\n"
        "@@ -5,3 +5,3 @@\n A\n-B\n+Q\n C\n"
        "@@ -1,3 +1,3 @@\n A\n-B\n+R\n C\n"
    )
    try:
        out = P.apply_unified_diff(src, diff)
        check(
            "J1 out-of-order hunk with later duplicate rejected",
            False,
            f"applied: {out['patched']!r}",
        )
    except P.PatchApplyError as exc:
        check(
            "J1 out-of-order hunk with later duplicate rejected",
            "out of order" in str(exc),
            str(exc),
        )


def test_fence_lines_in_hunk():
    src = "a\nflag\nb\n"
    diff = (
        "--- a/C.sol\n+++ b/C.sol\n"
        "@@ -1,3 +1,4 @@\n a\n+ ++ flag\n flag\n b\n"
    )
    try:
        out = P.apply_unified_diff(src, diff)
        check(
            "J2 added line starting with '++ ' applies",
            " ++ flag" in out["patched"],
            repr(out["patched"]),
        )
    except P.PatchApplyError as exc:
        check("J2 added line starting with '++ ' applies", False, str(exc))

    src2 = "a\n-- flag\nb\n"
    diff2 = (
        "--- a/C.sol\n+++ b/C.sol\n"
        "@@ -1,3 +1,2 @@\n a\n--- flag\n b\n"
    )
    try:
        out = P.apply_unified_diff(src2, diff2)
        check(
            "J3 removed line starting with '-- ' applies",
            out["patched"] == "a\nb\n",
            repr(out["patched"]),
        )
    except P.PatchApplyError as exc:
        check("J3 removed line starting with '-- ' applies", False, str(exc))


def test_no_newline_marker():
    src = "a\nb\nc\n"
    diff = (
        "--- a/C.sol\n+++ b/C.sol\n"
        "@@ -1,3 +1,3 @@\n a\n b\n-c\n\\ No newline at end of file\n"
        "+C\n\\ No newline at end of file\n"
    )
    try:
        out = P.apply_unified_diff(src, diff)
        check(
            "J4 trailing-newline removal honoured",
            out["patched"] == "a\nb\nC",
            repr(out["patched"]),
        )
    except P.PatchApplyError as exc:
        check("J4 trailing-newline removal honoured", False, str(exc))


def test_mutation_targets_real_assertion():
    comment_first = (
        "function t() public {\n"
        "  // sanity: assertEq(a, b)\n"
        "  assertEq(token.balanceOf(x), y);\n}"
    )
    mut = P.MutationTester._mutate_assert_eq_neutralized(comment_first)
    check(
        "J5a mutation ignores a comment mention",
        "assertEq(a, b)" in mut
        and "balanceOf(x),token.balanceOf(x)" in mut.replace(" ", ""),
        mut,
    )
    string_first = (
        "function t() public {\n"
        "  string memory s = \"assertEq(x, y)\";\n"
        "  assertEq(token.balanceOf(x), y);\n}"
    )
    mut = P.MutationTester._mutate_assert_eq_neutralized(string_first)
    check(
        "J5b mutation ignores a string mention",
        "\"assertEq(x, y)\"" in mut
        and "balanceOf(x),token.balanceOf(x)" in mut.replace(" ", ""),
        mut,
    )
    apostrophe = (
        "function t() public {\n"
        "  assertEq(a, b); // don't touch\n"
        "  assertEq(c, d);\n}"
    )
    mut = P.MutationTester._mutate_assert_eq_neutralized(apostrophe)
    check(
        "J5c apostrophe in a comment is not a string",
        mut != apostrophe and "assertEq(a,a)" in mut.replace(" ", ""),
        mut,
    )


def test_exploit_poc_validator():
    bypass = "\n".join([
        "function t() public {",
        "  uint256 spread = token.balanceOf(attacker);",
        "  uint256 spending = token.balanceOf(attacker);",
        "  assertTrue(noProfitPossible);",
        "  Attacker a = new Attacker(address(target));",
        "}",
    ])
    check(
        "J6a non-quantifying PoC rejected",
        P.ExploitPoCValidator.validate(bypass)["valid"] is False,
    )
    good = "\n".join([
        "function t() public {",
        "  vm.prank(attacker);",
        "  uint256 attackerBefore = token.balanceOf(attacker);",
        "  new Attacker(address(target)).attack();",
        "  uint256 attackerAfter = token.balanceOf(attacker);",
        "  assertGt(attackerAfter - attackerBefore, 0);",
        "}",
    ])
    res = P.ExploitPoCValidator.validate(good)
    check("J6b recommended PoC form accepted", res["valid"] is True, str(res["problems"]))

TEST_CONTENT = "\n".join([
    "// SPDX-License-Identifier: MIT",
    "pragma solidity ^0.8.20;",
    'import {Test} from "forge-std/Test.sol";',
    "contract VaultTest is Test {",
    "  function test_withdraw() public {",
    "    Vault v = new Vault();",
    "    v.withdraw(1);",
    "    assertEq(v.total(), 0);",
    "  }",
    "}",
]) + "\n"


def make_project(spec=None, with_symlink=False):
    tmp = pathlib.Path(tempfile.mkdtemp())
    proj = tmp / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "test").mkdir()
    (proj / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n')
    (proj / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "  function withdraw(uint256 amount) public {}\n"
        "  function total() public pure returns (uint256) { return 0; }\n"
        "}\n"
    )
    if with_symlink:
        os.symlink(proj / "src" / "Vault.sol", proj / "src" / "Linked.sol")
    spec_path = None
    if spec is not None:
        spec_path = tmp / "bounty.json"
        spec_path.write_text(json.dumps(spec))
    cfg = P.PipelineConfig(
        repo_url="https://example.invalid/repo",
        authorized_root=str(proj),
        project_dir=str(proj),
        bounty_spec_file=str(spec_path) if spec_path else None,
    )
    return tmp, proj, P.SecurityAnalysisServices(cfg)


def test_known_issue_requires_property():
    tmp, proj, svc = make_project(spec={
        "scope": {"contracts": ["Vault"]},
        "known_issues": ["rounding dust in share accounting"],
    })
    try:
        out = json.loads(svc.write_test(
            "HYP-001", "test/security_pipeline/a.t.sol", TEST_CONTENT,
            property_text="", test_name="test_a",
            target_contract="Vault", target_function="withdraw",
        ))
        check("K1 missing property_text refused when known issues exist",
              out["result_type"] == "PROPERTY_TEXT_REQUIRED", str(out.get("result_type")))
        out = json.loads(svc.write_test(
            "HYP-001", "test/security_pipeline/a.t.sol", TEST_CONTENT,
            property_text="withdraw can drain the vault", test_name="test_a",
            target_contract="Vault", target_function="withdraw",
        ))
        check("K2 write succeeds with property_text", out.get("success") is True, str(out))
        check("H1 successful write consumes one write slot",
              svc.budget.writes_used == 1, str(svc.budget.snapshot()))

        # second hypothesis, same path -> writer refuses (no overwrite)
        out = json.loads(svc.write_test(
            "HYP-002", "test/security_pipeline/a.t.sol", TEST_CONTENT,
            property_text="a different property entirely", test_name="test_b",
            target_contract="Vault", target_function="total",
        ))
        check("H2 refused write reports failure", out.get("success") is False, str(out))
        check("H3 refused write does not burn the budget",
              svc.budget.writes_used == 1, str(svc.budget.snapshot()))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scope_and_focus():
    tmp, proj, svc = make_project(spec={"scope": {"contracts": ["Vault"]}})
    try:
        out = json.loads(svc.write_test(
            "HYP-001", "test/security_pipeline/b.t.sol", TEST_CONTENT,
            property_text="x y z", test_name="test_b",
            target_contract="Vault", target_function="withdraw",
        ))
        check("G4 in-scope contract accepted", out.get("success") is True, str(out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_snapshot_marks_skipped():
    tmp, proj, _ = make_project(with_symlink=True)
    try:
        snap = P.WorkspaceIntegrity.snapshot(proj)
        check("J7 symlinked source marks the snapshot incomplete",
              snap.get("__skipped__") == "1", str(sorted(snap)))
        lock = P.ReproducibilityLock.collect(proj, None)
        check("J8 reproducibility lock records incompleteness",
              lock.get("audited_tree_incomplete") is True, str(lock.get("audited_tree_incomplete")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    tmp, proj, _ = make_project()
    try:
        snap = P.WorkspaceIntegrity.snapshot(proj)
        check("J9 clean project snapshot has no marker",
              "__skipped__" not in snap and "__truncated__" not in snap,
              str(sorted(snap)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_evidence_failure_recorded():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        ev_root = tmp / "ev"
        ev_root.mkdir()
        outside = tmp / "outside"
        outside.mkdir()
        os.symlink(outside, ev_root / "artifacts")
        store = P.EvidenceStore(ev_root, enabled=True)
        import warnings as _w
        with _w.catch_warnings(record=True) as caught:
            _w.simplefilter("always")
            result = store.write_hypothesis_json("HYP-001", "x.json", {"a": 1})
        check("I1 failed evidence write returns None", result is None)
        check("I2 failed evidence write is recorded", len(store.failures) >= 1, str(store.failures))
        check("I3 failed evidence write warns", len(caught) >= 1, str(caught))
        check("I4 nothing written outside the sandbox", list(outside.iterdir()) == [], str(list(outside.iterdir())))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def main():
    for fn in (
        test_diff_gap,
        test_diff_out_of_order,
        test_diff_normal_and_drift,
        test_gate_fail_closed_without_block,
        test_gate_structured_still_works,
        test_judge_verdict_authority,
        test_reconcile_missing_block,
        test_pseudo_comment_bypass,
        test_pseudo_real_test_still_accepted,
        test_writer_symlink_escape,
        test_writer_normal_write,
        test_focus_does_not_expand_scope,
        test_budget_refund,
        test_idiom_whitespace,
        test_redos_probe,
        test_pseudo_report_fences,
        test_role_grant_comment_bypass,
        test_slither_failure,
        test_fs_permissions,
        test_out_of_order_duplicate,
        test_fence_lines_in_hunk,
        test_no_newline_marker,
        test_mutation_targets_real_assertion,
        test_exploit_poc_validator,
        test_known_issue_requires_property,
        test_scope_and_focus,
        test_snapshot_marks_skipped,
        test_evidence_failure_recorded,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, f"EXCEPTION {type(exc).__name__}: {exc}")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
