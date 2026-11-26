#!/usr/bin/env python3
"""Permission checks for the code factory, run by scripts/test-factory.sh (perm section).

    python3 -I scripts/test-factory-perm.py <repo root> [<directory with resolved agent rules>]

A small last-match-wins evaluator over opencode.json, the generated OpenCode agent overlays and,
when a directory is given, the rules `opencode` resolved for each agent (one JSON file per agent,
a list of {permission, pattern, action}). Claude Code's settings are checked with a matcher where
deny wins over ask over allow. In both tools a trailing " *" in a pattern is optional, so the bare
command "git status" matches "git status *". Prints one PASS, FAIL or SKIP line per check.
"""

import json
import re
import sys

repo = sys.argv[1]
agent_json_dir = sys.argv[2] if len(sys.argv) > 2 else ""
results = []


def check(desc, cond):
    results.append(("PASS " if cond else "FAIL ") + desc)


def rx(pat):
    optional = pat.endswith(" *")
    if optional:
        pat = pat[:-2]
    body = "".join(".*" if c == "*" else re.escape(c) for c in pat)
    if optional:
        body += "(?: .*)?"
    return re.compile(body, re.S)


def matches(pat, text):
    return rx(pat).fullmatch(text) is not None


def flatten(perm):
    rules = []
    for tool, value in perm.items():
        if isinstance(value, str):
            rules.append((tool, "*", value))
        else:
            for pat, act in value.items():
                rules.append((tool, pat, act))
    return rules


def decide(rules, tool, text):
    action = "ask"
    for t, pat, act in rules:
        if t == tool and matches(pat, text):
            action = act
    return action


def overlay(path):
    """Rules from the block-style frontmatter the generator writes."""
    rules, tool, in_perm = [], None, False
    with open(path) as f:
        lines = f.read().split("\n")
    for line in lines[1:]:
        if line == "---":
            break
        if line == "permission:":
            in_perm = True
        elif in_perm and re.fullmatch(r"  (edit|bash):", line):
            tool = line.strip()[:-1]
        elif in_perm and tool:
            m = re.fullmatch(r'    "(.*)": "(allow|ask|deny)"', line)
            if m:
                rules.append((tool, m.group(1), m.group(2)))
    return rules


def claude_decide(cfg, text):
    perms = cfg["permissions"]

    def hit(key):
        for entry in perms.get(key, []):
            m = re.fullmatch(r"Bash\((.*)\)", entry)
            if m and matches(m.group(1), text):
                return True
        return False

    if hit("deny"):
        return "deny"
    if hit("ask"):
        return "ask"
    return "allow" if hit("allow") else "none"


with open(repo + "/opencode.json") as f:
    oc = json.load(f)
with open(repo + "/.claude/settings.json") as f:
    cc = json.load(f)
global_rules = flatten(oc["permission"])

denied = [
    "gh pr merge 1", "gh api repos/x", "git config user.name x", "bash -c true", "sh -c true",
    "env x", "curl http://x", "wget http://x", "sudo true", "git commit --no-verify -m x",
    "git commit -n -m x", "git commit -m x -n", "git push origin main", "git push --force origin x",
    "git push --no-verify origin x", "git -c a=b status", "git -C . status", "rm -rf x", "python3 x",
    "git commit --no-ver -m x", "git push origin HEAD:refs/heads/main",
    "git diff --output=x", "git log --output=x", "git show HEAD --output=x",
]
for cmd in denied:
    check("opencode denies: " + cmd, decide(global_rules, "bash", cmd) == "deny")
    check("claude denies: " + cmd, claude_decide(cc, cmd) == "deny")

def read_list(name):
    with open(repo + "/docs/factory/meta/claude-allow-" + name + ".txt") as f:
        return [line.strip() for line in f if line.strip()]


def list_decide(entries, text):
    """allow when an entry of a grant list matches, then the deny list of the settings still wins."""
    cfg = {"permissions": {"allow": entries, "ask": cc["permissions"].get("ask", []), "deny": cc["permissions"]["deny"]}}
    return claude_decide(cfg, text)


# Commands every role may run: read-only inspection, cargo and the repository scripts.
common = [
    "cargo test", "scripts/gate.sh --commit", "ls x", "rg x", "grep x y", "wc -l x", "diff a b",
    "git status", "git diff", "git log", "git show HEAD", "git write-tree",
]
# Commands that change the tree: the implementer only (OpenCode: not the readonly overlays).
code_only = ["git add x", "git commit -m x", "git rm x", "git mv a b", "git restore x", "mkdir x", "chmod +x x"]
# Commands only the driver, or the interactive command, may run.
orchestrator_only = ["git fetch origin main", "git switch -c factory/x", "gh pr view 1", "gh pr create --title x"]
for cmd in common + code_only:
    check("opencode allows: " + cmd, decide(global_rules, "bash", cmd) == "allow")
for cmd in common:
    check("claude settings allow: " + cmd, claude_decide(cc, cmd) == "allow")
for cmd in code_only + orchestrator_only:
    check("claude settings do not allow: " + cmd, claude_decide(cc, cmd) != "allow")
for cmd in code_only:
    check("claude code grant allows: " + cmd, list_decide(read_list("common") + read_list("code"), cmd) == "allow")
for cmd in orchestrator_only:
    check("claude code grant does not allow: " + cmd, list_decide(read_list("common") + read_list("code"), cmd) != "allow")
    check("claude orchestrator grant allows: " + cmd, list_decide(read_list("common") + read_list("code") + read_list("orchestrator"), cmd) == "allow")
    check("opencode does not allow: " + cmd, decide(global_rules, "bash", cmd) != "allow")
for cmd in code_only:
    check("claude readonly grant does not allow: " + cmd, list_decide(read_list("common"), cmd) != "allow")
for cmd in ["cat x", "rm x", "find ."]:
    check("opencode does not allow: " + cmd, decide(global_rules, "bash", cmd) != "allow")
    check("claude does not allow: " + cmd, claude_decide(cc, cmd) != "allow")
check("claude asks before a push", claude_decide(cc, "git push origin factory/x") == "ask")
check("opencode never offers a push", decide(global_rules, "bash", "git push origin factory/x") == "deny")

allow_src = read_list("common") + read_list("code") + read_list("orchestrator")
check("claude settings allow list equals the common grant", cc["permissions"]["allow"] == read_list("common"))
check("no push or pull request creation in the common or code grants", not any(("push" in e or "pr create" in e) for e in read_list("common") + read_list("code")))
with open(repo + "/.claude/commands/factory.md") as f:
    command = f.read()
m = re.search(r'^allowed-tools: "(.*)"$', command, re.M)
check("the command pre-approves exactly the allow list", bool(m) and m.group(1) == " ".join(allow_src))
check(
    "no Edit or Write rule in the committed allow list",
    not any(e.startswith(("Edit", "Write")) for e in cc["permissions"]["allow"]),
)
check(
    "no bypass mode is configured",
    "bypass" not in json.dumps(cc).lower() and "bypass" not in json.dumps(oc).lower(),
)


def agent_checks(label, rules, readonly):
    check(label + " git status allowed", decide(rules, "bash", "git status") == "allow")
    check(label + " git diff allowed", decide(rules, "bash", "git diff HEAD~1") == "allow")
    check(label + " rg allowed", decide(rules, "bash", "rg pattern src") == "allow")
    check(label + " grep allowed", decide(rules, "bash", "grep -n x y") == "allow")
    check(label + " git push main denied", decide(rules, "bash", "git push origin main") == "deny")
    check(label + " git push to a factory branch denied", decide(rules, "bash", "git push origin factory/x") == "deny")
    check(label + " gh pr merge denied", decide(rules, "bash", "gh pr merge 1") == "deny")
    check(label + " no-verify commit denied", decide(rules, "bash", "git commit --no-verify -m x") == "deny")
    if readonly:
        check(
            label + " run directory artifact editable",
            decide(rules, "edit", ".factory/runs/x/review-plan-1.md") == "allow",
        )
        check(label + " source file not editable", decide(rules, "edit", "crates/a/src/lib.rs") == "deny")
        check(label + " git commit denied", decide(rules, "bash", "git commit -m x") == "deny")
        check(label + " git add denied", decide(rules, "bash", "git add x") == "deny")
        check(label + " git fetch denied", decide(rules, "bash", "git fetch origin main") == "deny")
        check(label + " mkdir denied", decide(rules, "bash", "mkdir x") == "deny")
        check(label + " chmod denied", decide(rules, "bash", "chmod +x x") == "deny")
    else:
        check(label + " source file editable", decide(rules, "edit", "crates/a/src/lib.rs") == "allow")
        check(label + " git commit allowed", decide(rules, "bash", "git commit -m x") == "allow")


roles = {
    "factory-planner": True,
    "factory-plan-reviewer": True,
    "factory-code-reviewer": True,
    "factory-pr-writer": True,
    "factory-implementer": False,
}
for name, readonly in roles.items():
    rules = global_rules + overlay(repo + "/.opencode/agents/" + name + ".md")
    agent_checks("generated " + name + ":", rules, readonly)
    if agent_json_dir:
        path = agent_json_dir + "/" + name + ".json"
        try:
            with open(path) as f:
                data = json.load(f)
            raw = data if isinstance(data, list) else data.get("permission")
            resolved = [(r["permission"], r["pattern"], r["action"]) for r in raw]
        except Exception:
            results.append("SKIP resolved rules of " + name + ": unrecognised output shape")
            continue
        agent_checks("resolved " + name + ":", resolved, readonly)

print("\n".join(results))
