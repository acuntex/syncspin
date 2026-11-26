#!/usr/bin/env python3
"""Permission checks for the code factory, run by scripts/test-factory.sh (perm section).

    python3 -I scripts/test-factory-perm.py <repo root> [<directory with resolved agent rules>]

A small last-match-wins evaluator over opencode.json, the generated OpenCode agent overlays and,
when a directory is given, the rules `opencode` resolved for each agent (one JSON file per agent,
a list of {permission, pattern, action}). The OpenCode 2.x shape (an ordered list of
{action, resource, effect}, where `bash` is `shell`) is evaluated by the same tests over the same
deny and allow lists. Claude Code's settings and the per-phase grants plus the
driver's deny list are checked with a matcher where deny wins over ask over allow. The
project-level files must hold only the AGENTS.md denies; every other restriction is checked in the
factory layer. In both tools a trailing " *" in a pattern is optional, so the bare
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


def to_v2(rules):
    """The 2.x shape: an ordered list of action/resource/effect entries; `bash` becomes `shell`."""
    return [
        {"action": "shell" if tool == "bash" else tool, "resource": pattern, "effect": action}
        for tool, pattern, action in rules
    ]


def decide_v2(rules, tool, text):
    """Last matching entry wins, over the ordered 2.x permissions list."""
    action = "shell" if tool == "bash" else tool
    effect = "ask"
    for entry in rules:
        if entry["action"] == action and matches(entry["resource"], text):
            effect = entry["effect"]
    return effect


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


def read_list(name):
    with open(repo + "/docs/factory/meta/claude-allow-" + name + ".txt") as f:
        return [line.strip() for line in f if line.strip()]


def read_deny(name):
    with open(repo + "/docs/factory/meta/deny-" + name + ".txt") as f:
        return [line.strip() for line in f if line.strip()]


deny_project = read_deny("project")
deny_factory = read_deny("factory")

# The project-level files hold only what AGENTS.md states for every agent. Everything else that
# restricts the factory lives in the factory layer (the generated agents, the driver's per-phase flags).
bash_map = oc["permission"].get("bash", {})
check("opencode.json: the bash map has no \"*\" key", "*" not in bash_map)
check("opencode.json: every bash rule is a deny", all(v == "deny" for v in bash_map.values()))
check("opencode.json: no edit permission", "edit" not in oc["permission"])
check("opencode.json: no external_directory permission", "external_directory" not in oc["permission"])
check("opencode.json: only the bash permission is set", list(oc["permission"].keys()) == ["bash"])
check("opencode.json: the deny list equals deny-project.txt", list(bash_map.keys()) == deny_project)
check("claude settings: only a deny list", list(cc["permissions"].keys()) == ["deny"])
check(
    "claude settings: the deny list equals deny-project.txt",
    cc["permissions"]["deny"] == ["Bash(" + p + ")" for p in deny_project],
)
check("claude settings: no top-level key besides permissions", list(cc.keys()) == ["permissions"])

# What AGENTS.md states for every agent: denied by the project files themselves, in both tools.
denied_project = [
    "gh pr merge 1", "gh pr merge 1 --auto", "gh pr edit 1 --auto-merge", "git push origin main",
    "git push --force origin x", "git push --no-verify origin x", "git push origin HEAD:refs/heads/main",
    "git commit --no-verify -m x", "git commit -n -m x", "git commit -m x -n", "git commit --no-ver -m x",
]
for cmd in denied_project:
    check("project opencode denies: " + cmd, decide(global_rules, "bash", cmd) == "deny")
    check("project claude denies: " + cmd, claude_decide(cc, cmd) == "deny")

# What only the factory restricts: not denied by the project files, so an interactive session is free.
denied_factory = [
    "gh api repos/x", "git config user.name x", "bash -c true", "sh -c true", "env x", "curl http://x",
    "wget http://x", "sudo true", "git -c a=b status", "git -C . status", "rm -rf x", "python3 x",
    "git diff --output=x", "git log --output=x", "git show HEAD --output=x", "git push origin factory/x",
    "git reset --hard x", "gh repo view", "gh workflow run x", "gh release list", "gh auth status",
    "find . -exec rm {} ;", "find . -name x -exec rm {} +", "find . -execdir rm {} ;", "find . -delete",
    "find . -ok rm {} ;", "find . -fprint out", "git branch -D x", "git branch -d x", "git branch -m a b",
    "git branch -M a b", "git branch -c a b", "git branch -C a b", "git branch --delete x",
    "git branch --move a b", "git branch --copy a b", "git branch --set-upstream-to=x", "git branch -u x",
    "git branch x -D", "git branch --force x", "git grep -O x", "sed -n -i p x", "sed -i s/a/b/ x",
    "sort -o out in", "sort --output=out in", "tree -o out",
]
for cmd in denied_factory:
    check("project opencode does not deny: " + cmd, decide(global_rules, "bash", cmd) != "deny")
    check("project claude does not deny: " + cmd, claude_decide(cc, cmd) != "deny")
for cmd in ["cat x", "find . -name x", "git branch -a", "git status", "sed -n 1p x"]:
    check("project opencode leaves alone: " + cmd, decide(global_rules, "bash", cmd) == "ask")
    check("project claude leaves alone: " + cmd, claude_decide(cc, cmd) == "none")


def factory_claude(entries):
    """The Claude factory layer: the grant, the project deny list and the driver's --disallowedTools."""
    deny = cc["permissions"]["deny"] + ["Bash(" + p + ")" for p in deny_project + deny_factory]
    return {"permissions": {"allow": entries, "deny": deny}}


def list_decide(entries, text):
    return claude_decide(factory_claude(entries), text)


# Commands every role may run: read-only inspection, cargo and the repository scripts.
common = [
    "cargo test", "scripts/gate.sh --commit", "ls x", "rg x", "grep x y", "wc -l x", "diff a b",
    "git status", "git diff", "git log", "git show HEAD", "git write-tree",
    "cat x", "head -n 5 x", "tail -n 5 x", "find . -name x", "stat x", "file x", "tree -L 2", "sort x",
    "uniq x", "cut -d: -f1 x", "tr a b", "basename x", "dirname x", "realpath x", "pwd", "which x",
    "sed -n 1,5p x", "git branch", "git branch -a", "git branch --list x", "git branch --show-current",
    "git branch -vv", "git branch --contains x", "git branch --merged", "git stash list",
    "git describe --tags", "git ls-tree HEAD", "git cat-file -p HEAD", "git blame x", "git shortlog -sn",
    "git grep x", "git tag -l", "git remote -v", "git worktree list",
]
# Commands that change the tree: the implementer only.
code_only = ["git add x", "git commit -m x", "git rm x", "git mv a b", "git restore x", "mkdir x", "chmod +x x"]
# Commands only the driver, or the interactive command, may run.
orchestrator_only = ["git fetch origin main", "git switch -c factory/x", "gh pr view 1", "gh pr create --title x"]
# Never allowed to a factory agent in either tool.
never = [
    "rm x", "git push origin factory/x", "tee x", "cp a b", "mv a b", "touch x", "dd if=a of=b",
    "sed -i s/a/b/ x", "git branch -D x",
]

# The OpenCode factory agents: the project rules, then the agent's own rules.
roles = {
    "factory-planner": True,
    "factory-plan-reviewer": True,
    "factory-code-reviewer": True,
    "factory-pr-writer": True,
    "factory-implementer": False,
}
agent_rules = {name: global_rules + overlay(repo + "/.opencode/agents/" + name + ".md") for name in roles}
for name, readonly in roles.items():
    rules = agent_rules[name]
    for cmd in denied_project + denied_factory + never:
        check("opencode " + name + " denies: " + cmd, decide(rules, "bash", cmd) == "deny")
    for cmd in common:
        check("opencode " + name + " allows: " + cmd, decide(rules, "bash", cmd) == "allow")
    for cmd in code_only:
        want = "deny" if readonly else "allow"
        check("opencode " + name + " " + want + "s: " + cmd, decide(rules, "bash", cmd) == want)
    for cmd in orchestrator_only:
        check("opencode " + name + " denies: " + cmd, decide(rules, "bash", cmd) == "deny")

# The Claude factory layer, per access class.
for cmd in denied_project + denied_factory:
    check("claude readonly grant denies: " + cmd, list_decide(read_list("common"), cmd) == "deny")
    check("claude code grant denies: " + cmd, list_decide(read_list("common") + read_list("code"), cmd) == "deny")
for cmd in never:
    check("claude readonly grant does not allow: " + cmd, list_decide(read_list("common"), cmd) != "allow")
    check("claude code grant does not allow: " + cmd, list_decide(read_list("common") + read_list("code"), cmd) != "allow")
for cmd in common:
    check("claude readonly grant allows: " + cmd, list_decide(read_list("common"), cmd) == "allow")
for cmd in code_only:
    check("claude readonly grant does not allow: " + cmd, list_decide(read_list("common"), cmd) != "allow")
    check("claude code grant allows: " + cmd, list_decide(read_list("common") + read_list("code"), cmd) == "allow")
for cmd in orchestrator_only:
    check("claude code grant does not allow: " + cmd, list_decide(read_list("common") + read_list("code"), cmd) != "allow")
    check("claude orchestrator grant allows: " + cmd, list_decide(read_list("common") + read_list("code") + read_list("orchestrator"), cmd) == "allow")

allow_src = read_list("common") + read_list("code") + read_list("orchestrator")
check("no push or pull request creation in the common or code grants", not any(("push" in e or "pr create" in e) for e in read_list("common") + read_list("code")))
with open(repo + "/.claude/commands/factory.md") as f:
    command = f.read()
m = re.search(r'^allowed-tools: "(.*)"$', command, re.M)
check("the command pre-approves exactly the allow list", bool(m) and m.group(1) == " ".join(allow_src))
check(
    "no Edit or Write rule in the committed settings",
    not any(e.startswith(("Edit", "Write")) for e in cc["permissions"].get("allow", [])),
)
check(
    "no bypass mode is configured",
    "bypass" not in json.dumps(cc).lower() and "bypass" not in json.dumps(oc).lower(),
)

# Mirror: every grant entry that is a Bash rule is an allow rule of the OpenCode agents, and the
# deny lists of the generated agents are exactly the two deny files.
for name, readonly in roles.items():
    entries = read_list("common") + ([] if readonly else read_list("code"))
    want = [e[5:-1] for e in entries if e.startswith("Bash(")]
    got = [pat for tool, pat, act in overlay(repo + "/.opencode/agents/" + name + ".md") if tool == "bash" and act == "allow"]
    check(name + ": the allow rules mirror the Claude grants", got == want)
    got = [pat for tool, pat, act in overlay(repo + "/.opencode/agents/" + name + ".md") if tool == "bash" and act == "deny"]
    check(name + ": the deny rules are the two deny files", got == ["*"] + deny_project + deny_factory)


def agent_checks(label, rules, readonly, decide_fn=decide):
    check(label + " git status allowed", decide_fn(rules, "bash", "git status") == "allow")
    check(label + " git diff allowed", decide_fn(rules, "bash", "git diff HEAD~1") == "allow")
    check(label + " rg allowed", decide_fn(rules, "bash", "rg pattern src") == "allow")
    check(label + " grep allowed", decide_fn(rules, "bash", "grep -n x y") == "allow")
    check(label + " git push main denied", decide_fn(rules, "bash", "git push origin main") == "deny")
    check(label + " git push to a factory branch denied", decide_fn(rules, "bash", "git push origin factory/x") == "deny")
    check(label + " gh pr merge denied", decide_fn(rules, "bash", "gh pr merge 1") == "deny")
    check(label + " no-verify commit denied", decide_fn(rules, "bash", "git commit --no-verify -m x") == "deny")
    check(label + " python denied", decide_fn(rules, "bash", "python3 x") == "deny")
    if readonly:
        check(
            label + " run directory artifact editable",
            decide_fn(rules, "edit", ".factory/runs/x/review-plan-1.md") == "allow",
        )
        check(label + " source file not editable", decide_fn(rules, "edit", "crates/a/src/lib.rs") == "deny")
        check(label + " git commit denied", decide_fn(rules, "bash", "git commit -m x") == "deny")
        check(label + " git add denied", decide_fn(rules, "bash", "git add x") == "deny")
        check(label + " git fetch denied", decide_fn(rules, "bash", "git fetch origin main") == "deny")
        check(label + " mkdir denied", decide_fn(rules, "bash", "mkdir x") == "deny")
        check(label + " chmod denied", decide_fn(rules, "bash", "chmod +x x") == "deny")
    else:
        check(label + " source file editable", decide_fn(rules, "edit", "crates/a/src/lib.rs") == "allow")
        check(label + " git commit allowed", decide_fn(rules, "bash", "git commit -m x") == "allow")


for name, readonly in roles.items():
    agent_checks("generated " + name + ":", agent_rules[name], readonly)

# The OpenCode 2.x shape. 2.x resolves the V1 map into an ordered permissions array of
# action/resource/effect entries and keeps the order (verified with `opencode2 debug agents`; see
# docs/factory/process.md). The same deny and allow lists must decide the same way in that shape.
for name, readonly in roles.items():
    agent_checks("v2 " + name + ":", to_v2(agent_rules[name]), readonly, decide_v2)


def v2_shape(readonly):
    """The ordered list the same sources would produce: baseline deny first, allows, every deny last."""
    entries = []
    if readonly:
        entries.append({"action": "edit", "resource": "*", "effect": "deny"})
        entries.append({"action": "edit", "resource": ".factory/runs/*", "effect": "allow"})
    else:
        entries.append({"action": "edit", "resource": "*", "effect": "allow"})
    entries.append({"action": "shell", "resource": "*", "effect": "deny"})
    for name in ["common"] + ([] if readonly else ["code"]):
        for entry in read_list(name):
            if entry.startswith("Bash(") and entry.endswith(")"):
                entries.append({"action": "shell", "resource": entry[5:-1], "effect": "allow"})
    for pattern in deny_project + deny_factory:
        entries.append({"action": "shell", "resource": pattern, "effect": "deny"})
    return entries


v2_readonly = v2_shape(True)
v2_code = v2_shape(False)
for cmd in denied_project + denied_factory + never:
    check("v2 shape readonly denies: " + cmd, decide_v2(v2_readonly, "bash", cmd) == "deny")
    check("v2 shape code denies: " + cmd, decide_v2(v2_code, "bash", cmd) == "deny")
for cmd in common:
    check("v2 shape readonly allows: " + cmd, decide_v2(v2_readonly, "bash", cmd) == "allow")
    check("v2 shape code allows: " + cmd, decide_v2(v2_code, "bash", cmd) == "allow")
for cmd in code_only:
    check("v2 shape readonly does not allow: " + cmd, decide_v2(v2_readonly, "bash", cmd) != "allow")
    check("v2 shape code allows: " + cmd, decide_v2(v2_code, "bash", cmd) == "allow")
for cmd in orchestrator_only:
    check("v2 shape code denies: " + cmd, decide_v2(v2_code, "bash", cmd) == "deny")
check(
    "v2 shape: the shell baseline is the first shell rule",
    v2_readonly[2] == {"action": "shell", "resource": "*", "effect": "deny"},
)
shell_rules = [entry for entry in v2_readonly if entry["action"] == "shell"]
last_allow = max(i for i, entry in enumerate(shell_rules) if entry["effect"] == "allow")
first_deny = min(i for i, entry in enumerate(shell_rules) if i > 0 and entry["effect"] == "deny")
check("v2 shape: every shell deny follows every shell allow", first_deny > last_allow)
check("v2 shape: readonly artifacts are editable", decide_v2(v2_readonly, "edit", ".factory/runs/x/plan.md") == "allow")
check("v2 shape: readonly sources are not editable", decide_v2(v2_readonly, "edit", "src/lib.rs") == "deny")
check("v2 shape: code sources are editable", decide_v2(v2_code, "edit", "src/lib.rs") == "allow")

for name, readonly in roles.items():
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
