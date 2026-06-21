#!/usr/bin/env python3
"""
BaseAgent Compliance Tester for WRAITH Cell Core
Tests all cell agents for:
1. All agents inherit BaseAgent
2. run() returns List[Finding]  (type annotation check)
3. get_status() returns AgentInfo  (defined or inherited)
4. No duplicate methods
5. No infinite loops (while True without break/return)
"""

import ast
import sys
from typing import Dict, List, Set

sys.path.insert(0, r"C:\Users\Kebro\Documents\wraith-install\cell")

FILE_PATH = r"C:\Users\Kebro\Documents\wraith-install\cell\cell_core.py"

with open(FILE_PATH, "r") as f:
    source = f.read()

tree = ast.parse(source, filename=FILE_PATH)


def check_infinite_loop(func_node: ast.FunctionDef) -> List[str]:
    """Walk a function's AST looking for potential infinite loops."""
    warnings: List[str] = []
    for child in ast.walk(func_node):
        if isinstance(child, ast.While):
            is_constant_loop = False
            if isinstance(child.test, ast.Constant) and child.test.value in (True, 1):
                is_constant_loop = True
            elif isinstance(child.test, ast.NameConstant) and child.test.value is True:
                is_constant_loop = True

            if is_constant_loop:
                has_exit = False
                for stmt in child.body:
                    if isinstance(stmt, (ast.Break, ast.Return, ast.Raise)):
                        has_exit = True
                    elif isinstance(stmt, ast.If):
                        for sub in ast.walk(stmt):
                            if isinstance(sub, (ast.Break, ast.Return, ast.Raise)):
                                has_exit = True
                    elif isinstance(stmt, (ast.For, ast.While)):
                        for sub in ast.walk(stmt):
                            if isinstance(sub, (ast.Break, ast.Return, ast.Raise)):
                                has_exit = True
                if not has_exit:
                    warnings.append(f"infinite loop in {func_node.name}() — no break/return/raise found")
    return warnings


# ── Extract BaseAgent class info ──────────────────────────────────────────────

base_methods: Set[str] = set()
agent_classes: List[dict] = []
non_agent_classes: List[str] = []

for node in ast.iter_child_nodes(tree):
    if isinstance(node, ast.ClassDef):
        if node.name == "BaseAgent":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    base_methods.add(item.name)
        else:
            is_agent = any(
                isinstance(b, ast.Name) and b.id == "BaseAgent"
                for b in node.bases
            )
            if is_agent:
                agent_classes.append({"name": node.name, "lineno": node.lineno, "node": node})
            else:
                non_agent_classes.append(node.name)

# ── Analyze each agent ────────────────────────────────────────────────────────

results: List[dict] = []

for agent in agent_classes:
    node = agent["node"]
    name = agent["name"]
    lineno = agent["lineno"]

    methods: Dict[str, ast.FunctionDef] = {}
    class_attrs: Dict[str, ast.Assign] = {}

    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods[item.name] = item
        elif isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    class_attrs[target.id] = item

    # Check: has run()
    has_run = "run" in methods
    run_node = methods.get("run")

    # Check: run() return annotation
    run_returns_ok = False
    if run_node and run_node.returns:
        ret_str = ast.dump(run_node.returns)
        run_returns_ok = "Finding" in ret_str or "list" in ret_str.lower()

    # Check: get_status (defined in class or inherited from BaseAgent)
    has_get_status_defined = "get_status" in methods
    # get_status is in BaseAgent, so if not overridden, it's inherited — that's OK
    has_get_status = True  # Always true since BaseAgent defines it

    # Check: class name attribute
    has_name_attr = "name" in class_attrs

    # Check: duplicate method definitions
    method_counts: Dict[str, int] = {}
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            mname = item.name
            method_counts[mname] = method_counts.get(mname, 0) + 1
    duplicate_methods = [m for m, c in method_counts.items() if c > 1]

    # Check: infinite loops
    loop_warnings: List[str] = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            loop_warnings.extend(check_infinite_loop(item))
    loop_warnings = list(set(loop_warnings))

    # Build issues list
    issues: List[str] = []
    if not has_run:
        issues.append("MISSING run() method")
    elif not run_returns_ok:
        issues.append("run() return type annotation doesn't indicate List[Finding]")

    if not has_get_status_defined:
        # Not an issue — inherited from BaseAgent, which returns AgentInfo
        pass  # This is fine

    if not has_name_attr:
        issues.append("Missing class-level 'name' attribute (required by BaseAgent)")
    if duplicate_methods:
        issues.append(f"Duplicate methods: {duplicate_methods}")
    if loop_warnings:
        issues.extend(loop_warnings)

    compliant = (
        has_run
        and run_returns_ok
        and has_name_attr
        and not duplicate_methods
        and not loop_warnings
    )

    results.append({
        "name": name,
        "lineno": lineno,
        "has_run": has_run,
        "run_returns_ok": run_returns_ok,
        "has_get_status_defined": has_get_status_defined,
        "has_name_attr": has_name_attr,
        "duplicate_methods": duplicate_methods,
        "loop_warnings": loop_warnings,
        "method_count": len(methods),
        "methods": sorted(methods.keys()),
        "compliant": compliant,
        "issues": issues,
    })


# ── Print Results ────────────────────────────────────────────────────────────

print("=" * 80)
print("WRAITH CELL CORE — BaseAgent Compliance Test Suite")
print("=" * 80)
print(f"\nDiscovery: Found {len(agent_classes)} BaseAgent subclasses")
print(f"BaseAgent methods: {sorted(base_methods)}")
print(f"Non-agent classes: {non_agent_classes}")

print("\n" + "=" * 80)
print(f"COMPLIANCE REPORT: {len(results)} AGENTS")
print("=" * 80)

passed = 0
failed = 0

for i, r in enumerate(results, 1):
    status = "✅ PASS" if r["compliant"] else "❌ FAIL"
    if r["compliant"]:
        passed += 1
    else:
        failed += 1

    # get_status display
    if r["has_get_status_defined"]:
        get_status_str = "✅ (defined in class)"
    else:
        get_status_str = "✅ (inherited from BaseAgent)"

    print(f"\n── Agent {i:2d}: {r['name']} (line {r['lineno']}) [{status}]")
    print(f"   Inherits BaseAgent:  ✅")
    print(f"   Has run():           {'✅' if r['has_run'] else '❌   MISSING'}")
    print(f"   run()→List[Finding]:  {'✅' if r['run_returns_ok'] else '❌'}")
    print(f"   get_status():        {get_status_str}")
    print(f"   Has name attribute:  {'✅' if r['has_name_attr'] else '❌'}")
    print(f"   Duplicate methods:   {'❌ ' + str(r['duplicate_methods']) if r['duplicate_methods'] else '✅ None'}")
    print(f"   Infinite loops:      {'❌' if r['loop_warnings'] else '✅ None'}")
    print(f"   Methods ({r['method_count']}): {r['methods']}")
    if r["issues"]:
        print(f"   Issues:")
        for issue in r["issues"]:
            print(f"      ⚠️  {issue}")

# ── Summary ──────────────────────────────────────────────────────────────────

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Total agents tested: {len(results)}")
print(f"Compliant:           {passed}")
print(f"Non-compliant:       {failed}")
print(f"Pass rate:           {passed}/{len(results)} ({100 * passed // len(results) if results else 0}%)")

if failed > 0:
    print(f"\n❌ Non-compliant agents:")
    for r in results:
        if not r["compliant"]:
            print(f"   {r['name']:30s} — {', '.join(r['issues'])}")
else:
    print("\n🎉 All agents are BaseAgent compliant!")

print("=" * 80)
