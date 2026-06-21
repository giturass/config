#!/usr/bin/env python3
"""Sync Surge, Surfboard, and sing-box rule files.

The script accepts edits from any supported rule representation. In CI, pass a
git-generated changed-files list so the edited files become authoritative for
their rule family. Without changed files, the canonical rules/ files are used
when present; otherwise the largest existing source is used to bootstrap.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]

JSON_RULE_KEYS = ("domain", "domain_suffix", "domain_keyword", "ip_cidr", "process_name")
CASE_SENSITIVE_KINDS = {"process_name", "user_agent"}
LIST_RULE_TO_KIND = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "PROCESS-NAME": "process_name",
    "USER-AGENT": "user_agent",
}
KIND_TO_LIST_RULE = {
    "domain": "DOMAIN",
    "domain_suffix": "DOMAIN-SUFFIX",
    "domain_keyword": "DOMAIN-KEYWORD",
    "process_name": "PROCESS-NAME",
    "user_agent": "USER-AGENT",
}

CATEGORIES = ("proxy", "direct", "reject", "reject-plus")
REGULAR_CATEGORIES = ("proxy", "direct", "reject")


@dataclass(frozen=True)
class RuleEntry:
    kind: str
    value: str


class RuleSet:
    def __init__(self) -> None:
        self.entries: list[RuleEntry] = []
        self._seen: set[tuple[str, str]] = set()

    def add(self, kind: str, value: str) -> None:
        normalized = normalize_value(kind, value)
        if not normalized:
            return
        key = (kind, normalized if kind in CASE_SENSITIVE_KINDS else normalized.lower())
        if key in self._seen:
            return
        self._seen.add(key)
        self.entries.append(RuleEntry(kind, normalized))

    def extend(self, other: "RuleSet") -> None:
        for entry in other.entries:
            self.add(entry.kind, entry.value)

    def by_kind(self, *kinds: str) -> list[str]:
        wanted = set(kinds)
        return [entry.value for entry in self.entries if entry.kind in wanted]

    def split_reject_domains(self) -> tuple["RuleSet", "RuleSet"]:
        regular = RuleSet()
        domain_set = RuleSet()
        for entry in self.entries:
            if entry.kind in {"domain", "domain_suffix"}:
                domain_set.add(entry.kind, entry.value)
            else:
                regular.add(entry.kind, entry.value)
        return regular, domain_set

    def compatible_with_sing_box(self) -> "RuleSet":
        compatible = RuleSet()
        for entry in self.entries:
            if entry.kind in JSON_RULE_KEYS:
                compatible.add(entry.kind, entry.value)
        return compatible


def normalize_value(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "domain_suffix":
        value = value.lstrip(".").lower()
    elif kind in {"domain", "domain_keyword"}:
        value = value.lower()
    elif kind == "ip_cidr":
        value = value.lower()
    return value


def relpath(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_changed_files(path: Path | None) -> set[str]:
    if not path:
        return set()
    changed: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        item = raw_line.strip()
        if not item:
            continue
        item_path = Path(item)
        if item_path.is_absolute():
            try:
                item = item_path.relative_to(ROOT).as_posix()
            except ValueError:
                continue
        changed.add(item.replace("\\", "/"))
    return changed


def parse_regular_list(path: Path) -> RuleSet:
    result = RuleSet()
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        rule_type = parts[0].upper()
        if rule_type not in LIST_RULE_TO_KIND:
            raise ValueError(f"{relpath(path)}:{lineno}: unsupported rule type {parts[0]!r}")
        if len(parts) < 2 or not parts[1]:
            raise ValueError(f"{relpath(path)}:{lineno}: missing rule value")
        result.add(LIST_RULE_TO_KIND[rule_type], parts[1])
    return result


def parse_domain_set(path: Path) -> RuleSet:
    result = RuleSet()
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            raise ValueError(f"{relpath(path)}:{lineno}: reject-plus entries must be domains only")
        if line.startswith("."):
            result.add("domain_suffix", line[1:])
        else:
            result.add("domain", line)
    return result


def parse_sing_box_json(path: Path) -> RuleSet:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{relpath(path)}: invalid JSON: {exc}") from exc

    if payload.get("version") != 3:
        raise ValueError(f"{relpath(path)}: expected sing-box rule-set version 3")

    result = RuleSet()
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"{relpath(path)}: expected rules to be a list")

    supported = set(JSON_RULE_KEYS)
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise ValueError(f"{relpath(path)}: rule #{index} must be an object")
        unknown = sorted(set(rule) - supported)
        if unknown:
            unknown_text = ", ".join(unknown)
            raise ValueError(f"{relpath(path)}: rule #{index} has unsupported keys: {unknown_text}")
        for kind in JSON_RULE_KEYS:
            values = rule.get(kind, [])
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                raise ValueError(f"{relpath(path)}: {kind} in rule #{index} must be a list")
            for value in values:
                if not isinstance(value, str):
                    raise ValueError(f"{relpath(path)}: {kind} in rule #{index} contains a non-string value")
                result.add(kind, value)
    return result


def parse_rule_source(path: Path, category: str) -> RuleSet:
    if path.suffix == ".json":
        return parse_sing_box_json(path)
    if category == "reject-plus":
        return parse_domain_set(path)
    return parse_regular_list(path)


def list_sources(category: str) -> list[Path]:
    return [
        ROOT / "rules" / f"{category}.list",
        ROOT / "surge" / f"{category}.list",
        ROOT / "surfboard" / f"{category}.list",
    ]


def json_source(category: str) -> Path | None:
    if category == "proxy":
        return ROOT / "sing-box" / "proxy.json"
    if category == "direct":
        return ROOT / "sing-box" / "direct.json"
    return None


def changed_sources_for_category(category: str, changed: set[str]) -> list[RuleSet]:
    sources: list[RuleSet] = []

    for path in list_sources(category):
        if relpath(path) in changed and path.exists():
            sources.append(parse_rule_source(path, category))

    json_path = json_source(category)
    if json_path and relpath(json_path) in changed and json_path.exists():
        sources.append(parse_sing_box_json(json_path))

    reject_path = ROOT / "sing-box" / "reject.json"
    if category in {"reject", "reject-plus"} and relpath(reject_path) in changed and reject_path.exists():
        regular, domain_set = parse_sing_box_json(reject_path).split_reject_domains()
        sources.append(regular if category == "reject" else domain_set)

    return sources


def bootstrap_source_for_category(category: str) -> RuleSet:
    canonical = ROOT / "rules" / f"{category}.list"
    if canonical.exists():
        return parse_rule_source(canonical, category)

    candidates = [path for path in list_sources(category) if path.exists()]
    json_path = json_source(category)
    if json_path and json_path.exists():
        candidates.append(json_path)

    if not candidates:
        return RuleSet()

    parsed = [(path, parse_rule_source(path, category)) for path in candidates]
    parsed.sort(key=lambda item: len(item[1].entries), reverse=True)
    source_path, source_rules = parsed[0]
    print(f"bootstrap {category} from {relpath(source_path)} ({len(source_rules.entries)} entries)")
    return source_rules


def select_rules(category: str, changed: set[str]) -> RuleSet:
    changed_sources = changed_sources_for_category(category, changed)
    if changed_sources:
        selected = RuleSet()
        for source in changed_sources:
            selected.extend(source)
        print(f"sync {category} from {len(changed_sources)} changed source(s) ({len(selected.entries)} entries)")
        return selected
    return bootstrap_source_for_category(category)


def render_regular_list(rules: RuleSet) -> str:
    lines: list[str] = []
    for entry in rules.entries:
        if entry.kind == "ip_cidr":
            rule_type = "IP-CIDR6" if ":" in entry.value else "IP-CIDR"
            lines.append(f"{rule_type},{entry.value},no-resolve")
        elif entry.kind in KIND_TO_LIST_RULE:
            lines.append(f"{KIND_TO_LIST_RULE[entry.kind]},{entry.value}")
        else:
            raise ValueError(f"unsupported list rule kind {entry.kind!r}")
    return "\n".join(lines) + ("\n" if lines else "")


def render_domain_set(rules: RuleSet) -> str:
    lines: list[str] = []
    for entry in rules.entries:
        if entry.kind == "domain_suffix":
            lines.append(f".{entry.value}")
        elif entry.kind == "domain":
            lines.append(entry.value)
        else:
            continue
    return "\n".join(lines) + ("\n" if lines else "")


def render_sing_box_json(rules: RuleSet, label: str) -> str:
    compatible = rules.compatible_with_sing_box()
    omitted = len(rules.entries) - len(compatible.entries)
    if omitted:
        print(f"warning: omitted {omitted} {label} entrie(s) unsupported by sing-box", file=sys.stderr)

    grouped: dict[str, list[str]] = {}
    for kind in JSON_RULE_KEYS:
        values = compatible.by_kind(kind)
        if values:
            grouped[kind] = values

    payload = {"version": 3, "rules": [grouped] if grouped else []}
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def write_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def write_outputs(rule_sets: dict[str, RuleSet]) -> list[str]:
    changed: list[str] = []

    for category in CATEGORIES:
        content = render_domain_set(rule_sets[category]) if category == "reject-plus" else render_regular_list(rule_sets[category])
        for path in list_sources(category):
            if write_if_changed(path, content):
                changed.append(relpath(path))

    sing_box_outputs = {
        ROOT / "sing-box" / "proxy.json": render_sing_box_json(rule_sets["proxy"], "proxy"),
        ROOT / "sing-box" / "direct.json": render_sing_box_json(rule_sets["direct"], "direct"),
        ROOT / "sing-box" / "reject.json": render_sing_box_json(combine_rule_sets(rule_sets["reject"], rule_sets["reject-plus"]), "reject"),
    }
    for path, content in sing_box_outputs.items():
        if write_if_changed(path, content):
            changed.append(relpath(path))

    return changed


def combine_rule_sets(*sources: RuleSet) -> RuleSet:
    combined = RuleSet()
    for source in sources:
        combined.extend(source)
    return combined


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync Surge, Surfboard, and sing-box rules.")
    parser.add_argument(
        "--changed-files",
        type=Path,
        help="File containing git changed paths, one per line. Changed files become authoritative.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    changed_files = load_changed_files(args.changed_files)
    rule_sets = {category: select_rules(category, changed_files) for category in CATEGORIES}
    updated = write_outputs(rule_sets)

    if updated:
        print("updated:")
        for path in updated:
            print(f"  {path}")
    else:
        print("rules already synchronized")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
