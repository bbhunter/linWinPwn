#!/usr/bin/env python3
"""
NetExec Module and Action Enumerator for linWinPwn
Enumerates modules (-L) and protocol core actions (--help) from NetExec.
Analyzes usage status across linWinPwn.sh and outputs clean, structured results.
"""

import os
import sys
import re
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# Ensure standard UTF-8 stream output across platforms
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Default supported NetExec protocols
PROTOCOLS = [
    "smb",
    "ldap",
    "winrm",
    "mssql",
    "ssh",
    "rdp",
    "vnc",
    "ftp",
    "nfs",
    "wmi",
]

# Common sections in NetExec help that are not protocol-specific actions
COMMON_SECTIONS = {
    "positional arguments",
    "options",
    "optional arguments",
    "generic options",
    "output options",
    "dns",
    "authentication",
    "kerberos authentication",
    "certificate authentication",
    "modules",
}

# Terminal ANSI styling
class Style:
    def __init__(self, enabled=True):
        self.enabled = enabled and sys.stdout.isatty()

    @property
    def RESET(self):
        return "\033[0m" if self.enabled else ""

    @property
    def BOLD(self):
        return "\033[1m" if self.enabled else ""

    @property
    def DIM(self):
        return "\033[2m" if self.enabled else ""

    @property
    def GREEN(self):
        return "\033[92m" if self.enabled else ""

    @property
    def RED(self):
        return "\033[91m" if self.enabled else ""

    @property
    def YELLOW(self):
        return "\033[93m" if self.enabled else ""

    @property
    def BLUE(self):
        return "\033[94m" if self.enabled else ""

    @property
    def CYAN(self):
        return "\033[96m" if self.enabled else ""

    @property
    def MAGENTA(self):
        return "\033[95m" if self.enabled else ""


def run_command(cmd, timeout=30):
    """Execute a system command and return stdout, stderr, returncode"""
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return res.stdout, res.stderr, res.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1


def get_exec_prefix(bin_path):
    """Return command prefix (e.g. adding python executable if bin_path is a .py file)"""
    if bin_path and bin_path.endswith(".py"):
        return f'"{sys.executable}" "{bin_path}"'
    return f'"{bin_path}"'


def find_netexec(custom_path=None):
    """Find netexec or nxc binary in PATH or standard pipx/system locations"""
    if custom_path:
        p = Path(custom_path).expanduser().resolve()
        if p.is_file():
            return str(p)
        which_path = shutil.which(custom_path)
        if which_path:
            return which_path

    candidates = ["netexec", "nxc"]
    for cand in candidates:
        found = shutil.which(cand)
        if found:
            return found

    # Check common user / system paths on Unix
    search_dirs = [
        Path.home() / ".local" / "bin",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
    ]
    for d in search_dirs:
        for cand in candidates:
            bin_path = d / cand
            if bin_path.is_file() and os.access(bin_path, os.X_OK):
                return str(bin_path)

    return None


def find_linwinpwn(custom_path=None):
    """Locate linWinPwn.sh script"""
    if custom_path:
        p = Path(custom_path).expanduser().resolve()
        if p.is_file():
            return p

    # Standard relative location from helpers/
    script_dir = Path(__file__).resolve().parent
    search_paths = [
        script_dir.parent / "linWinPwn.sh",
        script_dir / "linWinPwn.sh",
        Path.cwd() / "linWinPwn.sh",
    ]
    for sp in search_paths:
        if sp.is_file():
            return sp
    return None


def is_metavar_string(val):
    """Check if a string represents an argparse metavar/choices rather than a description"""
    val = val.strip()
    if not val:
        return False
    if (val.startswith("{") and val.endswith("}")) or (val.startswith("[") and val.endswith("]")):
        return True
    tokens = val.split()
    for tok in tokens:
        cleaned = re.sub(r"^[\[\{\(]+|[\]\}\)\.,]+$", "", tok)
        if not cleaned:
            continue
        if not (cleaned.isupper() or cleaned.isdigit() or cleaned in ("...", "-", "_")):
            return False
    return True


def parse_modules(output):
    """
    Parse module list from `netexec <protocol> -L` output.
    Captures module name, description, privilege level, and category.
    Returns (active_modules, removed_modules).
    """
    modules = []
    removed_modules = []
    current_privilege = "Standard"
    current_category = "General"

    for line in output.splitlines():
        line_s = line.strip()
        if not line_s or "Traceback" in line_s:
            continue

        # Privilege header detection
        if "HIGH PRIVILEGE MODULES" in line_s.upper():
            current_privilege = "High"
            continue
        elif "LOW PRIVILEGE MODULES" in line_s.upper():
            current_privilege = "Low"
            continue

        # Subcategory detection (e.g. ENUMERATION, CREDENTIAL_DUMPING, PRIVILEGE_ESCALATION)
        if re.match(r"^[A-Z_]+$", line_s) and not line_s.startswith("[*]"):
            current_category = line_s.replace("_", " ").title()
            continue

        # Module line: [*] module_name    Description
        m = re.match(r"^\s*\[\*\]\s+([a-zA-Z0-9_\-]+)\s*(.*)$", line)
        if m:
            name = m.group(1).strip()
            desc = m.group(2).strip()
            # Capture deprecated / removed modules separately
            if "[REMOVED]" in desc or "[REMOVED]" in line_s:
                removed_modules.append({
                    "name": name,
                    "description": desc,
                    "privilege": current_privilege,
                    "category": current_category,
                })
                continue

            modules.append({
                "name": name,
                "description": desc,
                "privilege": current_privilege,
                "category": current_category,
            })

    return modules, removed_modules


def parse_actions(help_output):
    """
    Parse protocol-specific actions and flags from `netexec <protocol> --help`.
    Captures section name, primary flag, aliases, and clean multiline description.
    Returns (actions, all_help_flags).
    """
    lines = help_output.splitlines()
    actions = []
    current_section = None
    passed_modules = False
    is_protocol_section = False
    current_entry = None

    # Collect all flags mentioned across the entire help output
    all_help_flags = set(re.findall(r'(--[a-zA-Z0-9_\-]+)', help_output))

    def finalize_entry(entry):
        if not entry:
            return
        desc = " ".join(entry["desc_lines"]).strip()
        desc = re.sub(r"\s+", " ", desc)
        entry["description"] = desc
        del entry["desc_lines"]
        actions.append(entry)

    for line in lines:
        raw_line = line
        stripped = line.strip()

        # Check for section header (column 0, starts with uppercase letter, ends with ':')
        sec_match = re.match(r"^([A-Z][A-Za-z0-9_ /()\-]+):\s*$", raw_line)
        if sec_match and not stripped.startswith("usage:"):
            finalize_entry(current_entry)
            current_entry = None
            current_section = sec_match.group(1).strip()
            sec_lower = current_section.lower()

            if sec_lower == "modules":
                passed_modules = True

            # Protocol action sections strictly occur after the 'Modules:' section
            is_protocol_section = passed_modules and (sec_lower not in COMMON_SECTIONS)
            continue

        if not is_protocol_section:
            continue

        # Match flag option line (indented by 2 spaces and starting with '-')
        opt_match = re.match(r"^  (-[a-zA-Z0-9_\-]+(?:,\s*-[a-zA-Z0-9_\-]+)*)(.*)$", raw_line)
        if opt_match:
            finalize_entry(current_entry)
            flags_str = opt_match.group(1).strip()
            rest = opt_match.group(2) if opt_match.group(2) else ""

            all_flags = [f.strip() for f in flags_str.split(",")]
            long_flags = [f for f in all_flags if f.startswith("--")]
            primary_flag = long_flags[0] if long_flags else all_flags[0]

            desc_lines = []
            rest_stripped = rest.strip()
            if rest_stripped:
                # If description is on the same line, it is separated by 2+ spaces
                parts = re.split(r"\s{2,}", rest_stripped, maxsplit=1)
                if len(parts) == 2:
                    metavar, desc = parts
                    desc_lines.append(desc.strip())
                elif len(parts) == 1:
                    val = parts[0]
                    if not is_metavar_string(val):
                        desc_lines.append(val.strip())

            current_entry = {
                "section": current_section,
                "name": primary_flag,
                "flags": all_flags,
                "desc_lines": desc_lines,
            }
        elif current_entry is not None:
            # Multi-line description continuation line (indented 4+ spaces)
            if raw_line.startswith("    ") and stripped:
                current_entry["desc_lines"].append(stripped)

    finalize_entry(current_entry)
    detect_subargs(actions)
    return actions, all_help_flags



def detect_subargs(actions):
    """
    Detect sub-arguments / modifier flags and link them to their parent action.
    E.g. '-c, --collection' is a sub-arg for '--bloodhound'.
         '--mkfile' and '--pvk' are sub-args for '--dpapi'.
         '--gmsa-convert-id' is a sub-arg for '--gmsa'.
         '--users-export' is a sub-arg for '--users'.
         '--kerberoast-account' is a sub-arg for '--kerberoasting'.
    """
    sections = {}
    for a in actions:
        sec = a.get("section", "General")
        sections.setdefault(sec, []).append(a)

    for sec, sec_actions in sections.items():
        action_names = [a["name"] for a in sec_actions]

        # Check for section-level trigger (e.g. Bloodhound Scan -> --bloodhound)
        sec_trigger = None
        for a in sec_actions:
            clean_name = a["name"].lstrip("-")
            clean_sec = re.sub(r"[^a-zA-Z0-9]", "", sec.lower())
            if clean_name in clean_sec or clean_sec in clean_name:
                sec_trigger = a["name"]
                break

        for a in sec_actions:
            parent = None
            desc = a.get("description", "")
            name = a["name"]

            # Rule 1: Explicit mention in description (e.g. "DPAPI option. ...")
            desc_match = re.search(r"\b([A-Za-z0-9_-]+)\s+option\b", desc, re.IGNORECASE)
            if desc_match:
                candidate = "--" + desc_match.group(1).lower()
                for act in actions:
                    if act["name"] == candidate or candidate in act.get("flags", []):
                        parent = act["name"]
                        break

            # Rule 2: Prefix matching with a base flag in the same section
            # e.g. --gmsa-convert-id -> --gmsa, --users-export -> --users
            if not parent:
                for base in action_names:
                    if base != name and name.startswith(base + "-"):
                        parent = base
                        break

            # Rule 3: Fuzzy stem or substring matching (e.g. --targeted-kerberoast / --kerberoast-account -> --kerberoasting)
            if not parent:
                for act in sec_actions:
                    base_flags = act.get("flags", [act["name"]])
                    for bf in base_flags:
                        clean_bf = bf.lstrip("-")
                        clean_name = name.lstrip("-")
                        if len(clean_bf) >= 4 and act["name"] != name:
                            if clean_bf in clean_name or clean_bf in desc.lower():
                                parent = act["name"]
                                break
                    if parent:
                        break

            # Rule 4: Section-level sub-argument (e.g. Bloodhound Scan -> -c/--collection is sub-arg for --bloodhound)
            if not parent and sec_trigger and name != sec_trigger:
                parent = sec_trigger

            if parent:
                a["parent"] = parent
                a["is_subarg"] = True
            else:
                a["parent"] = None
                a["is_subarg"] = False

    return actions


def extract_protocol_commands(linwinpwn_content):
    """
    Extract NetExec execution lines from linWinPwn.sh, indexed by protocol.
    Separates active commands from commented-out (#) commands.
    Expands dynamic protocol variables (e.g. ${proto} in dpapi_dump line 5425 for smb, wmi, mssql, winrm).
    Returns dict: {protocol: {"active": [...], "commented": [...]}}
    """
    proto_cmds = {p: {"active": [], "commented": []} for p in PROTOCOLS}
    if not linwinpwn_content:
        return proto_cmds

    lines = linwinpwn_content.splitlines()
    netexec_re = r'(?:\$\{[^}]*netexec[^}]*\}|\$netexec|\bnetexec\b|\bnxc\b)'
    proto_var_re = r'(?:\$\{proto\}|\$proto\b)'

    for line in lines:
        s = line.strip()
        if not s:
            continue

        is_comment = False
        clean_s = s
        if clean_s.startswith("#"):
            is_comment = True
            clean_s = clean_s.lstrip("#").strip()

        if clean_s.startswith("echo ") or clean_s.startswith("echo -e"):
            continue
        if "check_tool_status" in clean_s:
            continue

        if re.search(netexec_re, clean_s):
            target_key = "commented" if is_comment else "active"

            # Check if line uses dynamic protocol variable like ${proto} (e.g. dpapi_dump in linWinPwn line 5425)
            if re.search(rf'{netexec_re}\s+(?:[^;\"\'\`]*?\s)?{proto_var_re}', clean_s, re.IGNORECASE):
                # linWinPwn line 5434: case ${dpapi_protocol} in: 1|smb, 2|wmi, 3|mssql, 4|winrm
                dynamic_protocols = ["smb", "wmi", "mssql", "winrm"]
                for dp in dynamic_protocols:
                    if dp in proto_cmds:
                        expanded_cmd = re.sub(proto_var_re, dp, clean_s)
                        proto_cmds[dp][target_key].append(expanded_cmd)
                continue

            # Standard explicit protocol call
            for p in PROTOCOLS:
                pat = rf'{netexec_re}\s+(?:[^;\"\'\`]*?\s)?\b{p}\b'
                if re.search(pat, clean_s, re.IGNORECASE):
                    proto_cmds[p][target_key].append(clean_s)
                    break

    return proto_cmds


def extract_linwinpwn_protocol_modules(content):
    """
    Extract list of unique module names passed via -M or --module in protocol commands.
    """
    if not content:
        return []
    matches = re.findall(r'(?:-M|--module)\s+["\']?([a-zA-Z0-9_\-]+)', content)
    seen = set()
    result = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def extract_linwinpwn_protocol_flags(content):
    """
    Extract list of unique --long-flags passed in protocol commands.
    """
    if not content:
        return []
    matches = re.findall(r'(--[a-zA-Z0-9_\-]+)', content)
    seen = set()
    result = []
    for f in matches:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result



def check_module_usage(name, content):
    """Check how many times a module is called via -M or --module in linWinPwn.sh"""
    if not content:
        return False, 0
    pat = rf'(?:-M|--module)\s+["\']?{re.escape(name)}["\']?(?:\s|$|["\';])'
    matches = re.findall(pat, content, re.IGNORECASE)
    cnt = len(matches)
    return cnt > 0, cnt


def check_action_usage(flags, content):
    """Check if any of an action's flags/aliases are called in linWinPwn.sh"""
    if not content:
        return False, 0, []
    total_cnt = 0
    matched_flags = []
    for flg in flags:
        pat = rf'(?<![a-zA-Z0-9_\-]){re.escape(flg)}(?![a-zA-Z0-9_\-])'
        matches = re.findall(pat, content)
        cnt = len(matches)
        if cnt > 0:
            total_cnt += cnt
            matched_flags.append(f"{flg} ({cnt}x)")
    return total_cnt > 0, total_cnt, matched_flags


def print_protocol_results(result, style, args):
    """Print clean, formatted protocol enumeration results to terminal"""
    protocol = result["protocol"].upper()
    modules = result["modules"]
    actions = result["core_actions"]
    errors = result["errors"]

    # Filter based on CLI flags
    filtered_modules = modules
    filtered_actions = actions

    if args.used:
        filtered_modules = [m for m in filtered_modules if m.get("in_linwinpwn", False)]
        filtered_actions = [a for a in filtered_actions if a.get("in_linwinpwn", False)]
    elif args.missing:
        filtered_modules = [m for m in filtered_modules if not m.get("in_linwinpwn", False)]
        filtered_actions = [a for a in filtered_actions if not a.get("in_linwinpwn", False)]

    primary_actions_all = [a for a in actions if not a.get("is_subarg", False)]
    sub_count_all = len(actions) - len(primary_actions_all)
    acts_str = f"Actions: {len(primary_actions_all)}" + (f" (+{sub_count_all} sub-args)" if sub_count_all else "")

    # Protocol Banner
    print()
    print(f"{style.BOLD}{style.YELLOW}{'='*80}{style.RESET}")
    print(f"{style.BOLD}{style.YELLOW}[>] PROTOCOL: {protocol}{style.RESET} "
          f"{style.DIM}(Modules: {len(modules)}, {acts_str}){style.RESET}")
    print(f"{style.BOLD}{style.YELLOW}{'='*80}{style.RESET}")

    if errors:
        for err in errors:
            print(f"  {style.RED}[!]{style.RESET} {err}")

    # Integrity Alerts for non-existent / deprecated features
    non_exist_mods = result.get("non_existent_modules", [])
    removed_mods = result.get("removed_modules_used", [])
    non_exist_flags = result.get("non_existent_flags", [])
    total_issues = len(non_exist_mods) + len(removed_mods) + len(non_exist_flags)

    if total_issues > 0:
        print(f"\n  {style.BOLD}{style.RED}--- linWinPwn Integrity Alerts ({total_issues} issue(s) detected) ---{style.RESET}")
        for rm in removed_mods:
            mod_name = rm["name"]
            is_c = rm.get("is_commented", False)
            if is_c:
                print(f"  {style.YELLOW}[!]{style.RESET} [Module] {style.BOLD}{mod_name:<20}{style.RESET} {style.YELLOW}[REMOVED - inactive]{style.RESET} {style.DIM}(commented in linWinPwn.sh){style.RESET} Module is deprecated/removed in NetExec {protocol}")
            else:
                print(f"  {style.RED}[!]{style.RESET} [Module] {style.BOLD}{mod_name:<20}{style.RESET} {style.YELLOW}[REMOVED]{style.RESET} Module is deprecated/removed in NetExec {protocol}")

        for nm in non_exist_mods:
            mod_name = nm["name"]
            is_c = nm.get("is_commented", False)
            if is_c:
                print(f"  {style.YELLOW}[!]{style.RESET} [Module] {style.BOLD}{mod_name:<20}{style.RESET} {style.YELLOW}[NOT FOUND - inactive]{style.RESET} {style.DIM}(commented in linWinPwn.sh){style.RESET} Module does not exist in NetExec {protocol} (-L)")
            else:
                print(f"  {style.RED}[!]{style.RESET} [Module] {style.BOLD}{mod_name:<20}{style.RESET} {style.RED}[NOT FOUND]{style.RESET} Module does not exist in NetExec {protocol} (-L)")

        for nf in non_exist_flags:
            flag_name = nf["flag"]
            is_c = nf.get("is_commented", False)
            if is_c:
                print(f"  {style.YELLOW}[!]{style.RESET} [Flag]   {style.BOLD}{flag_name:<20}{style.RESET} {style.YELLOW}[NOT FOUND - inactive]{style.RESET} {style.DIM}(commented in linWinPwn.sh){style.RESET} Flag does not exist in NetExec {protocol} (--help)")
            else:
                print(f"  {style.RED}[!]{style.RESET} [Flag]   {style.BOLD}{flag_name:<20}{style.RESET} {style.RED}[NOT FOUND]{style.RESET} Flag does not exist in NetExec {protocol} (--help)")

    if getattr(args, "integrity_only", False):
        return

    # Modules Section
    if not args.actions_only:
        print(f"\n  {style.BOLD}{style.CYAN}--- Modules ({len(filtered_modules)}/{len(modules)}) ---{style.RESET}")
        if not filtered_modules:
            print(f"  {style.DIM}(No modules found matching filter){style.RESET}")
        else:
            for m in filtered_modules:
                is_act = m.get("is_active", False)
                is_com = m.get("is_commented", False)
                cnt = m.get("usage_count", 0)

                if is_act:
                    mark = f"{style.GREEN}[+]{style.RESET}"
                    cnt_str = f"{style.GREEN}({cnt}x){style.RESET}"
                    status_note = ""
                elif is_com:
                    mark = f"{style.YELLOW}[#]{style.RESET}"
                    cnt_str = f"{style.YELLOW}({cnt}x#){style.RESET}"
                    status_note = f" {style.YELLOW}[not active yet in linwinpwn]{style.RESET}"
                else:
                    mark = f"{style.DIM}[-]{style.RESET}"
                    cnt_str = "    "
                    status_note = ""

                cat = f"[{m['privilege']}/{m['category']}]"
                print(f"  {mark} {cnt_str:<8} {style.BOLD}{m['name']:<24}{style.RESET} {style.MAGENTA}{cat:<26}{style.RESET} {m['description']}{status_note}")

    # Actions Section
    if not args.modules_only:
        primary_filtered = [a for a in filtered_actions if not a.get("is_subarg", False)]
        sub_filtered = [a for a in filtered_actions if a.get("is_subarg", False)]
        action_header_counts = f"{len(primary_filtered)} primary" + (f", {len(sub_filtered)} sub-args" if sub_filtered else "")
        print(f"\n  {style.BOLD}{style.BLUE}--- Core Actions / Protocol Flags ({action_header_counts}) ---{style.RESET}")
        if not filtered_actions:
            print(f"  {style.DIM}(No actions found matching filter){style.RESET}")
        else:
            for a in filtered_actions:
                is_act = a.get("is_active", False)
                is_com = a.get("is_commented", False)
                cnt = a.get("usage_count", 0)
                is_sub = a.get("is_subarg", False)
                parent = a.get("parent")

                if is_act:
                    mark = f"{style.GREEN}[+]{style.RESET}"
                    cnt_str = f"{style.GREEN}({cnt}x){style.RESET}"
                    status_note = ""
                elif is_com:
                    mark = f"{style.YELLOW}[#]{style.RESET}"
                    cnt_str = f"{style.YELLOW}({cnt}x#){style.RESET}"
                    status_note = f" {style.YELLOW}[not active yet in linwinpwn]{style.RESET}"
                else:
                    mark = f"{style.DIM}[-]{style.RESET}"
                    cnt_str = "    "
                    status_note = ""

                alias_str = ""
                if len(a.get("flags", [])) > 1:
                    other_flags = [f for f in a["flags"] if f != a["name"]]
                    if other_flags:
                        alias_str = f" {style.DIM}(alias: {', '.join(other_flags)}){style.RESET}"

                if is_sub:
                    # Clean visual hierarchy for sub-arguments / modifiers
                    flags_label = ", ".join(a.get("flags", [a["name"]]))
                    tree_icon = "└── " if sys.stdout.encoding and "utf" in sys.stdout.encoding.lower() else "|-- "
                    name_display = f"   {tree_icon}{flags_label}"
                    sub_tag = f"[sub-arg for {parent}]" if parent else "[sub-arg]"
                    print(f"  {mark} {cnt_str:<8} {style.YELLOW}{name_display:<30}{style.RESET} {style.DIM}{sub_tag:<32}{style.RESET} {a['description']}{status_note}")
                else:
                    sec_tag = f"[{a['section']}]"
                    print(f"  {mark} {cnt_str:<8} {style.BOLD}{a['name']:<30}{style.RESET} {style.CYAN}{sec_tag:<32}{style.RESET} {a['description']}{alias_str}{status_note}")


def print_summary_table(all_results, linwinpwn_loaded, style):
    """Print executive summary table of NetExec features vs linWinPwn usage (excluding sub-arguments)"""
    print()
    print(f"{style.BOLD}{'='*80}{style.RESET}")
    print(f"{style.BOLD}EXECUTIVE SUMMARY & COVERAGE REPORT{style.RESET} {style.DIM}(Excluding sub-arguments; # = not active yet){style.RESET}")
    print(f"{style.BOLD}{'='*80}{style.RESET}")

    if linwinpwn_loaded:
        header = f"  {'Protocol':<12} {'Modules (Used/Total)':<24} {'Actions (Used/Total)':<24} {'Coverage':<10}"
        print(f"{style.BOLD}{header}{style.RESET}")
        print(f"  {'-'*12} {'-'*24} {'-'*24} {'-'*10}")

        total_mods_active = 0
        total_mods_commented = 0
        total_mods = 0
        total_acts_active = 0
        total_acts_commented = 0
        total_acts = 0

        for r in all_results:
            p_name = r["protocol"].upper()
            m_tot = len(r["modules"])
            m_act = sum(1 for m in r["modules"] if m.get("is_active", False))
            m_com = sum(1 for m in r["modules"] if m.get("is_commented", False))

            # Exclude sub-arguments from the coverage summary: count primary core actions only
            primary_acts = [a for a in r["core_actions"] if not a.get("is_subarg", False)]
            a_tot = len(primary_acts)
            a_act = sum(1 for a in primary_acts if a.get("is_active", False))
            a_com = sum(1 for a in primary_acts if a.get("is_commented", False))

            total_mods += m_tot
            total_mods_active += m_act
            total_mods_commented += m_com
            total_acts += a_tot
            total_acts_active += a_act
            total_acts_commented += a_com

            proto_items = m_tot + a_tot
            proto_used = m_act + a_act
            pct_val = (proto_used / proto_items * 100) if proto_items > 0 else 0.0
            pct_str = f"{pct_val:.1f}%" if proto_items > 0 else "N/A"

            m_com_str = f" (+{m_com}#)" if m_com else ""
            a_com_str = f" (+{a_com}#)" if a_com else ""
            m_str = f"{m_act:2d}{m_com_str} / {m_tot:2d}"
            a_str = f"{a_act:2d}{a_com_str} / {a_tot:2d}"

            print(f"  {style.BOLD}{p_name:<12}{style.RESET} {m_str:<24} {a_str:<24} {style.GREEN}{pct_str:<10}{style.RESET}")

        print(f"  {'-'*12} {'-'*24} {'-'*24} {'-'*10}")
        grand_items = total_mods + total_acts
        grand_used = total_mods_active + total_acts_active
        grand_pct = f"{(grand_used / grand_items * 100):.1f}%" if grand_items > 0 else "0.0%"
        m_tot_com_str = f" (+{total_mods_commented}#)" if total_mods_commented else ""
        a_tot_com_str = f" (+{total_acts_commented}#)" if total_acts_commented else ""
        m_tot_str = f"{total_mods_active:2d}{m_tot_com_str} / {total_mods:2d}"
        a_tot_str = f"{total_acts_active:2d}{a_tot_com_str} / {total_acts:2d}"

        print(f"  {style.BOLD}{'TOTAL':<12} {m_tot_str:<24} {a_tot_str:<24} {style.YELLOW}{grand_pct:<10}{style.RESET}")

        # Reverse integrity check summary across all protocols
        all_issues = []
        for r in all_results:
            p_name = r["protocol"].upper()
            for rm in r.get("removed_modules_used", []):
                all_issues.append((p_name, "Module", rm["name"], "REMOVED", rm.get("is_commented", False), rm.get("description", "Marked [REMOVED] in NetExec")))
            for nm in r.get("non_existent_modules", []):
                all_issues.append((p_name, "Module", nm["name"], "NOT FOUND", nm.get("is_commented", False), nm.get("description", "Module not found in NetExec -L")))
            for nf in r.get("non_existent_flags", []):
                all_issues.append((p_name, "Flag", nf["flag"], "NOT FOUND", nf.get("is_commented", False), nf.get("description", "Flag not found in NetExec --help")))

        print(f"\n  {style.BOLD}linWinPwn Integrity Check:{style.RESET}")
        if all_issues:
            print(f"  {style.RED}[!]{style.RESET} {style.BOLD}{len(all_issues)} issue(s) detected in linWinPwn.sh NetExec calls:{style.RESET}")
            for proto, itype, name, status, is_c, detail in all_issues:
                if is_c:
                    status_label = f"[{status} - inactive]"
                    status_colored = f"{style.YELLOW}{status_label:<22}{style.RESET}"
                    detail_str = f"{detail} (commented in linWinPwn.sh)"
                else:
                    status_label = f"[{status}]"
                    status_colored = (f"{style.YELLOW}{status_label:<22}{style.RESET}" if status == "REMOVED"
                                      else f"{style.RED}{status_label:<22}{style.RESET}")
                    detail_str = detail
                print(f"    - {style.BOLD}{proto:<7}{style.RESET} {itype:<7} {style.BOLD}{name:<24}{style.RESET} {status_colored} {style.DIM}{detail_str}{style.RESET}")
        else:
            print(f"  {style.GREEN}[+]{style.RESET} All NetExec modules & actions called in linWinPwn.sh are valid and active!")
    else:
        header = f"  {'Protocol':<12} {'Modules':<12} {'Actions':<12} {'Errors':<8}"
        print(f"{style.BOLD}{header}{style.RESET}")
        print(f"  {'-'*12} {'-'*12} {'-'*12} {'-'*8}")
        for r in all_results:
            p_name = r["protocol"].upper()
            m_tot = len(r["modules"])
            primary_acts = [a for a in r["core_actions"] if not a.get("is_subarg", False)]
            a_tot = len(primary_acts)
            err_cnt = len(r["errors"])
            print(f"  {p_name:<12} {m_tot:<12} {a_tot:<12} {err_cnt:<8}")

    print(f"{style.BOLD}{'='*80}{style.RESET}\n")



def main():
    parser = argparse.ArgumentParser(
        description="NetExec Module and Action Enumerator for linWinPwn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s                       # Enumerate all protocols cleanly
  %(prog)s -p ldap smb           # Enumerate only LDAP and SMB
  %(prog)s --missing             # Show only modules and actions NOT yet used in linWinPwn.sh
  %(prog)s --used                # Show only modules and actions currently used in linWinPwn.sh
  %(prog)s --modules-only        # Show only modules
  %(prog)s --actions-only        # Show only core actions
  %(prog)s --summary-only        # Show only executive summary table
  %(prog)s --integrity-only      # Show only non-existent / deprecated NetExec calls
  %(prog)s --netexec-cmd /path   # Specify custom path or command for netexec
""",
    )

    parser.add_argument("-p", "--protocols", nargs="+", choices=PROTOCOLS,
                        help="Specific protocols to enumerate (default: all)")
    parser.add_argument("--modules-only", action="store_true",
                        help="Only enumerate modules, skip core actions")
    parser.add_argument("--actions-only", action="store_true",
                        help="Only enumerate core actions, skip modules")
    parser.add_argument("--used", action="store_true",
                        help="Only show modules/actions used in linWinPwn.sh")
    parser.add_argument("--missing", action="store_true",
                        help="Only show modules/actions NOT used in linWinPwn.sh")
    parser.add_argument("--summary-only", action="store_true",
                        help="Only display summary table, skip per-item listing")
    parser.add_argument("--integrity-only", action="store_true",
                        help="Only show non-existent or deprecated NetExec calls in linWinPwn.sh")
    parser.add_argument("--no-check", action="store_true",
                        help="Skip checking linWinPwn.sh usage")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colored output")
    parser.add_argument("--netexec-cmd", type=str, default=None,
                        help="Path to netexec binary or command name")
    parser.add_argument("--linwinpwn-path", type=str, default=None,
                        help="Path to linWinPwn.sh file")
    parser.add_argument("--output-json", type=str, default=None,
                        help="Optional: save results to JSON file (disabled by default)")
    parser.add_argument("--output-md", type=str, default=None,
                        help="Optional: save results to Markdown file (disabled by default)")

    args = parser.parse_args()
    style = Style(enabled=not args.no_color)

    protocols_to_scan = args.protocols if args.protocols else PROTOCOLS

    print(f"{style.BOLD}{style.CYAN}{'='*80}{style.RESET}")
    print(f"{style.BOLD}{style.CYAN}NetExec Module & Action Enumerator for linWinPwn{style.RESET}")
    print(f"{style.DIM}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{style.RESET}")
    print(f"{style.BOLD}{style.CYAN}{'='*80}{style.RESET}")

    # Detect NetExec binary
    netexec_bin = find_netexec(args.netexec_cmd)
    if not netexec_bin:
        print(f"\n{style.RED}[!] NetExec binary not found.{style.RESET}")
        print("    Ensure netexec / nxc is installed (e.g. `pipx install netexec`)")
        print("    Or specify custom path via --netexec-cmd <path>")
        sys.exit(1)

    exec_prefix = get_exec_prefix(netexec_bin)

    # Check NetExec version
    v_out, _, v_code = run_command(f"{exec_prefix} --version")
    version_str = v_out.strip() if v_code == 0 and v_out.strip() else "available"
    print(f"[*] NetExec:   {style.GREEN}{netexec_bin}{style.RESET} {style.DIM}({version_str}){style.RESET}")

    # Load linWinPwn.sh content
    linwinpwn_content = ""
    proto_commands = {}
    linwinpwn_loaded = False
    if not args.no_check:
        linwinpwn_file = find_linwinpwn(args.linwinpwn_path)
        if linwinpwn_file and linwinpwn_file.is_file():
            try:
                linwinpwn_content = linwinpwn_file.read_text(encoding="utf-8", errors="ignore")
                proto_commands = extract_protocol_commands(linwinpwn_content)
                linwinpwn_loaded = True
                print(f"[*] linWinPwn: {style.GREEN}{linwinpwn_file}{style.RESET} {style.DIM}(loaded for analysis){style.RESET}")
            except Exception as e:
                print(f"[*] linWinPwn: {style.YELLOW}Error reading {linwinpwn_file}: {e}{style.RESET}")
        else:
            print(f"[*] linWinPwn: {style.YELLOW}linWinPwn.sh not found, skipping usage checks{style.RESET}")

    # Enumerate protocols
    all_results = []
    for protocol in protocols_to_scan:
        res = {
            "protocol": protocol,
            "modules": [],
            "removed_modules": [],
            "core_actions": [],
            "valid_flags": [],
            "non_existent_modules": [],
            "removed_modules_used": [],
            "non_existent_flags": [],
            "errors": [],
        }

        # Protocol-specific commands from linWinPwn.sh (separated into active and commented)
        proto_data = proto_commands.get(protocol, {"active": [], "commented": []})
        active_content = "\n".join(proto_data.get("active", []))
        commented_content = "\n".join(proto_data.get("commented", []))

        # 1. Enumerate Modules via `netexec <protocol> -L`
        if not args.actions_only:
            mod_cmd = f"{exec_prefix} {protocol} -L"
            m_out, m_err, m_code = run_command(mod_cmd)
            if m_out:
                modules, removed_modules = parse_modules(m_out)
                if linwinpwn_loaded:
                    for mod in modules:
                        in_act, cnt_act = check_module_usage(mod["name"], active_content)
                        in_com, cnt_com = check_module_usage(mod["name"], commented_content)
                        if cnt_act > 0:
                            mod["in_linwinpwn"] = True
                            mod["is_active"] = True
                            mod["is_commented"] = False
                            mod["usage_count"] = cnt_act
                        elif cnt_com > 0:
                            mod["in_linwinpwn"] = True
                            mod["is_active"] = False
                            mod["is_commented"] = True
                            mod["usage_count"] = cnt_com
                        else:
                            mod["in_linwinpwn"] = False
                            mod["is_active"] = False
                            mod["is_commented"] = False
                            mod["usage_count"] = 0
                res["modules"] = modules
                res["removed_modules"] = removed_modules
            elif m_err and "traceback" in m_err.lower():
                res["errors"].append(f"Modules: {m_err.strip().splitlines()[-1]}")

        # 2. Enumerate Core Actions via `netexec <protocol> --help`
        if not args.modules_only:
            help_cmd = f"{exec_prefix} {protocol} --help"
            h_out, h_err, h_code = run_command(help_cmd)
            if h_out:
                actions, valid_flags = parse_actions(h_out)
                if linwinpwn_loaded:
                    for act in actions:
                        in_act, cnt_act, flags_act = check_action_usage(act["flags"], active_content)
                        in_com, cnt_com, flags_com = check_action_usage(act["flags"], commented_content)
                        if cnt_act > 0:
                            act["in_linwinpwn"] = True
                            act["is_active"] = True
                            act["is_commented"] = False
                            act["usage_count"] = cnt_act
                            act["matched_flags"] = flags_act
                        elif cnt_com > 0:
                            act["in_linwinpwn"] = True
                            act["is_active"] = False
                            act["is_commented"] = True
                            act["usage_count"] = cnt_com
                            act["matched_flags"] = flags_com
                        else:
                            act["in_linwinpwn"] = False
                            act["is_active"] = False
                            act["is_commented"] = False
                            act["usage_count"] = 0
                            act["matched_flags"] = []
                res["core_actions"] = actions
                res["valid_flags"] = sorted(list(valid_flags))
            elif h_err and "traceback" in h_err.lower():
                res["errors"].append(f"Actions: {h_err.strip().splitlines()[-1]}")

        # 3. Check for non-existent or deprecated features called in linWinPwn.sh
        if linwinpwn_loaded and (active_content or commented_content):
            # Check modules if modules were enumerated
            if res["modules"] or res["removed_modules"]:
                active_mod_map = {m["name"].lower(): m["name"] for m in res["modules"]}
                active_mod_norm = {m["name"].lower().replace("_", "-"): m["name"] for m in res["modules"]}
                removed_mod_map = {m["name"].lower(): m for m in res["removed_modules"]}
                removed_mod_norm = {m["name"].lower().replace("_", "-"): m for m in res["removed_modules"]}

                lwp_act_mods = extract_linwinpwn_protocol_modules(active_content)
                lwp_com_mods = extract_linwinpwn_protocol_modules(commented_content)

                seen_mods = set()
                # Active calls
                for lwp_mod in lwp_act_mods:
                    lwp_lower = lwp_mod.lower()
                    lwp_norm = lwp_lower.replace("_", "-")
                    seen_mods.add(lwp_lower)

                    if lwp_lower in active_mod_map or lwp_norm in active_mod_norm:
                        continue
                    elif lwp_lower in removed_mod_map or lwp_norm in removed_mod_norm:
                        rm_entry = removed_mod_map.get(lwp_lower) or removed_mod_norm.get(lwp_norm)
                        res["removed_modules_used"].append({
                            "name": lwp_mod,
                            "is_commented": False,
                            "description": rm_entry.get("description", "Marked [REMOVED] in NetExec"),
                        })
                    else:
                        res["non_existent_modules"].append({
                            "name": lwp_mod,
                            "is_commented": False,
                            "description": f"Module '{lwp_mod}' not found in NetExec {protocol} module list (-L)",
                        })

                # Commented calls (if not already recorded)
                for lwp_mod in lwp_com_mods:
                    lwp_lower = lwp_mod.lower()
                    if lwp_lower in seen_mods:
                        continue
                    seen_mods.add(lwp_lower)
                    lwp_norm = lwp_lower.replace("_", "-")

                    if lwp_lower in active_mod_map or lwp_norm in active_mod_norm:
                        continue
                    elif lwp_lower in removed_mod_map or lwp_norm in removed_mod_norm:
                        rm_entry = removed_mod_map.get(lwp_lower) or removed_mod_norm.get(lwp_norm)
                        res["removed_modules_used"].append({
                            "name": lwp_mod,
                            "is_commented": True,
                            "description": rm_entry.get("description", "Marked [REMOVED] in NetExec"),
                        })
                    else:
                        res["non_existent_modules"].append({
                            "name": lwp_mod,
                            "is_commented": True,
                            "description": f"Module '{lwp_mod}' not found in NetExec {protocol} module list (-L)",
                        })

            # Check flags if help was enumerated
            if res.get("valid_flags"):
                valid_flags_lower = {f.lower() for f in res["valid_flags"]}
                lwp_act_flags = extract_linwinpwn_protocol_flags(active_content)
                lwp_com_flags = extract_linwinpwn_protocol_flags(commented_content)
                ignored_flags = {"--module", "--help"}

                seen_flags = set()
                # Active flags
                for lwp_flag in lwp_act_flags:
                    fl_lower = lwp_flag.lower()
                    if fl_lower in ignored_flags:
                        continue
                    seen_flags.add(fl_lower)
                    if fl_lower not in valid_flags_lower:
                        res["non_existent_flags"].append({
                            "flag": lwp_flag,
                            "is_commented": False,
                            "description": f"Flag '{lwp_flag}' not found in NetExec {protocol} options (--help)",
                        })

                # Commented flags
                for lwp_flag in lwp_com_flags:
                    fl_lower = lwp_flag.lower()
                    if fl_lower in ignored_flags or fl_lower in seen_flags:
                        continue
                    seen_flags.add(fl_lower)
                    if fl_lower not in valid_flags_lower:
                        res["non_existent_flags"].append({
                            "flag": lwp_flag,
                            "is_commented": True,
                            "description": f"Flag '{lwp_flag}' not found in NetExec {protocol} options (--help)",
                        })

        all_results.append(res)

        if not args.summary_only:
            print_protocol_results(res, style, args)

    # Executive Summary Table
    print_summary_table(all_results, linwinpwn_loaded, style)

    # Output to file ONLY if explicitly requested
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
            print(f"[+] Results saved to JSON: {args.output_json}")
        except Exception as e:
            print(f"[!] Failed to write JSON file: {e}")

    if args.output_md:
        try:
            with open(args.output_md, "w", encoding="utf-8") as f:
                f.write(f"# NetExec Modules and Core Actions\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("| Protocol | Modules | Actions |\n|---|---|---|\n")
                for r in all_results:
                    f.write(f"| {r['protocol'].upper()} | {len(r['modules'])} | {len(r['core_actions'])} |\n")

                all_issues = []
                for r in all_results:
                    p_name = r["protocol"].upper()
                    for rm in r.get("removed_modules_used", []):
                        all_issues.append((p_name, "Module", rm["name"], "REMOVED", rm.get("is_commented", False), rm.get("description", "")))
                    for nm in r.get("non_existent_modules", []):
                        all_issues.append((p_name, "Module", nm["name"], "NOT FOUND", nm.get("is_commented", False), nm.get("description", "")))
                    for nf in r.get("non_existent_flags", []):
                        all_issues.append((p_name, "Flag", nf["flag"], "NOT FOUND", nf.get("is_commented", False), nf.get("description", "")))

                if all_issues:
                    f.write("\n## Integrity Issues Detected in linWinPwn.sh\n\n")
                    f.write("| Protocol | Type | Item | Status | Detail |\n|---|---|---|---|---|\n")
                    for proto, itype, name, status, is_c, detail in all_issues:
                        stat_label = f"**{status} (inactive)**" if is_c else f"**{status}**"
                        det = f"{detail} (commented out)" if is_c else detail
                        f.write(f"| {proto} | {itype} | `{name}` | {stat_label} | {det} |\n")
            print(f"[+] Results saved to Markdown: {args.output_md}")
        except Exception as e:
            print(f"[!] Failed to write Markdown file: {e}")


if __name__ == "__main__":
    main()