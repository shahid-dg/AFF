"""
analyzer.py: Analysis module for the AndroidServiceFuzzer framework.

Performs core invariant checks, differential analysis, plugin-based extensions,
case scoring, and result logging.
"""

import difflib
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple
from config import ConfigManager
from monitor import Monitor
from plugins.loader import get_plugin_loader  # <-- NEW: dynamic loader

logger = logging.getLogger(__name__)

class Analyzer:
    def __init__(self, config: ConfigManager, monitor: Monitor):
        self.config = config
        self.monitor = monitor
        self.priv_perms: List[str] = config.get_list('priv_perms')
        self.reboot_on_fatal: bool = config.get_bool('reboot_on_fatal')

        # Load enabled invariant plugins dynamically
        self.plugin_loader = get_plugin_loader(config)
        self.invariant_plugins = self.plugin_loader.get_enabled_invariant_plugins()

        logger.info(f"Analyzer initialized with {len(self.invariant_plugins)} enabled invariant plugin(s)")

    def invariant_checks(self, before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Core built-in package invariant checks (kept separate for clarity)"""
        issues = []

        if before.get("uid", "") != after.get("uid", ""):
            issues.append({
                "type": "UID_CHANGE",
                "from": before["uid"],
                "to": after["uid"]
            })

        before_dump = before.get("dump", "")
        after_dump = after.get("dump", "")
        for perm in self.priv_perms:
            if perm not in before_dump and perm in after_dump:
                issues.append({
                    "type": "PRIV_PERMISSION_GAIN",
                    "perm": perm
                })

        before_path = before.get("path", "")
        after_path = after.get("path", "")
        if "/system/" not in before_path and "/system/" in after_path:
            issues.append({
                "type": "SYSTEM_PARTITION_ESCALATION"
            })

        return issues

    def differential_global_state(self, before: Dict[str, str], after: Dict[str, str]) -> List[Dict[str, Any]]:
        """Core differential checks on global XML files"""
        issues = []
        for key in before:
            if key in after and before[key] != after[key]:
                diff = list(difflib.unified_diff(
                    before[key].splitlines(), after[key].splitlines(), lineterm=''
                ))
                if diff:
                    issues.append({
                        "type": "GLOBAL_STATE_CHANGE",
                        "key": key,
                        "diff_preview": '\n'.join(diff[:20])  # truncate for log size
                    })
        return issues

    def analyze_case(
        self,
        tx: int,
        pkg: str,
        args: List[Tuple[str, Any]],
        before_pkg: Dict[str, Any],
        after_pkg: Dict[str, Any],
        before_global: Dict[str, str],
        after_global: Dict[str, str],
        alive: bool,
        novelty: int,
        logs: str
    ) -> Tuple[float, Dict[str, Any]]:
        # Core checks
        core_pkg_issues = self.invariant_checks(before_pkg, after_pkg)
        core_global_issues = self.differential_global_state(before_global, after_global)

        # Plugin-based checks
        plugin_issues: List[Dict[str, Any]] = []
        for plugin in self.invariant_plugins:
            try:
                issues = plugin.check(before_pkg, after_pkg, before_global, after_global)
                if issues:
                    plugin_issues.extend(issues)
                    logger.debug(f"Plugin '{plugin.name}' reported {len(issues)} issue(s)")
            except Exception as e:
                logger.error(f"Invariant plugin '{plugin.name}' crashed during check: {e}", exc_info=True)

        all_issues = core_pkg_issues + core_global_issues + plugin_issues

        # Serialize args safely for JSON
        serial_args = []
        for arg_type, value in args:
            if arg_type == 'parcel':
                serial_args.append((arg_type, "parcel_with_subargs"))
            else:
                serial_args.append((arg_type, value))

        case: Dict[str, Any] = {
            "time": datetime.utcnow().isoformat(),
            "tx": tx,
            "pkg": pkg,
            "args": serial_args,
            "alive": alive,
            "novel_log_count": novelty,
            "issues": all_issues,
        }

        cid = hashlib.sha256(json.dumps(case, sort_keys=True).encode('utf-8')).hexdigest()
        case["id"] = cid

        # Write results
        try:
            with self.monitor.results_file.open("a", encoding='utf-8') as f:
                f.write(json.dumps(case) + "\n")

            if all_issues:
                with self.monitor.findings_file.open("a", encoding='utf-8') as f:
                    f.write(json.dumps(case, indent=2) + "\n")
                logger.info(f"Findings in case {cid}: {len(all_issues)} issue(s)")

            if not alive:
                with self.monitor.crashes_file.open("a", encoding='utf-8') as f:
                    f.write(f"\n=== SYSTEM_SERVER_CRASH {cid} ===\n{logs}\n")
                logger.warning(f"System server crash detected: {cid}")
                if self.reboot_on_fatal:
                    self.monitor.executor.restart_framework()

            score = novelty + len(all_issues) * 5 + (50 if not alive else 0)  # weighted scoring
            return score, case

        except IOError as e:
            logger.error(f"Failed to write case {cid}: {e}")
            return 0.0, case