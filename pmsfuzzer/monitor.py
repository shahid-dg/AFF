"""
monitor.py: Monitoring module for the AndroidServiceFuzzer framework.

This module handles system health checks, state snapshots, log collection, and output file management.
It tracks log signatures for novelty detection and writes results to JSONL and log files.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple

from config import ConfigManager
from executor import Executor

logger = logging.getLogger(__name__)

class Monitor:
    def __init__(self, config: ConfigManager, executor: Executor):
        """
        Initialize the Monitor.

        :param config: The ConfigManager instance.
        :param executor: The Executor instance.
        """
        self.config = config
        self.executor = executor
        self.output_dir: Path = Path(config.get_str('output_dir'))
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.results_file: Path = self.output_dir / "cases.jsonl"
        self.findings_file: Path = self.output_dir / "findings.jsonl"
        self.crashes_file: Path = self.output_dir / "crashes.log"
        self.seen_log_sigs: set[str] = set()  # MD5 hashes of log lines

    def system_server_alive(self) -> bool:
        """
        Check if the system_server process is alive.

        :return: True if alive, False otherwise.
        """
        result = self.executor.adb(["shell", "pidof", "system_server"])
        if result and result.returncode == 0:
            pid = result.stdout.strip()
            return bool(pid and pid.isdigit())
        logger.warning("Failed to check system_server alive")
        return False

    def snapshot_package(self, pkg: str) -> Dict[str, Any]:
        """
        Take a snapshot of a package's state.

        :param pkg: Package name.
        :return: Dictionary with package details.
        """
        snapshot = {
            "pkg": pkg,
            "dump": "",
            "uid": "",
            "path": "",
        }
        try:
            dump_res = self.executor.adb(["shell", "dumpsys", "package", pkg])
            if dump_res and dump_res.returncode == 0:
                snapshot["dump"] = dump_res.stdout

            uid_res = self.executor.adb(["shell", "cmd", "package", "get-package-uid", pkg])
            if uid_res and uid_res.returncode == 0:
                snapshot["uid"] = uid_res.stdout.strip()

            path_res = self.executor.adb(["shell", "pm", "path", pkg])
            if path_res and path_res.returncode == 0:
                snapshot["path"] = path_res.stdout.strip()

            logger.debug(f"Snapshot taken for package: {pkg}")
            return snapshot
        except Exception as e:
            logger.error(f"Error taking package snapshot for {pkg}: {e}")
            return snapshot

    def snapshot_global_state(self) -> Dict[str, str]:
        """
        Take a snapshot of global system state files.

        :return: Dictionary with file contents.
        """
        state = {
            "packages_xml": "",
            "runtime_perm": "",
        }
        try:
            pkgs_res = self.executor.adb(["shell", "cat", "/data/system/packages.xml"])
            if pkgs_res and pkgs_res.returncode == 0:
                state["packages_xml"] = pkgs_res.stdout

            perm_res = self.executor.adb(["shell", "cat", "/data/system/users/0/runtime-permissions.xml"])
            if perm_res and perm_res.returncode == 0:
                state["runtime_perm"] = perm_res.stdout

            logger.debug("Global state snapshot taken")
            return state
        except Exception as e:
            logger.error(f"Error taking global state snapshot: {e}")
            return state

    def collect_logs(self) -> Tuple[int, str]:
        """
        Collect error logs from system and crash buffers, calculate novelty.

        :return: Tuple of (novelty count, full logs).
        """
        try:
            result = self.executor.adb(["logcat", "-d", "-b", "system,crash", "*:E"])
            if result and result.returncode == 0:
                logs = result.stdout
                sigs = set()
                for line in logs.splitlines():
                    if "PackageManager" in line or "system_server" in line:
                        sig = hashlib.md5(line.encode('utf-8')).hexdigest()
                        sigs.add(sig)
                novelty = sigs - self.seen_log_sigs
                self.seen_log_sigs.update(novelty)
                logger.debug(f"Collected logs with {len(novelty)} novel entries")
                return len(novelty), logs
            else:
                logger.warning("Failed to collect logs")
                return 0, ""
        except Exception as e:
            logger.error(f"Error collecting logs: {e}")
            return 0, ""

    def clear_logs(self) -> None:
        """
        Clear the logcat buffers.
        """
        try:
            result = self.executor.adb(["logcat", "-c"])
            if result and result.returncode == 0:
                logger.debug("Logs cleared")
            else:
                logger.warning("Failed to clear logs")
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")