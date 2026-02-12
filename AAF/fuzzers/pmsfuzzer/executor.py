"""
executor.py: Execution module for the AndroidServiceFuzzer framework.

This module handles running ADB commands, discovering transactions, executing fuzz cases,
and restarting the framework if needed. It supports complex argument types including parcels
by serializing them into the required format for 'service call'. Supports array serialization in parcels.
"""

import subprocess
import time
import logging
from typing import List, Tuple, Any, Optional

from AAF.config.scripts.pms_config import ConfigManager

logger = logging.getLogger(__name__)

class Executor:
    def __init__(self, config: ConfigManager):
        """
        Initialize the Executor.

        :param config: The ConfigManager instance.
        """
        self.adb_path: str = config.get_str('adb_path')
        self.service: str = config.get_str('service')
        self.timeout: int = config.get_int('timeout')
        self.max_tx: int = config.get_int('max_tx')

    def adb(self, cmd: List[str], timeout: Optional[int] = None) -> Optional[subprocess.CompletedProcess]:
        """
        Run an ADB command.

        :param cmd: The ADB command arguments.
        :param timeout: Optional timeout in seconds.
        :return: The CompletedProcess or None on timeout.
        """
        timeout = timeout or self.timeout
        full_cmd = [self.adb_path] + cmd
        try:
            result = subprocess.run(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False
            )
            if result.returncode != 0:
                logger.warning(f"ADB command failed (rc={result.returncode}): {' '.join(full_cmd)} - stderr: {result.stderr.strip()}")
            else:
                logger.debug(f"ADB command succeeded: {' '.join(full_cmd)}")
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"ADB timeout after {timeout}s: {' '.join(full_cmd)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error running ADB: {e}")
            return None

    def discover_transactions(self) -> List[int]:
        """
        Discover valid transaction codes for the service.

        :return: List of valid transaction IDs.
        """
        valid = []
        for tx in range(1, self.max_tx + 1):
            r = self.adb(["shell", "service", "call", self.service, str(tx)], timeout=2)
            if r and r.returncode == 0 and "Parcel(" in r.stdout and "Exception" not in r.stdout:
                valid.append(tx)
        logger.info(f"Discovered {len(valid)} valid transactions")
        return valid

    def run_case(self, tx: int, args: List[Tuple[str, Any]]) -> Optional[subprocess.CompletedProcess]:
        """
        Run a fuzz case by calling the service with the given transaction and arguments.

        :param tx: Transaction ID.
        :param args: List of (type, value), where type can be 's16', 'i32', 'i64', 'null', 'parcel'.
                     For 'parcel', value is list of (sub_type, sub_value), supporting arrays like ('s16[]', list[str]).
        :return: The CompletedProcess from ADB or None on error.
        """
        cmd = ["shell", "service", "call", self.service, str(tx)]
        try:
            for arg_type, value in args:
                if arg_type in ('s16', 'i32', 'i64'):
                    cmd += [arg_type, str(value)]
                elif arg_type == 'null':
                    cmd += ['null']
                elif arg_type == 'parcel':
                    if not isinstance(value, list):
                        raise ValueError("Parcel value must be a list of (sub_type, sub_value)")
                    parcel_bytes = self._serialize_parcel(value)
                    hex_str = parcel_bytes.hex()
                    cmd += ['parcel', str(len(parcel_bytes)), hex_str]
                else:
                    raise ValueError(f"Unsupported arg_type: {arg_type}")

            logger.debug(f"Executing service call: {' '.join(cmd)}")
            result = self.adb(cmd)
            time.sleep(0.4)  # Allow time for effects to settle
            return result
        except ValueError as e:
            logger.error(f"Invalid argument in run_case for tx {tx}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in run_case for tx {tx}: {e}")
            return None

    def _serialize_parcel(self, sub_args: List[Tuple[str, Any]]) -> bytearray:
        """
        Serialize a list of (type, value) into a parcel bytearray. Supports arrays with length prefix.

        :param sub_args: List of (sub_type, sub_value), e.g., ('i32', 5), ('s16[]', ['str1', 'str2']).
        :return: Bytearray of the serialized parcel.
        """
        parcel = bytearray()
        for sub_type, sub_value in sub_args:
            if sub_type.endswith('[]'):
                base_type = sub_type[:-2]
                if not isinstance(sub_value, list):
                    raise ValueError(f"Array value must be a list for {sub_type}")
                length = len(sub_value)
                parcel.extend(length.to_bytes(4, 'little', signed=False))
                for v in sub_value:
                    if base_type == 'i32':
                        parcel.extend(int(v).to_bytes(4, 'little', signed=True))
                    elif base_type == 'i64':
                        parcel.extend(int(v).to_bytes(8, 'little', signed=True))
                    elif base_type == 's16':
                        self._write_string(parcel, str(v))
                    else:
                        raise ValueError(f"Unsupported base_type for array: {base_type}")
            else:
                if sub_type == 'i32':
                    parcel.extend(int(sub_value).to_bytes(4, 'little', signed=True))
                elif sub_type == 'i64':
                    parcel.extend(int(sub_value).to_bytes(8, 'little', signed=True))
                elif sub_type == 's16':
                    self._write_string(parcel, str(sub_value))
                else:
                    raise ValueError(f"Unsupported sub_type: {sub_type}")

        # Pad to 4-byte alignment if necessary
        while len(parcel) % 4 != 0:
            parcel.append(0)

        return parcel

    def _write_string(self, parcel: bytearray, s: Optional[str]) -> None:
        """
        Write a string to the parcel in Android's String16 format.

        :param parcel: The bytearray to write to.
        :param s: The string to write, or None.
        """
        if s is None:
            parcel.extend((-1).to_bytes(4, 'little', signed=True))
            return
        try:
            bytes_s = s.encode('utf-16le')
        except UnicodeEncodeError:
            bytes_s = ''.encode('utf-16le')  # Fallback to empty
        len_chars = len(bytes_s) // 2
        parcel.extend(len_chars.to_bytes(4, 'little', signed=False))
        parcel.extend(bytes_s)
        parcel.extend(b'\x00\x00')  # Null terminator for UTF-16

    def restart_framework(self) -> None:
        """
        Restart the Android framework services.
        """
        logger.info("Restarting framework")
        self.adb(["shell", "stop"])
        time.sleep(1)
        self.adb(["shell", "start"])
        time.sleep(4)
        logger.info("Framework restarted")