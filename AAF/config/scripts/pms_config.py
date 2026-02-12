"""
config.py: Configuration management for the AndroidServiceFuzzer framework.

This module handles loading, validating, and providing access to configuration
settings from a YAML file. It ensures all required keys are present and provides
type-safe access to config values. Errors are handled gracefully with logging.
"""

import logging
import yaml
from pathlib import Path
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, config_path: str = './config/config.yaml'):
        self.config_path = Path(config_path).resolve()
        self.config: Dict[str, Any] = self._load_config()
        self._validate_config()
        logger.error(f"Configuration file @ path: {self.config_path}")

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            logger.error(f"Configuration file not found: {self.config_path}")
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            if not isinstance(config, dict):
                raise ValueError("Configuration must be a dictionary.")
            logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in configuration file: {e}")
            raise

    def _validate_config(self) -> None:
        """
        Validate the loaded configuration for required keys and types.

        :raises ValueError: If validation fails.
        """
        required_keys = {
            'adb_path': str,
            'service': str,
            'max_tx': int,
            'iterations': int,
            'output_dir': str,
            'timeout': int,
            'reboot_on_fatal': bool,
            'users': list,
            'system_uids': list,
            'priv_perms': list,
            'known_pkgs': list,
        }

        for key, expected_type in required_keys.items():
            if key not in self.config:
                raise ValueError(f"Missing required configuration key: {key}")
            value = self.config[key]
            if not isinstance(value, expected_type):
                raise ValueError(f"Configuration key '{key}' must be of type {expected_type.__name__}, got {type(value).__name__}")
            if expected_type == list:
                if not all(isinstance(item, str) for item in value) and key not in ['users', 'system_uids']:
                    raise ValueError(f"All items in '{key}' must be strings.")
                if key == 'users' and not all(isinstance(item, int) for item in value):
                    raise ValueError(f"All items in 'users' must be integers.")
                if key == 'system_uids' and not all(isinstance(item, int) for item in value):
                    raise ValueError(f"All items in 'system_uids' must be integers.")

        # Ensure service is 'package' for PMS targeting
        if self.config['service'] != 'package':
            raise ValueError("Service must be 'package' for PMS targeting.")

        logger.info("Configuration validated successfully.")

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        :param key: The configuration key.
        :param default: Default value if key is not found.
        :return: The configuration value or default.
        """
        return self.config.get(key, default)

    def get_str(self, key: str, default: str = '') -> str:
        """
        Get a string configuration value.

        :param key: The configuration key.
        :param default: Default value if key is not found.
        :return: The string value.
        :raises ValueError: If the value is not a string.
        """
        value = self.get(key, default)
        if not isinstance(value, str):
            raise ValueError(f"Configuration key '{key}' must be a string.")
        return value

    def get_int(self, key: str, default: int = 0) -> int:
        """
        Get an integer configuration value.

        :param key: The configuration key.
        :param default: Default value if key is not found.
        :return: The integer value.
        :raises ValueError: If the value is not an integer.
        """
        value = self.get(key, default)
        if not isinstance(value, int):
            raise ValueError(f"Configuration key '{key}' must be an integer.")
        return value

    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Get a boolean configuration value.

        :param key: The configuration key.
        :param default: Default value if key is not found.
        :return: The boolean value.
        :raises ValueError: If the value is not a boolean.
        """
        value = self.get(key, default)
        if not isinstance(value, bool):
            raise ValueError(f"Configuration key '{key}' must be a boolean.")
        return value

    def get_list(self, key: str, default: List[Any] = None) -> List[Any]:
        """
        Get a list configuration value.

        :param key: The configuration key.
        :param default: Default value if key is not found.
        :return: The list value.
        :raises ValueError: If the value is not a list.
        """
        if default is None:
            default = []
        value = self.get(key, default)
        if not isinstance(value, list):
            raise ValueError(f"Configuration key '{key}' must be a list.")
        return value

    def update(self, key: str, value: Any) -> None:
        """
        Update a configuration value.

        :param key: The configuration key to update.
        :param value: The new value.
        """
        if key in self.config:
            self.config[key] = value
            logger.info(f"Updated configuration key '{key}' to {value}")
        else:
            logger.warning(f"Attempted to update non-existent key '{key}'")