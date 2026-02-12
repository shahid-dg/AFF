"""
config_editor.py (updated)

Added support for optional auto-sync disable via config flag:
    auto_sync_plugins: true/false

The auto_sync_plugins() function now respects this flag.
If disabled, it logs and skips synchronization.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Dict, Any, List, Tuple
import yaml

logging.getLogger(__name__).addHandler(logging.NullHandler())
logger = logging.getLogger(__name__)

CONFIG_PATH = Path("./config/config.yaml")
INVARIANTS_PATH = Path("./plugins/invariants")
MUTATIONS_PATH = Path("./plugins/mutations")

def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        logger.error(f"Config file not found: {CONFIG_PATH}")
        raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")
    
    with CONFIG_PATH.open('r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}
    
    if not isinstance(config, dict):
        raise ValueError("Invalid config.yaml format")
    
    logger.debug(f"Config loaded from {CONFIG_PATH}")
    return config

def save_config(config: Dict[str, Any]) -> None:
    try:
        with CONFIG_PATH.open('w', encoding='utf-8') as f:
            yaml.safe_dump(config, f, sort_keys=False, allow_unicode=True, indent=2)
        logger.info(f"Config saved to {CONFIG_PATH}")
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        raise

def save_config_if_changed(new_config: Dict[str, Any]) -> bool:
    try:
        current = load_config()
        if current == new_config:
            logger.debug("Config unchanged – no save needed")
            return False
        
        save_config(new_config)
        return True
    except Exception:
        save_config(new_config)
        return True

def discover_plugins() -> Dict[str, List[str]]:
    discovered: Dict[str, List[str]] = {'invariants': [], 'mutations': []}
    
    categories = [
        ('invariants', INVARIANTS_PATH, "plugins.invariants"),
        ('mutations', MUTATIONS_PATH, "plugins.mutations"),
    ]
    
    for cat_name, cat_path, namespace in categories:
        if not cat_path.is_dir():
            logger.debug(f"Category directory missing: {cat_path}")
            continue
        
        for module_info in pkgutil.iter_modules([str(cat_path)]):
            if module_info.ispkg or module_info.name == "base":
                continue
            
            full_name = f"{namespace}.{module_info.name}"
            try:
                module = importlib.import_module(full_name)
                base_class_name = "InvariantPlugin" if cat_name == "invariants" else "MutationPlugin"
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and hasattr(attr, "name")
                        and attr_name != base_class_name
                    ):
                        plugin_name = attr.name.strip()
                        if plugin_name and plugin_name not in discovered[cat_name]:
                            discovered[cat_name].append(plugin_name)
            except Exception as e:
                logger.warning(f"Failed to inspect module {full_name}: {e}")
    
    total = sum(len(v) for v in discovered.values())
    logger.info(f"Plugin discovery: {total} total ({dict((k, len(v)) for k, v in discovered.items())})")
    return discovered

def sync_plugins() -> Tuple[int, bool]:
    config = load_config()
    plugins_section = config.setdefault('plugins', {})
    enabled_section = plugins_section.setdefault('enabled', {})
    
    discovered = discover_plugins()
    added_count = 0
    
    for cat, names in discovered.items():
        prefix = "mutations." if cat == "mutations" else ""
        for name in names:
            key = f"{prefix}{name.lower()}"
            if key not in enabled_section:
                enabled_section[key] = True
                added_count += 1
                logger.info(f"Added missing plugin: {key} = true")
            else:
                logger.debug(f"Plugin already configured: {key}")
    
    saved = False
    if added_count > 0:
        saved = save_config_if_changed(config)
    
    return added_count, saved

def auto_sync_plugins() -> None:
    """
    Automatic plugin sync with optional disable via config flag.
    Respects config.auto_sync_plugins (default: true if missing).
    """
    config = load_config()
    if not config.get('auto_sync_plugins', True):
        logger.info("Auto-sync disabled in config (auto_sync_plugins: false)")
        return
    
    added, saved = sync_plugins()
    if added == 0:
        logger.info("Plugin config is up to date")
    elif saved:
        logger.info(f"Auto-synced {added} new plugin(s) to config.yaml")
    else:
        logger.info(f"Detected {added} new plugin(s) but config unchanged")

__all__ = [
    "load_config",
    "save_config",
    "save_config_if_changed",
    "discover_plugins",
    "sync_plugins",
    "auto_sync_plugins",
]