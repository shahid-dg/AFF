# Updated plugins/loader.py (supports multiple categories)
"""
plugins/loader.py

Enhanced dynamic plugin loader supporting multiple plugin types:
- invariants
- mutations
(future: snapshots, reporters, etc.)

Discovers namespaces dynamically and loads enabled plugins per category.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import List, Dict, Optional, Any
from AAF.config.scripts.pms_config import ConfigManager
from .invariants.base import InvariantPlugin
from .mutations.base import MutationPlugin  # New category
from config_editor import auto_sync_plugins


logger = logging.getLogger(__name__)


class PluginLoader:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.enabled_map: Dict[str, Dict[str, bool]] = self._load_plugin_config()
        self.invariant_plugins: List[InvariantPlugin] = []
        self.mutation_plugins: List[MutationPlugin] = []
        auto_sync_plugins()
        self._discover_and_load_all()


    def _load_plugin_config(self) -> Dict[str, Dict[str, bool]]:
        plugins_section = self.config.get('plugins', {})
        enabled = plugins_section.get('enabled', {})
        categories = {'invariants': {}, 'mutations': {}}

        for key, val in enabled.items():
            parts = key.split('.', 1)
            if len(parts) == 2:
                cat, name = parts
                if cat in categories:
                    categories[cat][name.lower()] = bool(val)
            else:
                # Backward compatibility: assume invariants
                categories['invariants'][key.lower()] = bool(val)

        logger.debug(f"Plugin config map: {categories}")
        return categories

    def _discover_and_load_all(self) -> None:
        base_path = Path(__file__).parent
        categories = [
            ('invariants', InvariantPlugin, self.invariant_plugins),
            ('mutations', MutationPlugin, self.mutation_plugins),
        ]

        for cat_name, base_cls, target_list in categories:
            cat_path = base_path / cat_name
            if not cat_path.is_dir():
                logger.warning(f"Plugin category directory missing: {cat_path}")
                continue

            discovered = 0
            loaded = 0
            enabled_for_cat = self.enabled_map.get(cat_name, {})

            for module_info in pkgutil.iter_modules([str(cat_path)]):
                if module_info.ispkg:
                    continue

                module_name = module_info.name
                full_name = f"plugins.{cat_name}.{module_name}"

                try:
                    module = importlib.import_module(full_name)
                    discovered += 1

                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, base_cls)
                            and attr is not base_cls
                            and hasattr(attr, "name")
                        ):
                            plugin_name = attr.name.strip().lower()
                            if enabled_for_cat.get(plugin_name, False):
                                try:
                                    instance = attr()
                                    target_list.append(instance)
                                    loaded += 1
                                    logger.info(f"Loaded {cat_name[:-1]} plugin: {attr.name} from {full_name}")
                                except Exception as e:
                                    logger.error(f"Failed to instantiate {cat_name[:-1]} plugin {attr.name}: {e}", exc_info=True)
                            else:
                                logger.debug(f"{cat_name[:-1].capitalize()} plugin {plugin_name} disabled")

                except Exception as e:
                    logger.error(f"Failed to load module {full_name}: {e}", exc_info=True)

            target_list.sort(key=lambda p: p.priority(), reverse=True)
            logger.info(f"{cat_name.capitalize()}: {discovered} modules, {loaded} enabled plugins loaded")

    def get_enabled_invariant_plugins(self) -> List[InvariantPlugin]:
        return self.invariant_plugins

    def get_enabled_mutation_plugins(self) -> List[MutationPlugin]:
        return self.mutation_plugins


_plugin_loader_instance: Optional[PluginLoader] = None

def get_plugin_loader(config: ConfigManager) -> PluginLoader:
    global _plugin_loader_instance
    if _plugin_loader_instance is None:
        _plugin_loader_instance = PluginLoader(config)
    return _plugin_loader_instance