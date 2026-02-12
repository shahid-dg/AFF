"""
generator.py: Input generation module for the AndroidServiceFuzzer framework.

This module handles generating fuzz inputs for PMS transactions, including random generation,
mutation of seeds, and grammar-based constraints. It persists seeds to a JSON file for
feedback-guided fuzzing. The grammar is based on Android 13's IPackageManager.aidl.
Supports array generation and parcel serialization for arrays.
"""

import json
import logging
import random
import string
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config import ConfigManager  # Assuming config.py is in the same directory

logger = logging.getLogger(__name__)

class InputGenerator:
    def __init__(self, config: ConfigManager):
        """
        Initialize the InputGenerator.

        :param config: The ConfigManager instance.
        """
        self.config = config
        self.users: List[int] = config.get_list('users')
        self.system_uids: List[int] = config.get_list('system_uids')
        self.priv_perms: List[str] = config.get_list('priv_perms')
        self.known_pkgs: List[str] = config.get_list('known_pkgs')
        self.output_dir: Path = Path(config.get_str('output_dir'))
        self.seeds_file: Path = self.output_dir / 'seeds.json'
        self.seed_corpus: List[Dict[str, Any]] = self._load_seeds()
        self.grammar: Dict[int, List[Tuple[str, str]]] = self._load_grammar()
        self.max_seeds: int = 1000  # Limit to prevent excessive memory usage

    def _load_seeds(self) -> List[Dict[str, Any]]:
        """
        Load seeds from the JSON file if it exists.

        :return: List of seed dictionaries.
        """
        if self.seeds_file.exists():
            try:
                with self.seeds_file.open('r', encoding='utf-8') as f:
                    seeds = json.load(f)
                if not isinstance(seeds, list):
                    raise ValueError("Seeds file must contain a list.")
                logger.info(f"Loaded {len(seeds)} seeds from {self.seeds_file}")
                return seeds
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"Error loading seeds: {e}. Starting with empty corpus.")
        else:
            logger.info("No seeds file found. Starting with empty corpus.")
        return []

    def _save_seeds(self) -> None:
        """
        Save the current seed corpus to the JSON file.
        """
        try:
            with self.seeds_file.open('w', encoding='utf-8') as f:
                json.dump(self.seed_corpus, f, indent=2)
            logger.info(f"Saved {len(self.seed_corpus)} seeds to {self.seeds_file}")
        except IOError as e:
            logger.error(f"Error saving seeds: {e}")

    def _load_grammar(self) -> Dict[int, List[Tuple[str, str]]]:
        """
        Load the PMS transaction grammar based on Android 13 IPackageManager.aidl.

        Includes transactions with simple types, null, and parcels for arrays and simple parcelables.
        :return: Dictionary of transaction ID to list of (mapped_type, category).
        """
        grammar = {
            1: [('s16', 'package'), ('i32', 'user')],
            2: [('s16', 'package'), ('i32', 'user')],
            3: [('s16', 'package'), ('i64', 'flags'), ('i32', 'user')],
            5: [('s16', 'package'), ('i64', 'flags'), ('i32', 'user')],
            6: [('parcel', 's16[]_package')],
            7: [('parcel', 's16[]_package')],
            9: [('s16', 'package'), ('i64', 'flags'), ('i32', 'user')],
            10: [('parcel', 'ComponentName'), ('i64', 'flags'), ('i32', 'user')],
            16: [('s16', 'generic_string')],
            17: [('s16', 'package'), ('s16', 'package')],
            18: [('i32', 'uid'), ('i32', 'uid')],
            19: [],
            20: [('i32', 'uid')],
            21: [('parcel', 'i32[]_uid')],
            23: [('s16', 'generic_string')],
            24: [('i32', 'uid')],
            25: [('i32', 'uid')],
            26: [('i32', 'uid')],
            36: [('i64', 'flags'), ('i32', 'user')],
            37: [('parcel', 's16[]_permission'), ('i64', 'flags'), ('i32', 'user')],
            38: [('i64', 'flags'), ('i32', 'user')],
            39: [('i32', 'flags')],
            40: [('s16', 'generic_string'), ('i64', 'flags'), ('i32', 'user')],
            42: [('s16', 'generic_string'), ('i32', 'uid'), ('i64', 'flags'), ('s16', 'generic_string')],
            44: [('s16', 'package'), ('i32', 'flags')],
            46: [('s16', 'package'), ('s16', 'package')],
            47: [('s16', 'package'), ('i32', 'generic_int'), ('s16', 'package')],
            48: [('s16', 'package'), ('i32', 'generic_int'), ('null', 'observer'), ('i32', 'user'), ('i32', 'flags')],
            50: [('parcel', 'versioned_package'), ('null', 'observer'), ('i32', 'user'), ('i32', 'flags')],
            51: [('s16', 'package')],
            52: [('s16', 'package')],
            53: [('i32', 'user')],
            58: [('s16', 'package')],
            61: [('s16', 'package'), ('i32', 'user')],
            63: [('i32', 'user'), ('s16', 'package')],
            67: [('parcel', 's16[]_package'), ('i32', 'generic_int'), ('i32', 'user')],
            68: [('s16', 'package'), ('i32', 'user')],
            69: [('i32', 'user')],
            71: [('i32', 'user')],
            73: [('i32', 'user')],
            82: [('s16', 'package'), ('i32', 'generic_int'), ('i32', 'flags'), ('i32', 'user'), ('s16', 'package')],
            83: [('s16', 'package'), ('i32', 'user')],
            84: [('s16', 'package'), ('s16', 'generic_string'), ('i32', 'uid'), ('s16', 'generic_string'), ('s16', 'generic_string'), ('i32', 'generic_int')],
            85: [('i32', 'user')],
            86: [('s16', 'package'), ('i32', 'boolean'), ('i32', 'user')],
            87: [('s16', 'generic_string'), ('i64', 'generic_long'), ('i32', 'flags'), ('null', 'observer')],
            89: [('s16', 'package'), ('null', 'observer')],
            90: [('s16', 'package'), ('i32', 'user'), ('null', 'observer')],
            91: [('s16', 'package'), ('null', 'observer'), ('i32', 'user')],
            92: [('s16', 'package')],
            93: [('s16', 'package'), ('i32', 'user'), ('null', 'observer')],
            96: [('s16', 'generic_string'), ('i32', 'generic_int')],
            100: [('s16', 'package'), ('i32', 'generic_int')],
            102: [('s16', 'package'), ('s16', 'generic_string'), ('i32', 'boolean'), ('null', 'observer')],
            103: [('s16', 'package'), ('i32', 'boolean'), ('s16', 'generic_string'), ('i32', 'boolean'), ('i32', 'boolean'), ('s16', 'generic_string')],
            104: [('s16', 'package'), ('s16', 'generic_string'), ('i32', 'boolean')],
            105: [('s16', 'package'), ('i32', 'boolean')],
            106: [('s16', 'package')],
            107: [('s16', 'package')],
            108: [('i32', 'generic_int')],
            111: [('s16', 'package'), ('s16', 'generic_string')],
            112: [('s16', 'generic_string')],
            113: [('i32', 'generic_int')],
        }
        logger.info(f"Loaded grammar with {len(grammar)} specific transactions.")
        return grammar

    def generate_random(self, tx: int) -> List[Tuple[str, Any]]:
        """
        Generate random arguments based on grammar for the transaction.

        :param tx: Transaction ID.
        :return: List of (type, value).
        """
        params = self.grammar.get(tx, [('s16', 'package'), ('s16', 'permission'), ('i32', 'user'), ('i32', 'flags')])
        args = []
        for arg_type, category in params:
            value = self._generate_value(arg_type, category)
            args.append((arg_type, value))
        return args

    def _generate_value(self, arg_type: str, category: str) -> Any:
        """
        Generate a value based on type and category.

        :param arg_type: Mapped type (s16, i32, i64, parcel, null).
        :param category: Guide for value (package, user, etc.).
        :return: Generated value.
        """
        if arg_type == 'parcel':
            return self._generate_parcel(category)
        if arg_type == 'null':
            return None
        if arg_type == 's16':
            if category == 'package':
                return self.rand_pkg()
            elif category == 'permission':
                return self.rand_perm()
            elif category == 'generic_string':
                return ''.join(random.choices(string.ascii_letters + string.digits + '._-', k=random.randint(5, 50)))
            else:
                return self.rand_pkg()  # Default
        elif arg_type == 'i32':
            if category == 'user':
                return random.choice(self.users)
            elif category == 'uid':
                return random.choice(self.system_uids + [random.randint(-1, 10000)])
            elif category == 'flags':
                return self.rand_flags()
            elif category == 'generic_int':
                return random.randint(-2**31, 2**31 - 1)
            elif category == 'boolean':
                return random.choice([0, 1])
            else:
                return random.randint(0, 0xffffffff)
        elif arg_type == 'i64':
            if category == 'flags':
                return random.randint(0, 2**63 - 1)
            elif category == 'generic_long':
                return random.randint(-2**63, 2**63 - 1)
            else:
                return random.randint(-2**63, 2**63 - 1)
        raise ValueError(f"Unsupported arg_type: {arg_type}")

    def _generate_parcel(self, category: str) -> List[Tuple[str, Any]]:
        """
        Generate sub_args for a parcel based on category.

        :param category: The category for the parcel (e.g., 's16[]_package', 'ComponentName').
        :return: List of (sub_type, sub_value) for serialization.
        """
        if category == 's16[]_package':
            num = random.randint(0, 10)
            values = [self.rand_pkg() for _ in range(num)]
            return [('s16[]', values)]
        elif category == 's16[]_permission':
            num = random.randint(0, 10)
            values = [self.rand_perm() for _ in range(num)]
            return [('s16[]', values)]
        elif category == 's16[]_generic_string':
            num = random.randint(0, 10)
            values = [''.join(random.choices(string.ascii_letters + string.digits + '._-', k=random.randint(5, 50))) for _ in range(num)]
            return [('s16[]', values)]
        elif category == 'i32[]_uid':
            num = random.randint(0, 10)
            values = [random.choice(self.system_uids + [random.randint(-1, 10000)]) for _ in range(num)]
            return [('i32[]', values)]
        elif category == 'ComponentName':
            pkg = self.rand_pkg()
            cls = pkg + '.' + ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
            return [('s16', pkg), ('s16', cls)]
        elif category == 'versioned_package':
            pkg = self.rand_pkg()
            ver = random.choice([-1, 0, random.randint(1, 2**63 - 1)])
            return [('s16', pkg), ('i64', ver)]
        raise ValueError(f"Unsupported parcel category: {category}")

    def mutate(self, seed: Dict[str, Any]) -> Tuple[int, List[Tuple[str, Any]]]:
        """
        Mutate a seed's tx and args.

        :param seed: Seed dictionary with 'tx' and 'args'.
        :return: Mutated tx and args.
        """
        tx = seed['tx']
        args: List[Tuple[str, Any]] = seed['args'][:]
        if not args:
            return tx, args

        idx = random.randint(0, len(args) - 1)
        arg_type, value = args[idx]

        if arg_type == 'null':
            return tx, args  # No mutation

        if arg_type == 'parcel':
            value = self.mutate_parcel(value)
        else:
            value = self.mutate_value(arg_type, value)

        args[idx] = (arg_type, value)
        logger.debug(f"Mutated seed for tx {tx}")
        return tx, args

    def mutate_parcel(self, sub_args: List[Tuple[str, Any]]) -> List[Tuple[str, Any]]:
        """
        Mutate a parcel's sub_args.

        :param sub_args: List of (sub_type, sub_value).
        :return: Mutated sub_args.
        """
        if not sub_args:
            return sub_args

        idx = random.randint(0, len(sub_args) - 1)
        sub_t, sub_v = sub_args[idx]

        if sub_t.endswith('[]'):
            base = sub_t[:-2]
            mutation_type = random.choice(['add', 'remove', 'mutate_elem'])
            if mutation_type == 'add':
                new_v = self._generate_base_value(base)
                sub_v.append(new_v)
            elif mutation_type == 'remove' and sub_v:
                sub_v.pop(random.randint(0, len(sub_v) - 1))
            elif mutation_type == 'mutate_elem' and sub_v:
                elem_idx = random.randint(0, len(sub_v) - 1)
                sub_v[elem_idx] = self.mutate_value(base, sub_v[elem_idx])
        else:
            sub_v = self.mutate_value(sub_t, sub_v)

        sub_args[idx] = (sub_t, sub_v)
        return sub_args

    def _generate_base_value(self, base: str) -> Any:
        """
        Generate a single value for a base type in array.

        :param base: Base type (s16, i32, etc.).
        :return: Value.
        """
        if base == 's16':
            return ''.join(random.choices(string.ascii_letters + string.digits + '._-', k=random.randint(5, 50)))
        elif base == 'i32':
            return random.randint(-2**31, 2**31 - 1)
        elif base == 'i64':
            return random.randint(-2**63, 2**63 - 1)
        raise ValueError(f"Unsupported base: {base}")

    def mutate_value(self, t: str, v: Any) -> Any:
        """
        Mutate a simple value based on type.

        :param t: Type (s16, i32, i64).
        :param v: Value to mutate.
        :return: Mutated value.
        """
        if t == 's16' or t == 'generic_string':  # Treat as string
            chosen = random.choice(['truncate', 'inject', 'edge'])
            if chosen == 'truncate' and len(v) > 0:
                v = v[:random.randint(0, len(v) - 1)]
            elif chosen == 'inject':
                special = random.choice(['\x00', '\n', '\r', '\\', '"', "'", '<', '>', '&'])
                pos = random.randint(0, len(v))
                v = v[:pos] + special + v[pos:]
            elif chosen == 'edge':
                v = random.choice(['', '\x00', 'a' * 1024])
        elif t in ('i32', 'i64'):
            chosen = random.choice(['bit_flip', 'edge_case'])
            if chosen == 'bit_flip':
                max_bit = 31 if t == 'i32' else 63
                bit = random.randint(0, max_bit)
                v ^= 1 << bit
            else:
                edges = [0, -1, 1, 2**31 - 1, -(2**31), 0xffffffff] if t == 'i32' else [0, -1, 1, 2**63 - 1, -(2**63), 0xffffffffffffffff]
                v = random.choice(edges)
        return v

    def rand_pkg(self) -> str:
        """
        Generate a random package name.

        :return: Package name string.
        """
        if random.random() < 0.4:
            return random.choice(self.known_pkgs)
        return f"com.fuzz.{random.randint(1, 999999)}.{''.join(random.choices(string.ascii_lowercase, k=5))}"

    def rand_perm(self) -> str:
        """
        Generate a random permission name.

        :return: Permission string.
        """
        if random.random() < 0.6:
            return random.choice(self.priv_perms)
        return f"android.permission.FUZZ_{random.randint(1, 99999)}.{''.join(random.choices(string.ascii_uppercase, k=5))}"

    def rand_flags(self) -> int:
        """
        Generate random flags (32-bit).

        :return: Integer flags.
        """
        return random.randint(0, 0xffffffff)

    def add_seed(self, seed: Dict[str, Any], score: float) -> None:
        """
        Add a seed if score is positive, and manage corpus size.

        :param seed: Seed dictionary with 'tx' and 'args'.
        :param score: Fitness score.
        """
        if score > 0:
            enhanced_seed = seed.copy()
            enhanced_seed['score'] = score
            self.seed_corpus.append(enhanced_seed)
            self.seed_corpus.sort(key=lambda s: s['score'], reverse=True)
            if len(self.seed_corpus) > self.max_seeds:
                self.seed_corpus = self.seed_corpus[:self.max_seeds]
            self._save_seeds()
            logger.info(f"Added seed for tx {seed['tx']} with score {score}. Corpus size: {len(self.seed_corpus)}")