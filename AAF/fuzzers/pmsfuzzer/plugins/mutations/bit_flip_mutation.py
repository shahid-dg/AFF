# plugins/mutations/bit_flip_mutation.py
"""
Example advanced mutation plugin: Aggressive bit-flipping on integer args.
"""

from typing import List, Tuple, Any, Dict
import random

from .base import MutationPlugin

class AggressiveBitFlipMutation(MutationPlugin):
    name = "aggressive_bit_flip"
    description = "Flips multiple bits in integer arguments for deeper coverage"

    def mutate(
        self,
        tx: int,
        args: List[Tuple[str, Any]],
        seed_metadata: Dict[str, Any]
    ) -> Tuple[int, List[Tuple[str, Any]]]:
        mutated_args = args[:]
        int_indices = [i for i, (t, v) in enumerate(args) if t in ('i32', 'i64') and isinstance(v, int)]

        if int_indices:
            target_idx = random.choice(int_indices)
            t, v = mutated_args[target_idx]
            flips = random.randint(2, 8)  # Multiple flips
            for _ in range(flips):
                bit = random.randint(0, 31 if t == 'i32' else 63)
                v ^= 1 << bit
            mutated_args[target_idx] = (t, v)

        return tx, mutated_args

    def priority(self) -> int:
        return 80  # High priority

    def probability(self) -> float:
        return 0.7