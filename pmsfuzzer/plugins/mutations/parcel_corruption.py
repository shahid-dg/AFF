# plugins/mutations/parcel_corruption.py
"""
Example advanced mutation plugin: Targeted parcel corruption.
"""

from typing import List, Tuple, Any, Dict
import random
from .base import MutationPlugin

class ParcelCorruptionMutation(MutationPlugin):
    name = "parcel_corruption"
    description = "Corrupts parcel sub-arguments (arrays, strings, etc.)"

    def mutate(
        self,
        tx: int,
        args: List[Tuple[str, Any]],
        seed_metadata: Dict[str, Any]
    ) -> Tuple[int, List[Tuple[str, Any]]]:
        mutated_args = args[:]
        parcel_indices = [i for i, (t, v) in enumerate(args) if t == 'parcel']

        if parcel_indices:
            idx = random.choice(parcel_indices)
            parcel = mutated_args[idx][1][:]  # Deepish copy
            if parcel:
                sub_idx = random.randint(0, len(parcel) - 1)
                sub_t, sub_v = parcel[sub_idx]
                if sub_t.endswith('[]'):
                    # Corrupt array length or element
                    if random.random() < 0.5 and isinstance(sub_v, list):
                        sub_v.append(sub_v[-1] if sub_v else 0)  # Duplicate last
                    else:
                        # Corrupt an element
                        elem_idx = random.randint(0, len(sub_v) - 1)
                        sub_v[elem_idx] = self._corrupt_value(sub_t[:-2], sub_v[elem_idx])
                else:
                    sub_v = self._corrupt_value(sub_t, sub_v)
                parcel[sub_idx] = (sub_t, sub_v)
            mutated_args[idx] = ('parcel', parcel)

        return tx, mutated_args

    def _corrupt_value(self, base_type: str, value: Any) -> Any:
        if base_type == 's16':
            return value + '\x00' * random.randint(1, 10)
        elif base_type in ('i32', 'i64'):
            return value ^ random.randint(1, 0xffffffff)
        return value

    def priority(self) -> int:
        return 90