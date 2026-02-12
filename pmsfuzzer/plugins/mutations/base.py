# plugins/mutations/base.py
"""
plugins/mutations/base.py

Abstract base class for mutation strategy plugins.
These plugins allow custom, pluggable mutation logic in the InputGenerator.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple

class MutationPlugin(ABC):
    """
    Base class for mutation plugins.
    Subclasses define custom mutation behaviors.
    """

    name: str = "unnamed_mutation"
    description: str = "No description provided"

    @abstractmethod
    def mutate(
        self,
        tx: int,
        args: List[Tuple[str, Any]],
        seed_metadata: Dict[str, Any]
    ) -> Tuple[int, List[Tuple[str, Any]]]:
        """
        Apply custom mutation to the transaction and arguments.

        :param tx: Original transaction ID.
        :param args: Original arguments list.
        :param seed_metadata: Additional context (e.g., previous score).
        :return: Mutated (tx, args).
        """
        return tx, args

    def priority(self) -> int:
        """Higher priority mutations run first when multiple are active."""
        return 50

    def probability(self) -> float:
        """Chance (0.0–1.0) this mutation is selected when multiple are available."""
        return 1.0