from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import networkx as nx

from app.domain.graph.builder import ArchitectureGraph
from app.domain.models.core import Component, ModelContext


@dataclass
class AttackStep:
    step_number: int
    source_component_id: str
    source_component_name: str
    target_component_id: str
    target_component_name: str
    flow_id: str
    crosses_boundary: bool
    encrypted: bool | None
    protocol: str | None


@dataclass
class AttackPath:
    path_id: str
    entry_point_id: str
    entry_point_name: str
    target_asset_id: str
    target_asset_name: str
    steps: list[AttackStep]
    hop_count: int
    risk_score: float  # 0.0 - 100.0 (higher = easier / higher risk path)
    unencrypted_hops: int
    boundary_crossings: int
    description: str


class AttackPathAnalyzer:
    """
    Analyzes potential attack paths from untrusted ingress nodes
    to sensitive assets and critical components.
    """

    def __init__(self, context: ModelContext) -> None:
        self.context = context
        self.arch_graph = ArchitectureGraph(context)

    def analyze_paths(self, max_depth: int = 8) -> list[AttackPath]:
        """
        Finds all viable attack paths from any entry point to any sensitive data store.
        """
        entry_points = self.arch_graph.get_entry_points()
        sensitive_stores = self.arch_graph.get_sensitive_data_stores()

        attack_paths: list[AttackPath] = []
        path_counter = 1

        for ep_id in entry_points:
            for store_id in sensitive_stores:
                if ep_id == store_id:
                    continue

                raw_paths = self.arch_graph.find_paths_from_entry_to_target(
                    ep_id, store_id, max_depth=max_depth
                )

                for node_sequence in raw_paths:
                    attack_path = self._build_attack_path(
                        f"AP-{path_counter:03d}", node_sequence
                    )
                    attack_paths.append(attack_path)
                    path_counter += 1

        # Sort by risk score descending
        attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return attack_paths

    def _build_attack_path(
        self, path_id: str, node_ids: list[str]
    ) -> AttackPath:
        steps: list[AttackStep] = []
        unencrypted_hops = 0
        boundary_crossings = 0

        for i in range(len(node_ids) - 1):
            src_id_str = node_ids[i]
            tgt_id_str = node_ids[i + 1]

            edge_data: dict[str, Any] = {}
            if self.arch_graph.graph.has_edge(src_id_str, tgt_id_str):
                edges = self.arch_graph.graph.get_edge_data(src_id_str, tgt_id_str)
                # Pick first edge if multiple
                first_key = next(iter(edges))
                edge_data = edges[first_key]

            is_boundary = edge_data.get("crosses_trust_boundary", False)
            is_encrypted = edge_data.get("encrypted")

            if is_boundary:
                boundary_crossings += 1
            if is_encrypted is False:
                unencrypted_hops += 1

            src_name = self.arch_graph.graph.nodes[src_id_str].get("name", src_id_str)
            tgt_name = self.arch_graph.graph.nodes[tgt_id_str].get("name", tgt_id_str)

            steps.append(
                AttackStep(
                    step_number=i + 1,
                    source_component_id=src_id_str,
                    source_component_name=src_name,
                    target_component_id=tgt_id_str,
                    target_component_name=tgt_name,
                    flow_id=edge_data.get("flow_id", ""),
                    crosses_boundary=is_boundary,
                    encrypted=is_encrypted,
                    protocol=edge_data.get("protocol"),
                )
            )

        # Risk Score Calculation:
        # Shorter paths are easier to traverse.
        # Unencrypted flows increase risk significantly.
        # Boundary crossings without auth increase risk.
        base_score = max(10.0, 100.0 - (len(node_ids) - 2) * 10.0)
        unencrypted_penalty = unencrypted_hops * 15.0
        boundary_penalty = boundary_crossings * 10.0
        risk_score = min(100.0, base_score + unencrypted_penalty + boundary_penalty)

        ep_id = node_ids[0]
        target_id = node_ids[-1]
        ep_name = self.arch_graph.graph.nodes[ep_id].get("name", ep_id)
        target_name = self.arch_graph.graph.nodes[target_id].get("name", target_id)

        desc = (
            f"Path from {ep_name} to {target_name} via {len(steps)} hops "
            f"({boundary_crossings} boundary crossings, {unencrypted_hops} unencrypted flows)."
        )

        return AttackPath(
            path_id=path_id,
            entry_point_id=ep_id,
            entry_point_name=ep_name,
            target_asset_id=target_id,
            target_asset_name=target_name,
            steps=steps,
            hop_count=len(steps),
            risk_score=round(risk_score, 1),
            unencrypted_hops=unencrypted_hops,
            boundary_crossings=boundary_crossings,
            description=desc,
        )
