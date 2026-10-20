from __future__ import annotations

from typing import Any
from uuid import UUID
import networkx as nx

from app.domain.models.core import Component, ComponentType, DataClassification, DataFlow, ModelContext


class ArchitectureGraph:
    """
    In-memory graph representation of an architecture model built using NetworkX.

    Provides topological queries, attack surface detection, and traversal helpers.
    NetworkX graphs are never persisted; they are reconstructed on demand from ModelContext.
    """

    def __init__(self, context: ModelContext) -> None:
        self.context = context
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._build()

    def _build(self) -> None:
        """Construct the NetworkX graph from components and data flows."""
        for comp_id, comp in self.context.components.items():
            self.graph.add_node(
                str(comp_id),
                id=str(comp_id),
                name=comp.name,
                component_type=comp.component_type.value,
                trust_zone=comp.trust_zone or "default",
                properties=comp.properties.model_dump(),
                description=comp.description or "",
            )

        for flow in self.context.data_flows:
            self.graph.add_edge(
                str(flow.source_component_id),
                str(flow.target_component_id),
                key=str(flow.id),
                flow_id=str(flow.id),
                name=flow.name or "",
                crosses_trust_boundary=flow.crosses_trust_boundary,
                source_trust_zone=flow.source_trust_zone or "default",
                target_trust_zone=flow.target_trust_zone or "default",
                encrypted=flow.properties.encrypted,
                data_classification=(
                    flow.properties.data_classification.value
                    if flow.properties.data_classification
                    else None
                ),
                carries_credentials=flow.properties.carries_credentials,
                carries_pii=flow.properties.carries_pii,
                protocol=flow.properties.protocol,
                properties=flow.properties.model_dump(),
            )

    def get_entry_points(self) -> list[str]:
        """
        Identify untrusted ingress points:
        - External entities
        - Untrusted inputs
        - Components with in-degree 0 in the 'internet' or public trust zone
        - Components flagged with internet_facing=True
        """
        entry_points: list[str] = []
        for node_id, data in self.graph.nodes(data=True):
            ctype = data.get("component_type")
            props = data.get("properties", {})
            tzone = str(data.get("trust_zone", "")).lower()

            if (
                ctype in (ComponentType.EXTERNAL_ENTITY.value, ComponentType.UNTRUSTED_INPUT.value)
                or props.get("internet_facing") is True
                or "internet" in tzone
                or "public" in tzone
            ):
                entry_points.append(node_id)
        return entry_points

    def get_sensitive_data_stores(self) -> list[str]:
        """
        Find components that store sensitive assets (PII, credentials, confidential data).
        """
        stores: list[str] = []
        for node_id, data in self.graph.nodes(data=True):
            ctype = data.get("component_type")
            props = data.get("properties", {})
            if ctype in (
                ComponentType.DATA_STORE.value,
                ComponentType.VECTOR_STORE.value,
            ):
                if props.get("stores_pii") or props.get("stores_credentials"):
                    stores.append(node_id)
                elif props.get("custom", {}).get("data_classification") in (
                    DataClassification.CONFIDENTIAL.value,
                    DataClassification.RESTRICTED.value,
                    DataClassification.PII.value,
                    DataClassification.PHI.value,
                    DataClassification.CREDENTIALS.value,
                ):
                    stores.append(node_id)
        return stores

    def find_paths_from_entry_to_target(
        self, source_id: str, target_id: str, max_depth: int = 10
    ) -> list[list[str]]:
        """
        Find all simple directed paths between two nodes with depth limit to prevent graph DoS.
        """
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            return []

        try:
            # Cast MultiDiGraph to DiGraph for simple paths
            simple_digraph = nx.DiGraph(self.graph)
            paths = list(
                nx.all_simple_paths(
                    simple_digraph, source=source_id, target=target_id, cutoff=max_depth
                )
            )
            return paths
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_boundary_crossing_edges(self) -> list[dict[str, Any]]:
        """
        Find all edges that cross trust boundaries.
        """
        crossings: list[dict[str, Any]] = []
        for u, v, key, data in self.graph.edges(data=True, keys=True):
            if data.get("crosses_trust_boundary") or (
                self.graph.nodes[u].get("trust_zone")
                != self.graph.nodes[v].get("trust_zone")
            ):
                crossings.append({
                    "flow_id": data.get("flow_id", key),
                    "source_id": u,
                    "target_id": v,
                    "source_zone": self.graph.nodes[u].get("trust_zone"),
                    "target_zone": self.graph.nodes[v].get("trust_zone"),
                    "data": data,
                })
        return crossings

    def compute_centrality(self) -> dict[str, float]:
        """
        Compute degree centrality to identify critical hub components.
        """
        if len(self.graph) == 0:
            return {}
        simple_digraph = nx.DiGraph(self.graph)
        return nx.degree_centrality(simple_digraph)
