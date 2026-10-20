"""
ThreatForge Benchmark Evaluation Runner
========================================
Computes Precision, Recall, False Positive Rate, and Applicability Accuracy
across all curated reference architecture scenarios.

Target Metrics:
  - Threat Precision: > 80%
  - Threat Recall: > 90%
  - False Positive Rate: < 15%
  - Applicability Accuracy: > 85%
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any
import uuid
from uuid import UUID

# Ensure backend app is on sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.domain.models.core import (
    Applicability,
    Component,
    ComponentProperties,
    ComponentType,
    DataClassification,
    DataFlow,
    DataFlowProperties,
    ModelContext,
)
from app.domain.rules import RuleEngine


def load_scenario(scenario_path: Path) -> tuple[dict[str, Any], ModelContext]:
    with open(scenario_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vid = uuid.uuid5(uuid.NAMESPACE_DNS, scenario_path.stem)

    components: dict[UUID, Component] = {}
    for c in data.get("components", []):
        cid = UUID(c["id"])
        props_data = c.get("properties", {})
        props = ComponentProperties(**props_data)
        components[cid] = Component(
            id=cid,
            model_version_id=vid,
            component_type=ComponentType(c["component_type"]),
            name=c["name"],
            trust_zone=c.get("trust_zone"),
            properties=props,
        )

    flows: list[DataFlow] = []
    for f in data.get("data_flows", []):
        fid = UUID(f["id"])
        props_data = f.get("properties", {})
        if "data_classification" in props_data and props_data["data_classification"]:
            props_data["data_classification"] = DataClassification(props_data["data_classification"])
        flow_props = DataFlowProperties(**props_data)
        flows.append(
            DataFlow(
                id=fid,
                model_version_id=vid,
                source_component_id=UUID(f["source_component_id"]),
                target_component_id=UUID(f["target_component_id"]),
                name=f.get("name"),
                crosses_trust_boundary=f.get("crosses_trust_boundary", False),
                properties=flow_props,
            )
        )

    context = ModelContext(
        model_version_id=vid,
        components=components,
        data_flows=flows,
    )

    return data, context


def run_benchmark(scenarios_dir: Path | None = None) -> dict[str, Any]:
    if scenarios_dir is None:
        scenarios_dir = Path(__file__).resolve().parent / "scenarios"

    engine = RuleEngine()
    scenario_files = sorted(scenarios_dir.glob("*.json"))

    if not scenario_files:
        raise RuntimeError(f"No scenario files found in {scenarios_dir}")

    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0

    results_table: list[dict[str, Any]] = []

    for s_file in scenario_files:
        meta, context = load_scenario(s_file)
        expected_applicable = set(meta.get("expected_threats", []))
        expected_na = set(meta.get("expected_non_applicable", []))

        analysis_results = engine.analyze_model(context)

        detected_applicable = {
            r.rule_id for _, r, res in analysis_results
            if res.applicability == Applicability.APPLICABLE
        }
        detected_na = {
            r.rule_id for _, r, res in analysis_results
            if res.applicability == Applicability.NOT_APPLICABLE
        }

        tp = len(expected_applicable & detected_applicable)
        fp = len(detected_applicable - expected_applicable)
        fn = len(expected_applicable - detected_applicable)
        tn = len(expected_na & detected_na)

        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn

        results_table.append({
            "scenario_id": meta.get("scenario_id", s_file.stem),
            "name": meta.get("name"),
            "expected_applicable": list(expected_applicable),
            "detected_applicable": list(detected_applicable),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        })

    # Compute Global Metrics
    precision = (total_tp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 1.0
    recall = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) > 0 else 1.0
    fpr = (total_fp / (total_tn + total_fp)) if (total_tn + total_fp) > 0 else 0.0
    accuracy = (
        (total_tp + total_tn) / (total_tp + total_tn + total_fp + total_fn)
        if (total_tp + total_tn + total_fp + total_fn) > 0
        else 1.0
    )

    metrics = {
        "scenarios_evaluated": len(scenario_files),
        "total_true_positives": total_tp,
        "total_false_positives": total_fp,
        "total_false_negatives": total_fn,
        "total_true_negatives": total_tn,
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "false_positive_rate": round(fpr * 100, 2),
        "accuracy": round(accuracy * 100, 2),
        "passed_precision_target": precision >= 0.80,
        "passed_recall_target": recall >= 0.90,
        "passed_fpr_target": fpr <= 0.15,
        "details": results_table,
    }

    return metrics


if __name__ == "__main__":
    metrics = run_benchmark()
    print("=" * 65)
    print("  THREATFORGE BENCHMARK EVALUATION RESULTS")
    print("=" * 65)
    print(f"Scenarios evaluated:     {metrics['scenarios_evaluated']}")
    print(f"Precision:               {metrics['precision']}% (Target: >80%) -> {'PASS' if metrics['passed_precision_target'] else 'FAIL'}")
    print(f"Recall:                  {metrics['recall']}% (Target: >90%) -> {'PASS' if metrics['passed_recall_target'] else 'FAIL'}")
    print(f"False Positive Rate:     {metrics['false_positive_rate']}% (Target: <15%) -> {'PASS' if metrics['passed_fpr_target'] else 'FAIL'}")
    print(f"Applicability Accuracy:  {metrics['accuracy']}%")
    print("=" * 65)
