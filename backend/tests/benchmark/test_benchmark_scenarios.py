from __future__ import annotations

from pathlib import Path
import sys
import pytest

# Root directory ThreatForge is parents[3]
benchmark_path = Path(__file__).resolve().parents[3] / "benchmark"
if str(benchmark_path) not in sys.path:
    sys.path.insert(0, str(benchmark_path))

from evaluate import run_benchmark


def test_benchmark_metrics_meet_production_thresholds():
    """
    Evaluates benchmark reference architectures.
    Asserts precision >= 80%, recall >= 90%, false positive rate <= 15%.
    """
    metrics = run_benchmark()
    assert metrics["scenarios_evaluated"] >= 5
    assert metrics["precision"] >= 80.0, f"Precision {metrics['precision']}% below target 80%"
    assert metrics["recall"] >= 90.0, f"Recall {metrics['recall']}% below target 90%"
    assert metrics["false_positive_rate"] <= 15.0, f"FPR {metrics['false_positive_rate']}% exceeds target 15%"
    assert metrics["passed_precision_target"] is True
    assert metrics["passed_recall_target"] is True
    assert metrics["passed_fpr_target"] is True
