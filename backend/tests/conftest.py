"""
pytest configuration for ThreatForge backend tests.
"""
import sys, os
# Ensure the backend/app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
