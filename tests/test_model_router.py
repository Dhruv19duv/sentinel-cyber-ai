"""Tests for the MoE-style model router."""

import pytest
from src.router.model_router import classify_intent, route_query, get_available_models


class TestClassifyIntent:
    """Tests for query intent classification."""

    def test_sql_injection_intent(self):
        """SQL injection query should route to vulnerability_detection."""
        query = "find SQL injection vulnerabilities in this code"
        intent, confidence = classify_intent(query)
        assert intent == "vulnerability_detection"
        assert confidence > 0

    def test_exploit_intent(self):
        """Exploit analysis query should route to exploit_analysis."""
        query = "analyze this zero-day exploit payload"
        intent, confidence = classify_intent(query)
        assert intent == "exploit_analysis"
        assert confidence > 0

    def test_patch_intent(self):
        """Patch/fix query should route to patch_generation."""
        query = "fix this security vulnerability and patch the code"
        intent, confidence = classify_intent(query)
        assert intent == "patch_generation"
        assert confidence > 0

    def test_threat_intel_intent(self):
        """CVE/threat query should route to threat_intelligence."""
        query = "check CVE-2024-3094 for latest threat intel"
        intent, confidence = classify_intent(query)
        assert intent == "threat_intelligence"
        assert confidence > 0

    def test_report_intent(self):
        """Report generation query should route to report_generation."""
        query = "generate a security report for this analysis"
        intent, confidence = classify_intent(query)
        assert intent == "report_generation"
        assert confidence > 0

    def test_empty_query_fallsback(self):
        """Empty or unclear query should fallback to vulnerability_detection."""
        intent, confidence = classify_intent("")
        assert intent == "vulnerability_detection"
        assert confidence < 0.5  # Low confidence for gibberish

    def test_normal_text_fallsback(self):
        """Normal text without security keywords should fallback."""
        intent, confidence = classify_intent("Hello, how are you?")
        assert intent == "vulnerability_detection"

    def test_multiple_intents_picks_highest(self):
        """Query with multiple intents should pick the highest confidence."""
        query = "find and fix this SQL injection vulnerability and generate a report"
        intent, confidence = classify_intent(query)
        assert intent in ("vulnerability_detection", "patch_generation", "report_generation")
        assert confidence > 0

    def test_case_insensitivity(self):
        """Classification should be case-insensitive."""
        intent1, _ = classify_intent("SQL INJECTION VULNERABILITY")
        intent2, _ = classify_intent("sql injection vulnerability")
        assert intent1 == intent2


class TestRouteQuery:
    """Tests for query routing decisions."""

    def test_routes_to_code_scanner_for_vulns(self):
        """Vulnerability queries should route to Code-Scanner."""
        result = route_query("find vulnerabilities in this code")
        assert result["primary_agent"] == "Code-Scanner"
        assert "Code-Scanner" not in result["secondary_agents"]

    def test_routes_to_exploit_analyzer(self):
        """Exploit queries should route to Exploit-Analyzer."""
        result = route_query("analyze this zero-day exploit chain")
        assert result["primary_agent"] == "Exploit-Analyzer"

    def test_routes_to_patch_generator(self):
        """Patch queries should route to Patch-Generator."""
        result = route_query("fix this security vulnerability in the code")
        assert result["primary_agent"] == "Patch-Generator"

    def test_routes_to_threat_intel(self):
        """CVE queries should route to Threat-Intelligence."""
        result = route_query("check CVE-2024-27198 advisory")
        assert result["primary_agent"] == "Threat-Intelligence"

    def test_routes_to_report_generator(self):
        """Report queries should route to Report-Generator."""
        result = route_query("generate security report")
        assert result["primary_agent"] == "Report-Generator"

    def test_low_confidence_adds_secondary(self):
        """Low confidence queries should get Code-Scanner as secondary."""
        result = route_query("something about exploit with unclear context")
        assert result["primary_agent"] != "Code-Scanner" or not result["secondary_agents"]
        # If primary isn't scanner and confidence is low, scanner should be secondary
        if result["confidence"] < 0.5 and result["primary_agent"] != "Code-Scanner":
            assert "Code-Scanner" in result["secondary_agents"]

    def test_patch_keyword_adds_patch_secondary(self):
        """Queries with 'fix' or 'patch' should get Patch-Generator as secondary."""
        result = route_query("find and fix security issues")
        if result["primary_agent"] != "Patch-Generator":
            assert "Patch-Generator" in result["secondary_agents"]

    def test_routing_has_reasoning(self):
        """Routing decision should include human-readable reasoning."""
        result = route_query("test query")
        assert "reasoning" in result
        assert len(result["reasoning"]) > 10

    def test_routing_includes_tools(self):
        """Routing decision should list required tools."""
        result = route_query("find SQL injection")
        assert "tools_required" in result
        assert isinstance(result["tools_required"], list)

    def test_confidence_between_0_and_1(self):
        """Confidence score should always be between 0 and 1."""
        test_queries = [
            "",
            "hello world",
            "find SQL injection in eval()",
            "critical remote code execution zero-day exploit patch",
            "generate CVE report for Log4j",
        ]
        for q in test_queries:
            _, confidence = classify_intent(q)
            assert 0 <= confidence <= 1, f"Confidence {confidence} out of range for: {q}"


class TestGetAvailableModels:
    """Tests for model listing."""

    def test_returns_list(self):
        """get_available_models should return a list."""
        models = get_available_models()
        assert isinstance(models, list)
        assert len(models) > 0

    def test_each_model_has_required_fields(self):
        """Each model should have id, name, type, strength, etc."""
        required = {"id", "name", "type", "strength", "min_vram_gb", "license"}
        for model in get_available_models():
            for field in required:
                assert field in model, f"Model {model.get('name')} missing field: {field}"

    def test_deepseek_is_present(self):
        """DeepSeek R1 should be in the available models."""
        models = get_available_models()
        assert any("deepseek" in m["id"] for m in models)

    def test_includes_moe_models(self):
        """All models should be MoE type."""
        for model in get_available_models():
            assert model["type"] == "MoE"
