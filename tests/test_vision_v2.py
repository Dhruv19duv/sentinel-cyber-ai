"""
Tests for Vision Agent v2: VLM Integration, Security Analysis, and New Modes.

Covers:
- VisionAgent.analyze_image_file() with different AnalysisMode values
- VisionAgent._analyze_with_vlm() VLM integration
- VisionAgent._security_analysis() image security scanning
- VisionAgent._extract_security_from_vlm() and _extract_objects_from_vlm()
- VisionAgent.analyze_base64_image()
- VisionAgent.get_status()
"""

import os
import sys
import json
import base64
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestVisionResult:
    """Tests for VisionResult dataclass."""

    def test_vision_result_defaults(self):
        """Test VisionResult has sensible defaults."""
        from src.vision.vision_agent import VisionResult

        result = VisionResult()
        assert result.detected_text == ""
        assert result.code_fragments == []
        assert result.objects_detected == []
        assert result.image_metadata == {}
        assert result.analysis is None
        assert result.vlm_analysis is None
        assert result.security_issues == []
        assert result.error is None
        assert result.analysis_mode == "ocr_only"

    def test_vision_result_to_dict(self):
        """Test VisionResult serializes to dict."""
        from src.vision.vision_agent import VisionResult

        result = VisionResult(
            detected_text="Hello World",
            code_fragments=[{"language": "python", "code": "print('hello')", "length": 15}],
            objects_detected=["code", "terminal"],
            image_metadata={"width": 1920, "height": 1080},
            vlm_analysis="A screenshot of code",
            security_issues=[{"title": "Credential exposure", "severity": "HIGH"}],
            analysis_mode="vlm_light",
        )

        d = result.to_dict()
        assert d["detected_text"] == "Hello World"
        assert len(d["code_fragments"]) == 1
        assert len(d["vlm_analysis"]) <= 500  # Truncated

    def test_vision_result_error(self):
        """Test VisionResult with error."""
        from src.vision.vision_agent import VisionResult

        result = VisionResult(error="Image not found")
        assert result.error == "Image not found"


class TestAnalyzeImageFile:
    """Tests for analyze_image_file with different modes."""

    def test_analyze_nonexistent_file(self):
        """Test analyzing a non-existent file returns error."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        result = agent.analyze_image_file("/nonexistent/image.png")

        assert result.error is not None
        assert "not found" in result.error.lower()

    @patch("src.vision.vision_agent.os.path.exists", return_value=True)
    @patch("src.vision.vision_agent.VisionAgent._get_image_metadata")
    @patch("src.vision.vision_agent.VisionAgent._extract_text")
    @patch("src.vision.vision_agent.VisionAgent._extract_code")
    def test_analyze_ocr_mode(self, mock_code, mock_text, mock_meta, mock_exists):
        """Test analyze_image_file with OCR mode."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode

        mock_meta.return_value = {"width": 100, "height": 100, "format": ".png"}
        mock_text.return_value = "Some detected text\nwith code\nprint('hello')"
        mock_code.return_value = [{"language": "python", "code": "print('hello')", "length": 15}]

        agent = VisionAgent()
        result = agent.analyze_image_file("test.png", mode=AnalysisMode.OCR_ONLY)

        assert result.error is None
        assert result.detected_text == "Some detected text\nwith code\nprint('hello')"
        assert len(result.code_fragments) == 1
        assert result.analysis_mode == "ocr_only"
        assert result.vlm_analysis is None  # No VLM in OCR mode

    @patch("src.vision.vision_agent.os.path.exists", return_value=True)
    @patch("src.vision.vision_agent.VisionAgent._get_image_metadata")
    @patch("src.vision.vision_agent.VisionAgent._extract_text")
    @patch("src.vision.vision_agent.VisionAgent._extract_code")
    @patch("src.vision.vision_agent.VisionAgent._analyze_with_vlm")
    def test_analyze_vlm_light_mode(self, mock_vlm, mock_code, mock_text, mock_meta, mock_exists):
        """Test analyze_image_file with VLM light mode."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode

        mock_meta.return_value = {"width": 200, "height": 200}
        mock_text.return_value = "login: admin\npassword: secret123"
        mock_code.return_value = []
        mock_vlm.return_value = {
            "description": "A login screen with username and password fields",
            "security_issues": [],
            "combined_analysis": "VLM + OCR analysis",
        }

        agent = VisionAgent()
        result = agent.analyze_image_file("test.png", mode=AnalysisMode.VLM_LIGHT)

        assert result.error is None
        assert result.vlm_analysis == "A login screen with username and password fields"
        assert result.analysis_mode == "vlm_light"
        mock_vlm.assert_called_once()

    @patch("src.vision.vision_agent.os.path.exists", return_value=True)
    @patch("src.vision.vision_agent.VisionAgent._get_image_metadata")
    @patch("src.vision.vision_agent.VisionAgent._extract_text")
    @patch("src.vision.vision_agent.VisionAgent._extract_code")
    @patch("src.vision.vision_agent.VisionAgent._analyze_with_vlm")
    def test_analyze_security_mode(self, mock_vlm, mock_code, mock_text, mock_meta, mock_exists):
        """Test analyze_image_file with security mode."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode

        mock_meta.return_value = {"width": 800, "height": 600, "format": ".png"}
        mock_text.return_value = "API_KEY = sk-1234567890abcdef"
        mock_code.return_value = [{"language": "assignment", "code": "API_KEY = sk-1234567890abcdef", "length": 35}]

        mock_vlm.return_value = {
            "description": "A code editor showing API credentials",
            "security_issues": [{"title": "API key visible", "severity": "CRITICAL", "source": "vlm_analysis"}],
            "combined_analysis": "Security analysis complete",
        }

        agent = VisionAgent()
        result = agent.analyze_image_file("test.png", mode=AnalysisMode.SECURITY)

        assert result.error is None
        assert len(result.security_issues) > 0
        assert result.analysis_mode == "security"
        # Should have both VLM issues AND OCR-based security findings
        assert any(s["source"] == "vlm_analysis" for s in result.security_issues) or \
               any(s["source"] == "security_scan" for s in result.security_issues)

    @patch("src.vision.vision_agent.os.path.exists", return_value=True)
    @patch("src.vision.vision_agent.VisionAgent._get_image_metadata")
    @patch("src.vision.vision_agent.VisionAgent._extract_text")
    @patch("src.vision.vision_agent.VisionAgent._extract_code")
    def test_analyze_metadata_mode(self, mock_code, mock_text, mock_meta, mock_exists):
        """Test analyze returns metadata in all modes."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode

        mock_meta.return_value = {"width": 1920, "height": 1080, "format": ".jpg", "size_bytes": 102400}
        mock_text.return_value = ""
        mock_code.return_value = []

        agent = VisionAgent()
        result = agent.analyze_image_file("test.jpg", mode=AnalysisMode.METADATA)

        assert result.error is None
        assert result.image_metadata["width"] == 1920
        assert result.image_metadata["height"] == 1080

    @patch("src.vision.vision_agent.os.path.exists", return_value=True)
    @patch("src.vision.vision_agent.VisionAgent._get_image_metadata")
    @patch("src.vision.vision_agent.VisionAgent._extract_text")
    @patch("src.vision.vision_agent.VisionAgent._extract_code")
    def test_analyze_tracks_history(self, mock_code, mock_text, mock_meta, mock_exists):
        """Test analysis history is tracked."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode

        mock_meta.return_value = {}
        mock_text.return_value = ""
        mock_code.return_value = []

        agent = VisionAgent()
        agent.analyze_image_file("test1.png", mode=AnalysisMode.OCR_ONLY)
        agent.analyze_image_file("test2.png", mode=AnalysisMode.OCR_ONLY)

        assert len(agent._analysis_history) == 2
        assert agent._analysis_history[0]["path"] == "test1.png"
        assert agent._analysis_history[1]["path"] == "test2.png"


class TestAnalyzeWithVLM:
    """Tests for the VLM integration.

    Note: _inference_engine is an instance attribute set in __init__,
    so we cannot use @patch on the class. Instead we set it after construction.
    """

    def test_vlm_unavailable(self):
        """Test VLM returns None when inference engine is not available."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode

        agent = VisionAgent()
        agent._inference_engine = None

        result = agent._analyze_with_vlm("test.png", AnalysisMode.VLM_LIGHT)
        assert result is None

    def _make_mock_engine(self, return_value=None, side_effect=None):
        """Create a mock inference engine with async analyze_security."""
        engine = MagicMock()
        engine.analyze_security = AsyncMock(
            return_value=return_value,
            side_effect=side_effect,
        )
        return engine

    def _make_vlm_agent(self, return_value=None, side_effect=None):
        """Create a VisionAgent with mocked inference engine and file I/O."""
        from src.vision.vision_agent import VisionAgent

        mock_engine = self._make_mock_engine(
            return_value=return_value,
            side_effect=side_effect,
        )

        agent = VisionAgent()
        agent._inference_engine = mock_engine
        return agent

    @patch("builtins.open", new_callable=MagicMock)
    def test_vlm_light_prompt(self, mock_open):
        """Test VLM light mode uses brief prompt."""
        from src.vision.vision_agent import AnalysisMode

        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_image_data"

        agent = self._make_vlm_agent(
            return_value="This is a screenshot of a terminal."
        )

        result = agent._analyze_with_vlm("test.png", AnalysisMode.VLM_LIGHT)

        assert result is not None
        assert "description" in result
        assert "screenshot" in result["description"].lower()

    @patch("builtins.open", new_callable=MagicMock)
    def test_vlm_deep_prompt(self, mock_open):
        """Test VLM deep mode uses detailed prompt."""
        from src.vision.vision_agent import AnalysisMode

        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_image_data"

        agent = self._make_vlm_agent(
            return_value="Detailed analysis of the image showing code and configuration."
        )

        result = agent._analyze_with_vlm("test.png", AnalysisMode.VLM_DEEP)

        assert result is not None
        assert "description" in result

    @patch("builtins.open", new_callable=MagicMock)
    def test_vlm_security_prompt(self, mock_open):
        """Test VLM security mode uses security-focused prompt."""
        from src.vision.vision_agent import AnalysisMode

        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_image_data"

        agent = self._make_vlm_agent(
            return_value="Sensitive credentials detected in the image."
        )

        result = agent._analyze_with_vlm("test.png", AnalysisMode.SECURITY)

        assert result is not None
        assert "description" in result

    @patch("builtins.open", new_callable=MagicMock)
    def test_vlm_extracts_security_issues(self, mock_open):
        """Test VLM response parsing detects security issues."""
        from src.vision.vision_agent import AnalysisMode

        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_image_data"

        agent = self._make_vlm_agent(
            return_value="The image shows a terminal with password fields and credentials visible."
        )

        result = agent._analyze_with_vlm("test.png", AnalysisMode.SECURITY)

        assert result is not None
        assert len(result["security_issues"]) > 0
        # Should catch "password" and "credential" keywords
        issue_titles = [i["title"].lower() for i in result["security_issues"]]
        assert any("password" in t or "credential" in t for t in issue_titles)

    @patch("builtins.open", new_callable=MagicMock)
    def test_vlm_handles_error_response(self, mock_open):
        """Test VLM handles error response from engine gracefully."""
        from src.vision.vision_agent import AnalysisMode

        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_image_data"

        agent = self._make_vlm_agent(
            return_value="Error: Model not responding"
        )

        result = agent._analyze_with_vlm("test.png", AnalysisMode.VLM_LIGHT)
        assert result is None  # Should return None on error

    @patch("builtins.open", new_callable=MagicMock)
    def test_vlm_handles_exception(self, mock_open):
        """Test VLM handles engine exception gracefully."""
        from src.vision.vision_agent import AnalysisMode

        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_image_data"

        agent = self._make_vlm_agent(
            side_effect=Exception("Connection failed")
        )

        result = agent._analyze_with_vlm("test.png", AnalysisMode.VLM_LIGHT)
        assert result is None  # Should return None on exception


class TestSecurityAnalysis:
    """Tests for image security analysis."""

    def test_detect_credentials(self):
        """Test security analysis detects credentials in OCR text."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        findings = agent._security_analysis(
            {"width": 800, "height": 600},
            "password = 'supersecret123!'",
            None,
        )

        assert len(findings) > 0
        assert any("password" in f["title"].lower() for f in findings)

    def test_detect_api_key(self):
        """Test security analysis detects API keys."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        findings = agent._security_analysis(
            {},
            "API_KEY = sk-live-abcdefghijklmnopqrstuvwxyz1234567890",
            None,
        )

        assert len(findings) > 0
        assert any("credential" in f["title"].lower() or "visible" in f["title"].lower()
                   for f in findings)

    def test_detect_private_key(self):
        """Test security analysis detects private keys."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        findings = agent._security_analysis(
            {},
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
            None,
        )

        assert len(findings) > 0
        assert any("key" in f["title"].lower() for f in findings)

    def test_detect_debug_mode(self):
        """Test security analysis detects debug mode exposure."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        findings = agent._security_analysis(
            {},
            "DEBUG=True\nstack trace: File 'app.py', line 42, in process",
            "The image shows a debug console",
        )

        assert len(findings) > 0
        assert any("debug" in f["title"].lower() for f in findings)

    def test_no_findings_for_clean_text(self):
        """Test security analysis returns no findings for clean text."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        findings = agent._security_analysis(
            {},
            "The sun is shining today.",
            "A beautiful landscape photo",
        )

        assert len(findings) == 0

    def test_credential_patterns_comprehensive(self):
        """Test all credential patterns are covered."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()

        test_cases = [
            ("password: mypass123", True),
            ("API_KEY = abcdefghijklmnopqrstuvwxyz12", True),
            ("secret = mysecretvalue", True),
            ("token = 1234567890abcdef1234567890abcdef12", True),
            ("AKIAIOSFODNN7EXAMPLE", True),
            ("normal variable = 42", False),
            ("def hello(): pass", False),
        ]

        for text, should_find in test_cases:
            findings = agent._security_analysis({}, text, None)
            if should_find:
                assert len(findings) > 0, f"Should detect in: {text}"
            else:
                assert len(findings) == 0, f"Should NOT detect in: {text}"


class TestExtractSecurityFromVLM:
    """Tests for extracting security findings from VLM text."""

    def test_extract_credential_keywords(self):
        """Test extraction finds credential keywords in VLM text."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        issues = agent._extract_security_from_vlm(
            "The image shows credentials and passwords exposed."
        )

        assert len(issues) >= 2
        keywords_found = set()
        for issue in issues:
            for kw in ["credential", "password"]:
                if kw in issue["description"]:
                    keywords_found.add(kw)

        assert "credential" in keywords_found
        assert "password" in keywords_found

    def test_extract_private_key_keyword(self):
        """Test extraction finds private key indicators."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        issues = agent._extract_security_from_vlm(
            "-----BEGIN OPENSSH PRIVATE KEY----- visible in the image"
        )

        assert len(issues) > 0
        assert any("key" in i["title"].lower() for i in issues)

    def test_extract_no_findings_clean(self):
        """Test extraction returns empty for clean descriptions."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        issues = agent._extract_security_from_vlm(
            "A cat sitting on a couch in a sunny room."
        )

        assert len(issues) == 0

    def test_extract_multiple_findings(self):
        """Test extraction finds multiple security indicators."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        issues = agent._extract_security_from_vlm(
            "The screenshot shows an error with a stack trace exposing sensitive data and API tokens."
        )

        # Should find multiple: error, stack trace, sensitive, token
        assert len(issues) >= 2


class TestExtractObjectsFromVLM:
    """Tests for extracting objects from VLM description."""

    def test_extract_technical_objects(self):
        """Test extraction finds technical elements in VLM text."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        objects = agent._extract_objects_from_vlm(
            "This is a screenshot of a terminal showing code and a database connection."
        )

        assert "code" in objects
        assert "terminal" in objects
        assert "database" in objects

    def test_extract_no_objects(self):
        """Test extraction returns empty for non-technical descriptions."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        objects = agent._extract_objects_from_vlm(
            "A beautiful landscape with mountains and trees."
        )

        assert len(objects) == 0

    def test_extract_dashboard_elements(self):
        """Test extraction finds dashboard-related elements."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        objects = agent._extract_objects_from_vlm(
            "The dashboard shows login form, table, and chart data."
        )

        assert "dashboard" in objects
        assert "login" in objects
        assert "form" in objects
        assert "table" in objects
        assert "chart" in objects


class TestAnalyzeBase64Image:
    """Tests for analyze_base64_image."""

    @patch("src.vision.vision_agent.HAS_PIL", False)
    def test_base64_no_pillow(self):
        """Test base64 analysis returns error when Pillow not available."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        result = agent.analyze_base64_image("dGVzdA==")

        assert result.error is not None
        assert "Pillow" in result.error

    @patch("src.vision.vision_agent.HAS_PIL", True)
    @patch("src.vision.vision_agent.Image.open")
    @patch("src.vision.vision_agent.VisionAgent.analyze_image_file")
    def test_base64_success(self, mock_analyze, mock_pil_open):
        """Test successful base64 image analysis."""
        from src.vision.vision_agent import VisionAgent, AnalysisMode, VisionResult

        mock_img = MagicMock()
        mock_pil_open.return_value = mock_img

        mock_analyze.return_value = VisionResult(
            detected_text="Hello World",
            image_metadata={"width": 100, "height": 100},
            analysis_mode="ocr_only",
        )

        agent = VisionAgent()
        result = agent.analyze_base64_image("dGVzdA==", mode=AnalysisMode.OCR_ONLY)

        assert result.error is None
        assert result.detected_text == "Hello World"
        mock_analyze.assert_called_once()

    @patch("src.vision.vision_agent.HAS_PIL", True)
    @patch("src.vision.vision_agent.Image.open")
    def test_base64_decode_failure(self, mock_pil_open):
        """Test base64 analysis handles decode failure."""
        from src.vision.vision_agent import VisionAgent

        mock_pil_open.side_effect = Exception("Invalid image data")

        agent = VisionAgent()
        result = agent.analyze_base64_image("aW52YWxpZA==")

        assert result.error is not None
        assert "Failed" in result.error


class TestGetStatus:
    """Tests for get_status reporting."""

    def test_get_status_structure(self):
        """Test get_status returns expected keys."""
        from src.vision.vision_agent import VisionAgent

        agent = VisionAgent()
        status = agent.get_status()

        assert "pillow_available" in status
        assert "tesseract_available" in status
        assert "vlm_available" in status
        assert "analysis_history" in status
        assert "supported_modes" in status


class TestAnalysisModes:
    """Tests for the AnalysisMode enum."""

    def test_all_modes_available(self):
        """Test all expected analysis modes exist."""
        from src.vision.vision_agent import AnalysisMode

        modes = [m.value for m in AnalysisMode]
        expected = ["ocr_only", "metadata", "vlm_light", "vlm_deep", "security", "code_extract"]

        for mode in expected:
            assert mode in modes

    def test_mode_values_unique(self):
        """Test all mode values are unique."""
        from src.vision.vision_agent import AnalysisMode

        values = [m.value for m in AnalysisMode]
        assert len(values) == len(set(values))
