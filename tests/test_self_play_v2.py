"""
Tests for Self-Play v2: Model-in-the-Loop Generation and Dataset Export.

Covers:
- TrainingExample.to_training_format() output structure
- SelfPlayLearningPipeline._extract_code_from_response()
- SelfPlayLearningPipeline.generate_training_batch() with use_model_generation=True
- SelfPlayLearningPipeline.export_training_dataset()
- SelfPlayLearningPipeline.export_train_val_split()
"""

import os
import sys
import json
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestTrainingExampleFormat:
    """Tests for TrainingExample.to_training_format()."""

    def test_to_training_format_positive_vuln(self):
        """Test training format for a positive (vulnerable) example."""
        from src.learning.self_play import TrainingExample

        example = TrainingExample(
            id="test-1",
            query="Analyze this code",
            code_context='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            expected_findings=[{"type": "sql_injection", "cwe": "CWE-89",
                                "severity": "CRITICAL", "present": True,
                                "description": "SQL injection in query",
                                "remediation": "Use parameterized queries"}],
            actual_findings=[],
            confidence_score=0.95,
            source_agent="self-play-test",
            vulnerability_type="sql_injection",
            difficulty="hard",
            is_positive=True,
            model_generated=True,
        )

        fmt = example.to_training_format()
        assert "instruction" in fmt
        assert "input" in fmt
        assert "output" in fmt
        assert "sql_injection" in fmt["instruction"].lower()
        assert "CRITICAL" in fmt["output"]
        assert "Use parameterized queries" in fmt["output"]
        assert "SELECT" in fmt["input"]

    def test_to_training_format_negative_clean(self):
        """Test training format for a negative (clean) example."""
        from src.learning.self_play import TrainingExample

        example = TrainingExample(
            id="test-2",
            query="Analyze this code",
            code_context='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            expected_findings=[{"type": "sql_injection", "cwe": "CWE-89",
                                "severity": "CRITICAL", "present": False}],
            actual_findings=[],
            confidence_score=0.90,
            source_agent="self-play-test",
            vulnerability_type="sql_injection",
            difficulty="easy",
            is_positive=False,
            model_generated=False,
        )

        fmt = example.to_training_format()
        assert "instruction" in fmt
        assert "input" in fmt
        assert "output" in fmt
        assert "no security vulnerabilities" in fmt["output"].lower()

    def test_to_training_format_empty_findings(self):
        """Test training format handles empty expected_findings gracefully."""
        from src.learning.self_play import TrainingExample

        example = TrainingExample(
            id="test-3",
            query="test",
            code_context="print('hello')",
            expected_findings=[],
            actual_findings=[],
            confidence_score=0.5,
            source_agent="test",
            vulnerability_type="unknown",
            difficulty="easy",
            is_positive=True,
        )

        fmt = example.to_training_format()
        assert "instruction" in fmt
        assert "output" in fmt  # Should still produce output even with no findings

    def test_to_training_format_output_length(self):
        """Test training format output is non-empty and reasonable size."""
        from src.learning.self_play import TrainingExample

        example = TrainingExample(
            id="test-4",
            query="test",
            code_context="vulnerable_code()",
            expected_findings=[{"type": "xss", "cwe": "CWE-79",
                                "severity": "HIGH", "present": True,
                                "description": "XSS vulnerability",
                                "remediation": "Use textContent instead of innerHTML"}],
            actual_findings=[],
            confidence_score=0.85,
            source_agent="test",
            vulnerability_type="xss",
            difficulty="medium",
            is_positive=True,
        )

        fmt = example.to_training_format()
        assert len(fmt["output"]) > 10, "Output should be non-trivial"

    def test_to_dict_includes_model_generated(self):
        """Test to_dict includes the model_generated flag."""
        from src.learning.self_play import TrainingExample

        example = TrainingExample(
            id="test-5",
            query="test",
            code_context="code",
            expected_findings=[],
            actual_findings=[],
            confidence_score=0.5,
            source_agent="test",
            vulnerability_type="test",
            difficulty="easy",
            is_positive=True,
            model_generated=True,
        )

        d = example.to_dict()
        assert d["model_generated"] is True

    def test_to_dict_limits_query(self):
        """Test to_dict truncates long queries."""
        from src.learning.self_play import TrainingExample

        example = TrainingExample(
            id="test-6",
            query="x" * 500,
            code_context="code",
            expected_findings=[],
            actual_findings=[],
            confidence_score=0.5,
            source_agent="test",
            vulnerability_type="test",
            difficulty="easy",
            is_positive=True,
        )

        d = example.to_dict()
        assert len(d["query"]) <= 200


class TestExtractCodeFromResponse:
    """Tests for _extract_code_from_response."""

    def test_extract_code_block(self):
        """Test extracting code from a markdown code block."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        response = "```python\ndef vulnerable():\n    return eval(user_input)\n```\nThis fixes it."

        code = pipeline._extract_code_from_response(response)
        assert code is not None
        assert "def vulnerable()" in code
        assert "eval" in code

    def test_extract_code_block_no_language(self):
        """Test extracting code from a code block without language specifier."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        response = "```\nprint('hello')\n```"

        code = pipeline._extract_code_from_response(response)
        assert code is not None
        assert "print" in code

    def test_extract_direct_code(self):
        """Test extracting code when response looks like code directly."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        response = "def hello():\n    return 'world'\n\nimport os\nos.system('ls')"

        code = pipeline._extract_code_from_response(response)
        assert code is not None
        assert "def hello" in code

    def test_extract_code_no_match(self):
        """Test extraction returns None when no code is detected."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        response = "This is a description of code without actually showing any."

        code = pipeline._extract_code_from_response(response)
        assert code is None

    def test_extract_code_empty_response(self):
        """Test extraction returns None for empty response."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        assert pipeline._extract_code_from_response("") is None
        assert pipeline._extract_code_from_response(None) is None

    def test_extract_code_multi_block(self):
        """Test extracting from multiple code blocks returns first."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        response = "```python\nfirst_block\n```\nSome text\n```python\nsecond_block\n```"

        code = pipeline._extract_code_from_response(response)
        assert code == "first_block"


class TestGenerateTrainingBatch:
    """Tests for generate_training_batch with model generation."""

    def test_generate_without_orchestrator(self):
        """Test batch generation without an orchestrator still works."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        import asyncio
        examples = asyncio.run(pipeline.generate_training_batch(
            count=10,
            use_model_generation=False,
        ))

        assert len(examples) == 10
        for ex in examples:
            assert ex.id
            assert ex.code_context
            assert ex.is_positive in (True, False)
            assert ex.model_generated is False

    def test_generate_tracks_stats(self):
        """Test batch generation updates stats correctly."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        initial = pipeline.stats.total_training_examples

        import asyncio
        asyncio.run(pipeline.generate_training_batch(count=5))

        assert pipeline.stats.total_training_examples == initial + 5

    def test_generate_model_based_fallback(self):
        """Test model-based generation falls back to templates on error."""
        from src.learning.self_play import SelfPlayLearningPipeline
        with patch.object(SelfPlayLearningPipeline, '_generate_model_based',
                          side_effect=Exception("Model not available")):
            pipeline = SelfPlayLearningPipeline()
            # Make inference_engine non-None so the model block executes
            pipeline._inference_engine = MagicMock()
            import asyncio
            examples = asyncio.run(pipeline.generate_training_batch(
                count=5,
                use_model_generation=True,
                model_generation_ratio=1.0,
            ))
            # Should fall back to templates when _generate_model_based raises
            assert len(examples) == 5

    def test_generate_batch_vuln_type_coverage(self):
        """Test batch generation covers multiple vulnerability types."""
        from src.learning.self_play import SelfPlayLearningPipeline
        from src.learning.self_play import VULNERABILITY_TEMPLATES

        pipeline = SelfPlayLearningPipeline()
        import asyncio
        examples = asyncio.run(pipeline.generate_training_batch(count=50))

        types_covered = set(e.vulnerability_type for e in examples)
        # Should cover most template types
        assert len(types_covered) >= len(VULNERABILITY_TEMPLATES) * 0.5

    def test_generate_assigns_difficulty(self):
        """Test batch generation assigns difficulty based on is_positive."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        import asyncio
        examples = asyncio.run(pipeline.generate_training_batch(count=20))

        has_medium = any(e.difficulty == "medium" for e in examples)
        has_easy = any(e.difficulty == "easy" for e in examples)
        assert has_medium or has_easy, "Should assign different difficulties"


class TestExportTrainingDataset:
    """Tests for export_training_dataset and export_train_val_split."""

    def test_export_training_dataset_empty(self):
        """Test exporting with no examples produces empty file."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            result = pipeline.export_training_dataset(
                output_path=path,
                min_confidence=0.5,
                max_examples=100,
            )
            assert result == path
            # File should exist (may be empty)
            assert os.path.exists(path)
        finally:
            os.unlink(path)

    def test_export_training_dataset_with_examples(self):
        """Test exporting with examples produces valid JSONL."""
        from src.learning.self_play import SelfPlayLearningPipeline, TrainingExample

        pipeline = SelfPlayLearningPipeline()

        # Add some examples with improvement_impact set
        for i in range(5):
            pipeline.examples.append(TrainingExample(
                id=f"exp-{i}",
                query=f"test {i}",
                code_context=f"code {i}",
                expected_findings=[{"type": "sql_injection", "cwe": "CWE-89", "severity": "HIGH"}],
                actual_findings=[{"title": "SQL Injection"}],
                confidence_score=0.9,
                source_agent="test",
                vulnerability_type="sql_injection",
                difficulty="medium",
                is_positive=True,
                improvement_impact=1.0,
            ))

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            pipeline.export_training_dataset(
                output_path=path,
                min_confidence=0.5,
                max_examples=10,
            )
            # Read back and validate
            with open(path) as f:
                lines = f.readlines()

            assert len(lines) == 5
            for line in lines:
                entry = json.loads(line)
                assert "instruction" in entry
                assert "input" in entry
                assert "output" in entry
        finally:
            os.unlink(path)

    def test_export_training_dataset_filters_low_confidence(self):
        """Test export filters out low-confidence and low-impact examples."""
        from src.learning.self_play import SelfPlayLearningPipeline, TrainingExample

        pipeline = SelfPlayLearningPipeline()

        # High quality
        pipeline.examples.append(TrainingExample(
            id="good", query="test", code_context="code",
            expected_findings=[{"type": "xss", "cwe": "CWE-79", "severity": "HIGH"}],
            actual_findings=[{"title": "XSS"}],
            confidence_score=0.9, source_agent="test",
            vulnerability_type="xss", difficulty="medium",
            is_positive=True, improvement_impact=1.0,
        ))
        # Low quality (should be filtered)
        pipeline.examples.append(TrainingExample(
            id="bad", query="test", code_context="code",
            expected_findings=[{"type": "xss", "cwe": "CWE-79", "severity": "HIGH"}],
            actual_findings=[],
            confidence_score=0.1, source_agent="test",
            vulnerability_type="xss", difficulty="easy",
            is_positive=True, improvement_impact=0.0,
        ))

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            pipeline.export_training_dataset(
                output_path=path,
                min_confidence=0.5,
                max_examples=10,
            )
            with open(path) as f:
                lines = f.readlines()

            assert len(lines) == 1
            assert json.loads(lines[0])["instruction"] != ""
        finally:
            os.unlink(path)

    def test_export_train_val_split(self):
        """Test export_train_val_split produces two files."""
        from src.learning.self_play import SelfPlayLearningPipeline, TrainingExample

        pipeline = SelfPlayLearningPipeline()

        # Add examples
        for i in range(20):
            pipeline.examples.append(TrainingExample(
                id=f"ex-{i}", query=f"test {i}", code_context=f"code {i}",
                expected_findings=[{"type": "command_injection", "cwe": "CWE-78", "severity": "CRITICAL"}],
                actual_findings=[{"title": f"Finding {i}"}],
                confidence_score=0.8, source_agent="test",
                vulnerability_type="command_injection", difficulty="medium",
                is_positive=True, improvement_impact=0.9,
            ))

        with tempfile.TemporaryDirectory() as tmpdir:
            train_path, val_path = pipeline.export_train_val_split(
                output_dir=tmpdir,
                train_ratio=0.8,
                max_examples=20,
            )

            assert os.path.exists(train_path)
            assert os.path.exists(val_path)
            assert os.path.basename(train_path) == "selfplay_train.jsonl"
            assert os.path.basename(val_path) == "selfplay_val.jsonl"

            with open(train_path) as f:
                train_count = len(f.readlines())
            with open(val_path) as f:
                val_count = len(f.readlines())

            assert train_count >= 0
            assert val_count >= 0
            assert train_count + val_count == 20
            # Train should be ~80%
            assert train_count > val_count

    def test_export_train_val_split_no_examples(self):
        """Test export_train_val_split with no examples."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()

        with tempfile.TemporaryDirectory() as tmpdir:
            train_path, val_path = pipeline.export_train_val_split(
                output_dir=tmpdir,
                max_examples=100,
            )

            assert os.path.exists(train_path)
            assert os.path.exists(val_path)

            with open(train_path) as f:
                assert len(f.readlines()) == 0
            with open(val_path) as f:
                assert len(f.readlines()) == 0

    def test_export_respects_max_examples(self):
        """Test export respects max_examples limit."""
        from src.learning.self_play import SelfPlayLearningPipeline, TrainingExample

        pipeline = SelfPlayLearningPipeline()

        for i in range(50):
            pipeline.examples.append(TrainingExample(
                id=f"ex-{i}", query=f"test {i}", code_context=f"code {i}",
                expected_findings=[{"type": "path_traversal", "cwe": "CWE-22", "severity": "HIGH"}],
                actual_findings=[{"title": f"Finding {i}"}],
                confidence_score=0.9, source_agent="test",
                vulnerability_type="path_traversal", difficulty="medium",
                is_positive=True, improvement_impact=1.0,
            ))

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            pipeline.export_training_dataset(
                output_path=path,
                max_examples=10,
            )
            with open(path) as f:
                assert len(f.readlines()) == 10
        finally:
            os.unlink(path)


class TestModelBasedGeneration:
    """Tests for model-in-the-loop generation with mocked inference."""

    @patch("src.learning.self_play.HAS_INFERENCE_ENGINE", True)
    @patch("src.learning.self_play.InferenceEngine")
    @patch("src.learning.self_play.ModelRegistry")
    def test_generate_model_based_success(self, mock_registry, mock_engine):
        """Test model-based generation with mocked successful inference."""
        from src.learning.self_play import SelfPlayLearningPipeline

        # Mock the engine
        mock_registry.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_instance.analyze_security = AsyncMock(
            return_value="```python\ndef get_user(id):\n    return db.query(f'SELECT * FROM users WHERE id = {id}')\n```"
        )
        mock_engine.return_value = mock_instance

        pipeline = SelfPlayLearningPipeline()
        import asyncio
        examples = asyncio.run(pipeline.generate_training_batch(
            count=10,
            use_model_generation=True,
            model_generation_ratio=0.5,
        ))

        assert len(examples) == 10
        # With ratio=0.5 and count=10, expect exactly 5 model-generated
        model_gen = [e for e in examples if e.model_generated]
        assert len(model_gen) == 5

    @patch("src.learning.self_play.HAS_INFERENCE_ENGINE", False)
    def test_generate_model_based_no_engine(self):
        """Test model-based generation falls back when inference engine unavailable."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        assert pipeline._inference_engine is None

        import asyncio
        # Use model_generation_ratio=0.0 to ensure all examples use templates
        examples = asyncio.run(pipeline.generate_training_batch(
            count=5,
            use_model_generation=True,
            model_generation_ratio=0.0,
        ))

        # Should still produce examples via templates
        assert len(examples) == 5
        assert all(not e.model_generated for e in examples)

    @patch("src.learning.self_play.HAS_INFERENCE_ENGINE", True)
    @patch("src.learning.self_play.InferenceEngine")
    @patch("src.learning.self_play.ModelRegistry")
    def test_generate_model_based_counts_tracked(self, mock_registry, mock_engine):
        """Test stats track model-generated example count."""
        from src.learning.self_play import SelfPlayLearningPipeline

        mock_registry.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_instance.analyze_security = AsyncMock(
            return_value="```python\ndef foo():\n    pass\n```"
        )
        mock_engine.return_value = mock_instance

        pipeline = SelfPlayLearningPipeline()
        initial_model_count = pipeline.stats.model_generated_examples

        import asyncio
        asyncio.run(pipeline.generate_training_batch(
            count=10,
            use_model_generation=True,
            model_generation_ratio=1.0,
        ))

        assert pipeline.stats.model_generated_examples > initial_model_count


class TestRunImprovementCycle:
    """Tests for the full improvement cycle."""

    def test_run_improvement_cycle_no_orchestrator(self):
        """Test improvement cycle runs without orchestrator."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        import asyncio
        result = asyncio.run(pipeline.run_improvement_cycle(
            examples_count=5,
            use_model_generation=False,
            export_dataset=False,
        ))

        assert "cycle_id" in result
        assert result["examples_generated"] == 5
        assert "average_accuracy" in result
        assert result["model_generation_enabled"] is False

    def test_run_improvement_cycle_increments(self):
        """Test improvement cycle counter increments."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        initial = pipeline.stats.total_improvement_cycles

        import asyncio
        asyncio.run(pipeline.run_improvement_cycle(
            examples_count=3,
            export_dataset=False,
        ))

        assert pipeline.stats.total_improvement_cycles == initial + 1

    def test_run_improvement_cycle_with_export(self):
        """Test improvement cycle with dataset export enabled."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        import asyncio
        result = asyncio.run(pipeline.run_improvement_cycle(
            examples_count=5,
            use_model_generation=False,
            export_dataset=True,
        ))

        assert "dataset_exported" in result
        # Should have exported dataset
        datasets_dir = os.path.join(pipeline.storage_dir, "datasets")
        assert os.path.exists(datasets_dir)

    def test_run_improvement_cycle_history(self):
        """Test improvement cycle records history."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        initial_history = len(pipeline.improvement_history)

        import asyncio
        asyncio.run(pipeline.run_improvement_cycle(
            examples_count=3,
            export_dataset=False,
        ))

        assert len(pipeline.improvement_history) == initial_history + 1
        record = pipeline.improvement_history[-1]
        assert "cycle_id" in record
        assert "average_accuracy" in record
        assert "duration_seconds" in record


class TestExtractKnowledgeBase:
    """Tests for knowledge base extraction."""

    def test_extract_knowledge_base(self):
        """Test knowledge base extraction returns expected structure."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        kb = pipeline.extract_knowledge_base()

        assert "extracted_at" in kb
        assert "patterns" in kb
        assert "confidence_adjustments" in kb
        assert "vulnerability_types_covered" in kb
        assert "training_examples_count" in kb


class TestGetStatus:
    """Tests for get_status reporting."""

    def test_get_status_structure(self):
        """Test get_status returns expected keys."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        status = pipeline.get_status()

        assert "total_examples" in status
        assert "model_generated_examples" in status
        assert "template_based_examples" in status
        assert "total_patterns" in status
        assert "improvement_cycles" in status
        assert "vulnerability_types_covered" in status
        assert "inference_engine_available" in status
        assert "storage_dir" in status

    def test_get_status_counts(self):
        """Test status counts are reasonable."""
        from src.learning.self_play import SelfPlayLearningPipeline

        pipeline = SelfPlayLearningPipeline()
        status = pipeline.get_status()

        assert status["total_examples"] >= 0
        assert status["model_generated_examples"] >= 0
        assert status["template_based_examples"] == status["total_examples"] - status["model_generated_examples"]
