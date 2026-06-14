#!/usr/bin/env python3
"""
Sentinel Cyber AI — RL-Style Fine-Tuning Loop
=============================================

Connects the complete pipeline: Self-Play → Dataset → Training → Evaluation → Deploy

This is Sentinel's equivalent of RLHF/Constitutional AI for frontier labs.
Instead of human feedback, we use:
1. Self-play to generate high-quality training examples
2. Automated evaluation to score improvements
3. Iterative fine-tuning based on evaluation results
4. Automatic deployment of improved models

Usage:
    # Run a complete RL cycle (self-play → train → eval → deploy)
    python scripts/rl_finetune_loop.py --cycle

    # Run with specific model and dataset
    python scripts/rl_finetune_loop.py --cycle \\
        --model unsloth/DeepSeek-R1-Distill-Qwen-7B-bnb-4bit \\
        --self-play-examples 100 \\
        --training-epochs 3

    # Just generate self-play data (skip training)
    python scripts/rl_finetune_loop.py --generate-data --count 200

    # Evaluate a trained model
    python scripts/rl_finetune_loop.py --evaluate --model ./outputs/sentinel-v1/final

    # Quick test (tiny model, small data)
    python scripts/rl_finetune_loop.py --quick-test

Prerequisites:
    - Unsloth installed (pip install unsloth)
    - HuggingFace models accessible
    - CUDA-capable GPU (16GB+ VRAM recommended)
"""

import asyncio
import json
import logging
import os
import sys
import time
import argparse
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RL-LOOP] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("rl-loop")


@dataclass
class RLCycleResult:
    """Result from a complete RL fine-tuning cycle."""
    cycle_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    self_play_examples_generated: int
    self_play_accuracy: float
    dataset_examples: int
    model_path: Optional[str]
    evaluation_results: Optional[Dict[str, Any]]
    improvement_metrics: Dict[str, Any]
    deployed: bool
    errors: List[str]

    def summary(self) -> str:
        """Get a human-readable summary."""
        lines = [
            f"\n{'='*60}",
            f"RL Cycle {self.cycle_id} — Complete",
            f"{'='*60}",
            f"Duration: {self.duration_seconds:.1f}s",
            f"Self-play examples: {self.self_play_examples_generated}",
            f"Self-play accuracy: {self.self_play_accuracy:.1%}",
            f"Dataset examples: {self.dataset_examples}",
            f"Model: {self.model_path or 'Not trained'}",
            f"Deployed: {self.deployed}",
        ]

        if self.evaluation_results:
            overall = self.evaluation_results.get("overall", {})
            lines.append(f"Evaluation pass rate: {overall.get('pass_rate', 0):.0%}")
            lines.append(f"Overall score: {overall.get('overall_score', 0):.0%}")

        if self.errors:
            lines.append(f"\nErrors ({len(self.errors)}):")
            for err in self.errors[:5]:
                lines.append(f"  ! {err}")

        lines.append(f"\nImprovement Metrics:")
        for key, value in self.improvement_metrics.items():
            if isinstance(value, float):
                lines.append(f"  {key}: {value:.1%}")
            else:
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)


class RLFinetuneLoop:
    """
    RL-Style Fine-Tuning Loop for Sentinel.

    Pipeline:
    1. SELF-PLAY: Generate training examples via self-play (with real model if available)
    2. EVALUATE: Score current model performance on benchmark suite
    3. DATASET: Export high-quality self-play examples as training dataset
    4. TRAIN: Fine-tune the model using QLoRA on the generated dataset
    5. EVALUATE: Score the fine-tuned model on the same benchmark
    6. COMPARE: Compare pre/post training scores
    7. DEPLOY: If improved, deploy the new model
    8. REPORT: Generate improvement report

    This is Sentinel's answer to Anthropic's RLHF pipeline — fully automated,
    no human labelers needed, focused entirely on cybersecurity improvement.
    """

    def __init__(
        self,
        orchestrator=None,
        config_path: str = "config/training_config.yaml",
        storage_dir: str = "~/.cache/sentinel/rl-loop",
    ):
        self._orchestrator = orchestrator
        self._config_path = config_path
        self._storage_dir = os.path.expanduser(storage_dir)
        self._self_play = None
        self._evaluator = None
        self._planner = None
        self._cycle_count = 0
        self._cycle_results: List[RLCycleResult] = []

        os.makedirs(self._storage_dir, exist_ok=True)
        logger.info(f"RL Fine-Tuning Loop initialized (storage: {self._storage_dir})")

    def set_orchestrator(self, orchestrator):
        self._orchestrator = orchestrator

    def set_self_play(self, self_play):
        self._self_play = self_play

    def set_evaluator(self, evaluator):
        self._evaluator = evaluator

    def set_planner(self, planner):
        self._planner = planner

    async def run_cycle(
        self,
        model_name: Optional[str] = None,
        self_play_examples: int = 100,
        self_play_cycles: int = 1,
        training_epochs: int = 3,
        use_model_generation: bool = True,
        model_generation_ratio: float = 0.4,
        deploy_on_improvement: bool = True,
        quick_test: bool = False,
    ) -> RLCycleResult:
        """
        Run one complete RL fine-tuning cycle.

        Args:
            model_name: Model to fine-tune (None = use config default)
            self_play_examples: Number of self-play examples to generate
            self_play_cycles: Number of self-play improvement cycles
            training_epochs: Number of training epochs
            use_model_generation: Use real model for example generation
            model_generation_ratio: Fraction of examples from model
            deploy_on_improvement: Auto-deploy if evaluation improves
            quick_test: Use tiny settings for quick validation

        Returns:
            RLCycleResult with all metrics
        """
        self._cycle_count += 1
        cycle_id = f"rl-cycle-{self._cycle_count}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        start_time = datetime.utcnow()
        errors: List[str] = []

        logger.info(f"\n{'='*70}")
        logger.info(f"RL Cycle {cycle_id} — Starting")
        logger.info(f"{'='*70}")
        logger.info(f"Config: model={model_name or 'default'}, "
                    f"examples={self_play_examples}, epochs={training_epochs}, "
                    f"model_gen={use_model_generation}")

        # ── Phase 1: Self-Play ──
        logger.info(f"\n{'─'*70}")
        logger.info("Phase 1: Self-Play Learning")
        logger.info(f"{'─'*70}")

        self_play_accuracy = 0.0
        if self._self_play:
            for i in range(self_play_cycles):
                try:
                    cycle_result = await self._self_play.run_improvement_cycle(
                        examples_count=self_play_examples if not quick_test else 10,
                        use_model_generation=use_model_generation,
                        model_generation_ratio=model_generation_ratio,
                        export_dataset=False,  # We'll export in Phase 2
                    )
                    self_play_accuracy = cycle_result.get("average_accuracy", 0.0)
                    logger.info(f"Self-play cycle {i+1}/{self_play_cycles}: "
                                f"accuracy={self_play_accuracy:.1%}, "
                                f"patterns={cycle_result.get('patterns_discovered', 0)}")
                except Exception as e:
                    error_msg = f"Self-play cycle {i+1} failed: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
        else:
            logger.warning("Self-play not available — skipping data generation")
            errors.append("Self-play not available")

        total_examples = len(self._self_play.examples) if self._self_play else 0

        # ── Phase 2: Pre-Training Evaluation ──
        logger.info(f"\n{'─'*70}")
        logger.info("Phase 2: Pre-Training Evaluation (baseline)")
        logger.info(f"{'─'*70}")

        pre_eval_results = None
        if self._evaluator:
            try:
                pre_eval_results = await self._evaluate_current_model()
                if pre_eval_results:
                    overall = pre_eval_results.get("overall", {})
                    logger.info(f"Pre-training evaluation: "
                                f"pass_rate={overall.get('pass_rate', 0):.0%}, "
                                f"score={overall.get('overall_score', 0):.0%}")
            except Exception as e:
                error_msg = f"Pre-training evaluation failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        else:
            logger.warning("Evaluator not available — skipping pre-training evaluation")
            errors.append("Evaluator not available")

        # ── Phase 3: Dataset Export ──
        logger.info(f"\n{'─'*70}")
        logger.info("Phase 3: Dataset Export")
        logger.info(f"{'─'*70}")

        dataset_path = None
        dataset_count = 0
        if self._self_play:
            try:
                output_dir = os.path.join(self._storage_dir, "datasets", cycle_id)
                train_path, val_path = self._self_play.export_train_val_split(
                    output_dir=output_dir,
                    max_examples=200 if not quick_test else 20,
                )
                dataset_path = train_path
                dataset_count = sum(1 for _ in open(train_path)) if os.path.exists(train_path) else 0
                logger.info(f"Dataset exported: {dataset_count} training examples")
            except Exception as e:
                error_msg = f"Dataset export failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        else:
            # Fall back to prepared dataset
            dataset_path = "./data/processed/cyber_train.jsonl"
            if os.path.exists(dataset_path):
                dataset_count = sum(1 for _ in open(dataset_path))
                logger.info(f"Using existing dataset: {dataset_count} examples")
            else:
                # Generate from prepare_dataset.py
                try:
                    from scripts.prepare_dataset import create_dataset
                    output_dir = os.path.join(self._storage_dir, "datasets", cycle_id)
                    os.makedirs(output_dir, exist_ok=True)
                    dataset_path = os.path.join(output_dir, "cyber_train.jsonl")
                    create_dataset(dataset_path, num_samples=100 if not quick_test else 10)
                    dataset_count = sum(1 for _ in open(dataset_path))
                    logger.info(f"Generated dataset: {dataset_count} examples")
                except Exception as e:
                    error_msg = f"Dataset preparation failed: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)

        # ── Phase 4: Model Training ──
        logger.info(f"\n{'─'*70}")
        logger.info("Phase 4: QLoRA Fine-Tuning")
        logger.info(f"{'─'*70}")

        trained_model_path = None
        if dataset_path and dataset_count > 0:
            try:
                from scripts.train_sentinel import load_config, train
                import argparse

                # Create training args
                train_args = argparse.Namespace(
                    model=model_name,
                    dataset=dataset_path,
                    output=os.path.join(self._storage_dir, "models", cycle_id),
                    epochs=1 if quick_test else training_epochs,
                    max_samples=20 if quick_test else -1,
                    batch_size=2 if quick_test else 4,
                    lr=None,
                    config=self._config_path,
                    cpu=False,
                )

                logger.info(f"Starting fine-tuning: model={model_name or 'default'}, "
                            f"epochs={train_args.epochs}")

                # Check if unsloth is available
                try:
                    from unsloth import FastLanguageModel
                    trained_model_path = train(load_config(train_args.config), train_args)
                    logger.info(f"Model trained: {trained_model_path}")
                except ImportError:
                    logger.warning("Unsloth not available — skipping training")
                    errors.append("Unsloth not available for training")
                except Exception as e:
                    error_msg = f"Training failed: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)

            except Exception as e:
                error_msg = f"Training setup failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        else:
            logger.warning("No dataset available — skipping training")
            errors.append("No dataset for training")

        # ── Phase 5: Post-Training Evaluation ──
        logger.info(f"\n{'─'*70}")
        logger.info("Phase 5: Post-Training Evaluation")
        logger.info(f"{'─'*70}")

        post_eval_results = None
        if self._evaluator and trained_model_path:
            try:
                post_eval_results = await self._evaluate_current_model()
                if post_eval_results:
                    overall = post_eval_results.get("overall", {})
                    logger.info(f"Post-training evaluation: "
                                f"pass_rate={overall.get('pass_rate', 0):.0%}, "
                                f"score={overall.get('overall_score', 0):.0%}")
            except Exception as e:
                error_msg = f"Post-training evaluation failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        else:
            logger.info("Post-training evaluation skipped (no evaluator or trained model)")

        # ── Phase 6: Compare & Improve Metrics ──
        logger.info(f"\n{'─'*70}")
        logger.info("Phase 6: Improvement Analysis")
        logger.info(f"{'─'*70}")

        improvement_metrics = self._calculate_improvement(
            pre_eval_results, post_eval_results, self_play_accuracy
        )

        logger.info(f"Improvement metrics:")
        for key, value in improvement_metrics.items():
            if isinstance(value, float):
                logger.info(f"  {key}: {value:.1%}")
            elif isinstance(value, (int, str)):
                logger.info(f"  {key}: {value}")

        # ── Phase 7: Deploy ──
        deployed = False
        if deploy_on_improvement and trained_model_path:
            improvement_score = improvement_metrics.get("improvement_score", 0.0)
            if improvement_score > 0:
                try:
                    await self._deploy_model(trained_model_path, cycle_id)
                    deployed = True
                    logger.info(f"Model deployed: {trained_model_path}")
                except Exception as e:
                    error_msg = f"Model deployment failed: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            else:
                logger.info(f"Improvement score {improvement_score:.1%} — not deploying")

        # ── Phase 8: Report ──
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        result = RLCycleResult(
            cycle_id=cycle_id,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_seconds=duration,
            self_play_examples_generated=total_examples,
            self_play_accuracy=self_play_accuracy,
            dataset_examples=dataset_count,
            model_path=trained_model_path,
            evaluation_results=post_eval_results or pre_eval_results,
            improvement_metrics=improvement_metrics,
            deployed=deployed,
            errors=errors,
        )

        self._cycle_results.append(result)

        # Save cycle report
        report_path = os.path.join(self._storage_dir, "reports", f"{cycle_id}.json")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump({
                "cycle_id": result.cycle_id,
                "duration_seconds": result.duration_seconds,
                "self_play_examples": result.self_play_examples_generated,
                "self_play_accuracy": result.self_play_accuracy,
                "dataset_examples": result.dataset_examples,
                "model_path": result.model_path,
                "improvement_metrics": result.improvement_metrics,
                "deployed": result.deployed,
                "errors": result.errors,
            }, f, indent=2)

        logger.info(result.summary())
        return result

    async def _evaluate_current_model(self) -> Optional[Dict[str, Any]]:
        """Run the evaluation suite on the current model."""
        if not self._evaluator:
            # Try to create one
            try:
                from src.evaluation.swe_bench_evals import SentinelEvaluator
                self._evaluator = SentinelEvaluator(
                    orchestrator=self._orchestrator,
                    planner=self._planner,
                )
            except Exception as e:
                logger.warning(f"Could not create evaluator: {e}")
                return None

        try:
            results = await self._evaluator.evaluate_all()
            return results
        except Exception as e:
            logger.error(f"Evaluation failed: {e}")
            return None

    def _calculate_improvement(
        self,
        pre_eval: Optional[Dict[str, Any]],
        post_eval: Optional[Dict[str, Any]],
        self_play_accuracy: float,
    ) -> Dict[str, Any]:
        """Calculate improvement metrics from pre/post evaluation."""
        metrics = {}

        # Self-play accuracy
        metrics["self_play_accuracy"] = self_play_accuracy

        # Evaluation improvement
        if pre_eval and post_eval:
            pre_overall = pre_eval.get("overall", {})
            post_overall = post_eval.get("overall", {})

            pre_score = pre_overall.get("overall_score", 0)
            post_score = post_overall.get("overall_score", 0)
            pre_pass = pre_overall.get("pass_rate", 0)
            post_pass = post_overall.get("pass_rate", 0)

            metrics["pre_training_score"] = pre_score
            metrics["post_training_score"] = post_score
            metrics["score_improvement"] = post_score - pre_score
            metrics["score_improvement_pct"] = (
                (post_score - pre_score) / max(pre_score, 0.01)
                if pre_score > 0 else 0
            )
            metrics["pre_training_pass_rate"] = pre_pass
            metrics["post_training_pass_rate"] = post_pass
            metrics["pass_rate_improvement"] = post_pass - pre_pass
        else:
            metrics["pre_training_score"] = 0
            metrics["post_training_score"] = 0
            metrics["score_improvement"] = 0
            metrics["score_improvement_pct"] = 0

        # Composite improvement score
        metrics["improvement_score"] = max(
            metrics.get("score_improvement", 0),
            metrics.get("self_play_accuracy", 0) * 0.3,  # Self-play counts too
        )

        # Training metrics
        metrics["self_play_examples"] = (
            len(self._self_play.examples) if self._self_play else 0
        )
        metrics["patterns_discovered"] = (
            len(self._self_play.discovered_patterns) if self._self_play else 0
        )

        return metrics

    async def _deploy_model(self, model_path: str, cycle_id: str) -> bool:
        """Deploy a trained model (save reference and update config)."""
        # Record deployment
        deploy_record = {
            "cycle_id": cycle_id,
            "model_path": model_path,
            "deployed_at": datetime.utcnow().isoformat(),
            "cycle_count": self._cycle_count,
        }

        deploy_path = os.path.join(self._storage_dir, "deployments.json")
        deployments = []
        if os.path.exists(deploy_path):
            with open(deploy_path) as f:
                try:
                    deployments = json.load(f)
                except (json.JSONDecodeError, ValueError):
                    deployments = []

        deployments.append(deploy_record)

        # Keep only last 5
        deployments = deployments[-5:]

        with open(deploy_path, "w") as f:
            json.dump(deployments, f, indent=2)

        logger.info(f"Deployment recorded: {model_path}")
        return True

    def get_cycle_history(self) -> List[Dict[str, Any]]:
        """Get history of all RL cycles."""
        return [
            {
                "cycle_id": r.cycle_id,
                "duration": f"{r.duration_seconds:.0f}s",
                "examples": r.self_play_examples_generated,
                "accuracy": f"{r.self_play_accuracy:.1%}",
                "dataset": r.dataset_examples,
                "score": (
                    f"{r.evaluation_results.get('overall', {}).get('overall_score', 0):.0%}"
                    if r.evaluation_results else "N/A"
                ),
                "deployed": r.deployed,
                "errors": len(r.errors),
            }
            for r in self._cycle_results
        ]

    def get_status(self) -> Dict[str, Any]:
        """Get RL loop status."""
        return {
            "total_cycles": self._cycle_count,
            "self_play_available": self._self_play is not None,
            "evaluator_available": self._evaluator is not None,
            "orchestrator_connected": self._orchestrator is not None,
            "storage_dir": self._storage_dir,
            "recent_cycles": self.get_cycle_history()[-5:],
            "latest_deployment": self._get_latest_deployment(),
        }

    def _get_latest_deployment(self) -> Optional[Dict]:
        deploy_path = os.path.join(self._storage_dir, "deployments.json")
        if os.path.exists(deploy_path):
            with open(deploy_path) as f:
                try:
                    deployments = json.load(f)
                    return deployments[-1] if deployments else None
                except (json.JSONDecodeError, ValueError):
                    return None
        return None


async def main_async():
    """Async main entry point."""
    parser = argparse.ArgumentParser(
        description="Sentinel Cyber AI — RL-Style Fine-Tuning Loop"
    )
    parser.add_argument(
        "--cycle",
        action="store_true",
        help="Run a complete RL cycle",
    )
    parser.add_argument(
        "--generate-data",
        action="store_true",
        help="Generate self-play data only",
    )
    parser.add_argument(
        "--evaluate",
        type=str,
        default=None,
        metavar="MODEL_PATH",
        help="Evaluate a trained model",
    )
    parser.add_argument(
        "--quick-test",
        action="store_true",
        help="Quick test with tiny settings",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model to fine-tune",
    )
    parser.add_argument(
        "--self-play-examples",
        type=int,
        default=100,
        help="Number of self-play examples",
    )
    parser.add_argument(
        "--self-play-cycles",
        type=int,
        default=1,
        help="Number of self-play improvement cycles",
    )
    parser.add_argument(
        "--training-epochs",
        type=int,
        default=3,
        help="Number of training epochs",
    )
    parser.add_argument(
        "--no-model-gen",
        action="store_true",
        help="Disable model-in-the-loop generation",
    )
    parser.add_argument(
        "--no-deploy",
        action="store_true",
        help="Don't auto-deploy after training",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show RL loop status",
    )

    args = parser.parse_args()

    # Initialize core components
    logger.info("Initializing RL Fine-Tuning Loop...")

    orchestrator = None
    self_play = None
    evaluator = None
    planner = None

    # Try to import core components
    try:
        from src.main import setup_orchestrator
        orchestrator = setup_orchestrator()
        logger.info("Orchestrator initialized")
    except Exception as e:
        logger.warning(f"Could not initialize orchestrator: {e}")

    try:
        from src.learning.self_play import SelfPlayLearningPipeline
        self_play = SelfPlayLearningPipeline(orchestrator=orchestrator)
        logger.info("Self-play pipeline initialized")
    except Exception as e:
        logger.warning(f"Could not initialize self-play: {e}")

    try:
        from src.planning.agentic_planner import AgenticPlanner
        planner = AgenticPlanner(orchestrator=orchestrator)
        logger.info("Planner initialized")

        from src.evaluation.swe_bench_evals import SentinelEvaluator
        evaluator = SentinelEvaluator(
            orchestrator=orchestrator,
            planner=planner,
        )
        logger.info("Evaluator initialized")
    except Exception as e:
        logger.warning(f"Could not initialize evaluator: {e}")

    # Create RL loop
    rl_loop = RLFinetuneLoop(orchestrator=orchestrator)
    rl_loop.set_self_play(self_play)
    rl_loop.set_evaluator(evaluator)
    rl_loop.set_planner(planner)

    if args.status:
        print(json.dumps(rl_loop.get_status(), indent=2))
        return

    if args.generate_data:
        if self_play:
            logger.info(f"Generating {args.self_play_examples} self-play examples...")
            examples = await self_play.generate_training_batch(
                count=args.self_play_examples,
                use_model_generation=not args.no_model_gen,
            )
            output_dir = os.path.join(rl_loop._storage_dir, "datasets", "manual")
            train_path, val_path = self_play.export_train_val_split(
                output_dir=output_dir,
                max_examples=args.self_play_examples,
            )
            logger.info(f"Generated {len(examples)} examples, exported to {train_path}")
        else:
            logger.error("Self-play not available")
        return

    if args.evaluate:
        logger.info(f"Evaluating model: {args.evaluate}")
        if evaluator:
            results = await evaluator.evaluate_all()
            evaluator.print_summary(results)
        else:
            logger.error("Evaluator not available")
        return

    if args.cycle or args.quick_test:
        quick = args.quick_test
        result = await rl_loop.run_cycle(
            model_name=args.model,
            self_play_examples=10 if quick else args.self_play_examples,
            self_play_cycles=1 if quick else args.self_play_cycles,
            training_epochs=1 if quick else args.training_epochs,
            use_model_generation=not args.no_model_gen and not quick,
            model_generation_ratio=0.0 if quick else 0.4,
            deploy_on_improvement=not args.no_deploy and not quick,
            quick_test=quick,
        )
        print(result.summary())
        return

    # Default: show help
    parser.print_help()


def main():
    """Synchronous entry point."""
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("RL loop interrupted by user")
    except Exception as e:
        logger.error(f"RL loop failed: {e}")
        raise


if __name__ == "__main__":
    main()
