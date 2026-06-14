#!/usr/bin/env python3
"""
Sentinel Cyber AI - Training Script
====================================
Fine-tune open-source LLMs for cybersecurity tasks using QLoRA.

Usage:
    # Train with default config
    python scripts/train_sentinel.py

    # Train with specific model and dataset
    python scripts/train_sentinel.py \
        --model unsloth/DeepSeek-R1-Distill-Qwen-7B-bnb-4bit \
        --dataset ./data/processed/cyber_train.jsonl \
        --output ./outputs/sentinel-v1

    # Quick test with tiny model on CPU
    python scripts/train_sentinel.py \
        --model unsloth/DeepSeek-R1-Distill-Qwen-1.5B-bnb-4bit \
        --dataset ./data/processed/cyber_train.jsonl \
        --max_samples 20 --epochs 1
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Optional, Dict, Any

import torch
import yaml
from datasets import Dataset, load_dataset
from transformers import (
    AutoTokenizer,
    TrainingArguments,
    BitsAndBytesConfig,
)
from trl import SFTTrainer
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_config(config_path: str = "config/training_config.yaml") -> Dict[str, Any]:
    """Load training configuration from YAML file."""
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    logger.info(f"Loaded configuration from {config_path}")
    return config


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Sentinel Cyber AI - Fine-tune LLMs for cybersecurity"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Base model to fine-tune (overrides config)",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Path to training dataset JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory for the trained model",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=None,
        help="Number of training epochs (overrides config)",
    )
    parser.add_argument(
        "--max_samples",
        type=int,
        default=None,
        help="Maximum number of training samples to use",
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=None,
        help="Per-device training batch size",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=None,
        help="Learning rate (overrides config)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/training_config.yaml",
        help="Path to config YAML file",
    )
    parser.add_argument(
        "--cpu",
        action="store_true",
        help="Force CPU training (for machines without GPU)",
    )
    return parser.parse_args()


def load_dataset_from_jsonl(file_path: str, max_samples: int = -1) -> Dataset:
    """Load dataset from a JSONL file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    data = []
    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if max_samples > 0 and i >= max_samples:
                break
            data.append(json.loads(line.strip()))

    logger.info(f"Loaded {len(data)} examples from {file_path}")
    return Dataset.from_list(data)


def format_chat_template(example: Dict[str, str], tokenizer) -> str:
    """Format a training example using the chat template format."""
    # The dataset should have instruction, input, and output fields
    instruction = example.get("instruction", "")
    input_text = example.get("input", "")
    output_text = example.get("output", "")

    if input_text:
        user_message = f"{instruction}\n\n{input_text}"
    else:
        user_message = instruction

    # Format as a conversation
    messages = [
        {"role": "user", "content": user_message},
        {"role": "assistant", "content": output_text},
    ]

    return tokenizer.apply_chat_template(messages, tokenize=False)


def setup_model_and_tokenizer(
    model_name: str,
    use_4bit: bool = True,
    max_seq_length: int = 4096,
    device: str = "auto",
):
    """Load the base model and tokenizer with quantization."""
    from unsloth import FastLanguageModel

    logger.info(f"Loading model: {model_name}")

    # Determine compute dtype based on available hardware
    if device == "cpu" or not torch.cuda.is_available():
        logger.info("No GPU detected or CPU mode forced — loading in full precision")
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=max_seq_length,
            dtype=None,
            load_in_4bit=False,
            device_map=device,
        )
    else:
        # Check for bfloat16 support
        bf16_supported = torch.cuda.is_bf16_supported()
        compute_dtype = torch.bfloat16 if bf16_supported else torch.float16
        logger.info(
            f"GPU detected: {torch.cuda.get_device_name(0)} | "
            f"BF16: {bf16_supported} | "
            f"4-bit: {use_4bit}"
        )

        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=max_seq_length,
            dtype=compute_dtype,
            load_in_4bit=use_4bit,
            device_map="auto",
        )

    # Set padding token if not set
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    logger.info(f"Model loaded: {model_name}")
    logger.info(f"Model parameters: {model.num_parameters():,}")

    return model, tokenizer


def setup_lora(model, lora_config: Dict[str, Any]):
    """Apply LoRA configuration to the model."""
    from unsloth import is_bfloat16_supported

    model = FastLanguageModel.get_peft_model(
        model,
        r=lora_config.get("r", 32),
        target_modules=lora_config.get("target_modules", None),
        lora_alpha=lora_config.get("lora_alpha", 64),
        lora_dropout=lora_config.get("lora_dropout", 0.05),
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
        use_rslora=False,
        loftq_config=None,
    )

    logger.info("LoRA applied to model")
    return model


def train(config: Dict[str, Any], args: argparse.Namespace):
    """Run the full training pipeline."""
    # Resolve model name
    model_name = args.model or config["model"]["base_model"]
    output_dir = args.output or config["training"]["output_dir"]
    max_seq_length = config["model"].get("max_seq_length", 4096)
    use_4bit = config["model"].get("load_in_4bit", True) and not args.cpu
    device = "cpu" if args.cpu else "auto"

    # Load model and tokenizer
    model, tokenizer = setup_model_and_tokenizer(
        model_name, use_4bit=use_4bit, max_seq_length=max_seq_length, device=device
    )

    # Load dataset
    dataset_path = args.dataset or config["dataset"]["train_file"]
    max_samples = args.max_samples or config["dataset"].get("max_train_samples", -1)

    logger.info(f"Loading dataset from: {dataset_path}")
    dataset = load_dataset_from_jsonl(dataset_path, max_samples)

    # Split into train/validation
    val_file = config["dataset"].get("val_file", None)
    if val_file and os.path.exists(val_file):
        max_val = config["dataset"].get("max_val_samples", 100)
        val_dataset = load_dataset_from_jsonl(val_file, max_val)
        train_dataset = dataset
        logger.info(f"Train: {len(train_dataset)} | Val: {len(val_dataset)}")
    else:
        split_ratio = config["dataset"].get("train_val_split", 0.9)
        split = dataset.train_test_split(test_size=1 - split_ratio, seed=42)
        train_dataset = split["train"]
        val_dataset = split["test"]
        logger.info(
            f"Split dataset: Train {len(train_dataset)} | Val {len(val_dataset)}"
        )

    # Format datasets with chat template
    def format_fn(examples):
        texts = [
            format_chat_template(
                {"instruction": inst, "input": inp, "output": out}, tokenizer
            )
            for inst, inp, out in zip(
                examples.get("instruction", [""] * len(examples["input"])),
                examples.get("input", [""] * len(examples["input"])),
                examples["output"],
            )
        ]
        return {"text": texts}

    train_dataset = train_dataset.map(format_fn, batched=True, remove_columns=train_dataset.column_names)
    val_dataset = val_dataset.map(format_fn, batched=True, remove_columns=val_dataset.column_names)

    # Training arguments
    training_config = config["training"]
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=args.epochs or training_config.get("num_epochs", 3),
        per_device_train_batch_size=args.batch_size or training_config.get("per_device_train_batch_size", 4),
        per_device_eval_batch_size=training_config.get("per_device_eval_batch_size", 4),
        gradient_accumulation_steps=training_config.get("gradient_accumulation_steps", 4),
        learning_rate=args.lr or training_config.get("learning_rate", 2e-4),
        warmup_ratio=training_config.get("warmup_ratio", 0.03),
        lr_scheduler_type=training_config.get("lr_scheduler_type", "cosine"),
        optim=training_config.get("optimizer", "adamw_8bit"),
        logging_steps=training_config.get("logging_steps", 10),
        save_steps=training_config.get("save_steps", 100),
        eval_steps=training_config.get("eval_steps", 100),
        evaluation_strategy="steps",
        save_strategy="steps",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        bf16=training_config.get("bf16", False) and torch.cuda.is_bf16_supported(),
        fp16=training_config.get("fp16", True) and not torch.cuda.is_bf16_supported(),
        report_to="none",
        remove_unused_columns=False,
        dataloader_num_workers=0,
        save_total_limit=3,
        seed=42,
    )

    # Initialize SFT Trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        args=training_args,
        max_seq_length=max_seq_length,
        dataset_text_field="text",
    )

    # Train
    logger.info("🚀 Starting training...")
    trainer.train()

    # Save final model
    final_output_dir = os.path.join(output_dir, "final")
    logger.info(f"💾 Saving model to {final_output_dir}")
    trainer.model.save_pretrained(final_output_dir)
    tokenizer.save_pretrained(final_output_dir)

    # Save merged model (full weights, no LoRA adapters)
    merged_output_dir = os.path.join(output_dir, "merged")
    logger.info(f"🔄 Saving merged model to {merged_output_dir}")
    try:
        from unsloth import FastLanguageModel
        merged_model = FastLanguageModel.get_merged_model(trainer.model)
        merged_model.save_pretrained(merged_output_dir)
        tokenizer.save_pretrained(merged_output_dir)
        logger.info("✅ Model merged and saved successfully!")
    except Exception as e:
        logger.warning(f"Could not save merged model: {e}")
        logger.info("The LoRA adapter weights are saved and functional.")

    logger.info("✨ Training complete!")
    return final_output_dir


def main():
    args = parse_args()
    config = load_config(args.config)
    train(config, args)


if __name__ == "__main__":
    # Import unsloth lazily to avoid import errors on CPU-only machines
    try:
        from unsloth import FastLanguageModel
    except ImportError:
        logger.warning(
            "Unsloth not installed. Install with:\n"
            "  pip install unsloth\n"
            "  # Or for full GPU support:\n"
            "  pip install \"unsloth[cu124] @ git+https://github.com/unslothai/unsloth.git\""
        )
        sys.exit(1)

    main()
