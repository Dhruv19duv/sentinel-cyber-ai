#!/usr/bin/env python3
"""
Sentinel Cyber AI - Inference Script
====================================
Test your fine-tuned model on cybersecurity tasks.

Usage:
    # Test a fine-tuned model
    python scripts/inference.py --model ./outputs/sentinel-v1/final
    
    # Test with a specific prompt
    python scripts/inference.py \
        --model ./outputs/sentinel-v1/final \
        --prompt "Find vulnerabilities in: eval(request.GET.get('code'))"
    
    # Interactive mode (chat-like)
    python scripts/inference.py --model ./outputs/sentinel-v1/final --interactive
    
    # Use the base model directly (no fine-tuning)
    python scripts/inference.py --model unsloth/DeepSeek-R1-Distill-Qwen-7B-bnb-4bit
    
    # Run on CPU
    python scripts/inference.py --model ./outputs/sentinel-v1/final --cpu
"""

import os
import sys
import json
import argparse
import logging
from typing import Optional

import torch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# Example prompts to test with
EXAMPLE_PROMPTS = [
    {
        "name": "SQL Injection Detection",
        "prompt": "Analyze this code for security vulnerabilities:\n\ndef login(username, password):\n    query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n    return db.execute(query)",
    },
    {
        "name": "Command Injection",
        "prompt": "Find vulnerabilities in this code:\n\nimport subprocess\ndef ping(host):\n    return subprocess.run(f'ping {host}', shell=True)",
    },
    {
        "name": "Secure Password Storage",
        "prompt": "How should I store user passwords securely? Show code.",
    },
    {
        "name": "XSS Detection",
        "prompt": "Is this code vulnerable?\n\ndocument.getElementById('output').innerHTML = user_input;",
    },
]


def load_model(model_path: str, use_cpu: bool = False, max_seq_length: int = 4096):
    """Load a fine-tuned or base model."""
    from unsloth import FastLanguageModel

    device = "cpu" if use_cpu else "auto"

    logger.info(f"Loading model from: {model_path}")
    logger.info(f"Device: {device}")

    if torch.cuda.is_available() and not use_cpu:
        logger.info(f"GPU: {torch.cuda.get_device_name(0)}")

    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_path,
            max_seq_length=max_seq_length,
            dtype=None,
            load_in_4bit=not use_cpu,
            device_map=device,
        )
    except Exception as e:
        logger.warning(f"Could not load as full model, trying as adapter: {e}")
        # Try loading as a LoRA adapter on top of a base model
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_path,
            max_seq_length=max_seq_length,
            dtype=None,
            load_in_4bit=not use_cpu,
            device_map=device,
            use_safetensors=True,
        )

    FastLanguageModel.for_inference(model)
    logger.info("Model loaded successfully!")
    
    return model, tokenizer


def generate_response(
    model,
    tokenizer,
    prompt: str,
    max_new_tokens: int = 1024,
    temperature: float = 0.7,
    top_p: float = 0.95,
    top_k: int = 40,
    repetition_penalty: float = 1.1,
    do_sample: bool = True,
) -> str:
    """Generate a response from the model."""
    messages = [
        {"role": "user", "content": prompt},
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt",
    ).to(model.device)

    outputs = model.generate(
        input_ids=inputs,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        top_p=top_p,
        top_k=top_k,
        repetition_penalty=repetition_penalty,
        do_sample=do_sample,
        pad_token_id=tokenizer.eos_token_id,
    )

    response = tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
    return response.strip()


def run_interactive(model, tokenizer):
    """Run an interactive chat session."""
    print("\n" + "=" * 60)
    print("🔐 Sentinel Cyber AI — Interactive Mode")
    print("=" * 60)
    print("Type 'quit' to exit, 'example' to try an example prompt.")
    print()

    while True:
        try:
            user_input = input("\n🧑 You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break

        if user_input.lower() == "example":
            print("\nAvailable examples:")
            for i, ex in enumerate(EXAMPLE_PROMPTS, 1):
                print(f"  {i}. {ex['name']}")
            
            try:
                choice = input("\nChoose example (1-{}): ".format(len(EXAMPLE_PROMPTS)))
                idx = int(choice) - 1
                if 0 <= idx < len(EXAMPLE_PROMPTS):
                    user_input = EXAMPLE_PROMPTS[idx]["prompt"]
                    print(f"\n📝 Prompt: {user_input[:80]}...")
                else:
                    print("Invalid choice.")
                    continue
            except (ValueError, IndexError):
                print("Invalid choice.")
                continue

        print("\n🤖 Sentinel: ", end="", flush=True)
        response = generate_response(model, tokenizer, user_input)
        print(response)
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Cyber AI - Run inference on fine-tuned models"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="./outputs/sentinel-v1/final",
        help="Path to fine-tuned model or HuggingFace model name",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Single prompt to run",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive chat mode",
    )
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Run all example prompts",
    )
    parser.add_argument(
        "--max_tokens",
        type=int,
        default=1024,
        help="Maximum tokens to generate",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Sampling temperature",
    )
    parser.add_argument(
        "--cpu",
        action="store_true",
        help="Force CPU inference",
    )
    args = parser.parse_args()

    # Load model
    model, tokenizer = load_model(args.model, use_cpu=args.cpu)

    if args.interactive:
        run_interactive(model, tokenizer)
    elif args.examples:
        print(f"\n{'='*60}")
        print("🔐 Sentinel Cyber AI — Running Example Prompts")
        print(f"{'='*60}\n")
        
        for ex in EXAMPLE_PROMPTS:
            print(f"{'─'*60}")
            print(f"📝 Example: {ex['name']}")
            print(f"{'─'*60}")
            print(f"Prompt: {ex['prompt'][:100]}...\n")
            
            response = generate_response(model, tokenizer, ex["prompt"])
            print(f"Response:\n{response}\n")
    elif args.prompt:
        print(f"\n📝 Prompt: {args.prompt}\n")
        print("🤖 Response:")
        response = generate_response(
            model, tokenizer, args.prompt,
            max_new_tokens=args.max_tokens,
            temperature=args.temperature,
        )
        print(response)
    else:
        # Interactive mode by default if no other mode specified
        run_interactive(model, tokenizer)


if __name__ == "__main__":
    try:
        from unsloth import FastLanguageModel
    except ImportError:
        logger.error(
            "Unsloth not installed. Install with:\n"
            "  pip install unsloth\n"
            "  # Or for full GPU support:\n"
            "  pip install \"unsloth[cu124] @ git+https://github.com/unslothai/unsloth.git\""
        )
        sys.exit(1)

    main()
