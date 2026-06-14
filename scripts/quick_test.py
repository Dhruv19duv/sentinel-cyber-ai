#!/usr/bin/env python3
"""
Sentinel Cyber AI - Quick Test
==============================
Verify that the project setup is correct and dependencies are installed.

Usage:
    python scripts/quick_test.py
"""

import sys
import os
import importlib
import importlib.util
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

REQUIRED_PACKAGES = [
    "torch",
    "transformers",
    "datasets",
    "accelerate",
    "peft",
    "trl",
    "sentencepiece",
    "protobuf",
]

OPTIONAL_PACKAGES = [
    ("bitsandbytes", "For 4-bit quantization on GPU"),
    ("scipy", "For evaluation metrics"),
    ("requests", "For downloading datasets"),
    ("yaml", "For loading config files (pyyaml)"),
]


def check_packages():
    """Check that all required packages are installed."""
    all_ok = True

    print("\n" + "=" * 50)
    print("  🔐 Sentinel Cyber AI — System Check")
    print("=" * 50)

    # Python version
    print(f"\n📦 Python: {sys.version.split()[0]}")
    print(f"   Path: {sys.executable}")

    # Required packages
    print(f"\n📋 Required Packages:")
    for package in REQUIRED_PACKAGES:
        try:
            mod = importlib.import_module(package)
            version = getattr(mod, "__version__", "unknown")
            print(f"   ✅ {package}: {version}")
        except ImportError:
            print(f"   ❌ {package}: NOT INSTALLED")
            all_ok = False

    # Optional packages
    print(f"\n📋 Optional Packages:")
    for package, desc in OPTIONAL_PACKAGES:
        try:
            mod = importlib.import_module(package)
            version = getattr(mod, "__version__", "unknown")
            print(f"   ✅ {package}: {version} ({desc})")
        except ImportError:
            print(f"   ⚠️  {package}: NOT INSTALLED ({desc})")

    # CUDA availability
    print(f"\n🖥️  Hardware:")
    import torch
    if torch.cuda.is_available():
        print(f"   ✅ CUDA available")
        print(f"   GPU: {torch.cuda.get_device_name(0)}")
        print(f"   VRAM: {torch.cuda.get_device_properties(0).total_mem / 1e9:.1f} GB")
        print(f"   BF16 support: {torch.cuda.is_bf16_supported()}")
    else:
        print(f"   ⚠️  CUDA NOT available (will use CPU)")
        try:
            import psutil
            ram_gb = psutil.virtual_memory().total / 1e9
            print(f"   RAM: {ram_gb:.1f} GB")
        except ImportError:
            print("   (install psutil for RAM info)")

    # summary
    print(f"\n{'='*50}")
    if all_ok:
        print("  ✅ All required packages are installed!")
        print("  You're ready to train!")
    else:
        print("  ❌ Some required packages are missing.")
        print("  Run: pip install -r requirements.txt")
    print(f"{'='*50}\n")

    return all_ok


def test_dataset_creation():
    """Test that the dataset preparation script works."""
    print("\n📊 Testing dataset preparation...")
    try:
        from scripts.prepare_dataset import create_dataset
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            temp_path = f.name
        
        create_dataset(temp_path, num_samples=5)
        
        with open(temp_path, "r") as f:
            count = sum(1 for _ in f)
        
        os.unlink(temp_path)
        print(f"   ✅ Dataset creation works! Created {count} examples.")
        return True
    except Exception as e:
        print(f"   ⚠️  Dataset test: {e}")
        return False


if __name__ == "__main__":
    ok = check_packages()
    
    sys.exit(0 if ok else 1)
