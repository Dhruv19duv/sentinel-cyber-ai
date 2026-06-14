#!/usr/bin/env python3
"""Deploy Sentinel Cyber AI to production.

Usage:
    python scripts/deploy.py                   # Interactive deploy
    python scripts/deploy.py --docker          # Deploy with Docker
    python scripts/deploy.py --api-only        # Deploy API server only
    python scripts/deploy.py --check           # Check deployment requirements
    
Environment Variables:
    SENTINEL_API_KEY          API key for authentication
    SENTINEL_CORS_ORIGINS     Comma-separated allowed origins
    SENTINEL_MODEL_PATH       Path to fine-tuned model
    SENTINEL_GPU              GPU device IDs (default: "0")
"""

import sys
import os
import subprocess
import argparse
import json
from pathlib import Path


def check_requirements():
    """Check system requirements for deployment."""
    checks = {}

    # Python version
    checks["python"] = sys.version_info >= (3, 10)

    # Docker
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        checks["docker"] = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        checks["docker"] = False

    # Docker Compose
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=5,
        )
        checks["docker_compose"] = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        checks["docker_compose"] = False

    # CUDA availability
    try:
        import torch
        checks["cuda"] = torch.cuda.is_available()
        if checks["cuda"]:
            checks["gpu_name"] = torch.cuda.get_device_name(0)
            checks["vram_gb"] = torch.cuda.get_device_properties(0).total_mem / 1e9
    except ImportError:
        checks["cuda"] = False

    # Required Python packages
    required_packages = [
        "fastapi", "uvicorn", "torch", "transformers",
        "unsloth", "datasets", "pyyaml",
    ]
    checks["packages"] = {}
    for pkg in required_packages:
        try:
            __import__(pkg.replace("-", "_"))
            checks["packages"][pkg] = True
        except ImportError:
            checks["packages"][pkg] = False

    return checks


def deploy_docker():
    """Deploy with Docker Compose."""
    print("\n🐳 Deploying with Docker Compose...\n")

    # Build the image
    print("📦 Building Docker image...")
    result = subprocess.run(
        ["docker", "compose", "-f", "docker/docker-compose.yml", "build"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"❌ Build failed: {result.stderr[:500]}")
        return False

    # Start the service
    print("🚀 Starting Sentinel API...")
    result = subprocess.run(
        ["docker", "compose", "-f", "docker/docker-compose.yml", "up", "-d"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"❌ Deploy failed: {result.stderr[:500]}")
        return False

    print("✅ Sentinel API deployed!")
    print("   API: http://localhost:8080")
    print("   Docs: http://localhost:8080/docs")
    print("   Health: http://localhost:8080/health")
    return True


def deploy_api_only():
    """Deploy the API server directly (no Docker)."""
    print("\n🚀 Starting Sentinel API server...\n")
    from src.api.server import serve
    serve()


def print_report(checks: dict):
    """Print deployment readiness report."""
    print("\n" + "=" * 60)
    print("🔐 Sentinel Deployment Readiness Report")
    print("=" * 60)

    # System
    print(f"\n📦 Python: {'✅' if checks.get('python') else '❌'} >= 3.10")
    print(f"   Version: {sys.version.split()[0]}")

    # Docker
    print(f"\n🐳 Docker: {'✅' if checks.get('docker') else '❌'} Available")
    print(f"   Compose: {'✅' if checks.get('docker_compose') else '❌'}")

    # GPU
    if checks.get("cuda"):
        print(f"\n🖥️  GPU: ✅ {checks.get('gpu_name', 'Unknown')}")
        print(f"   VRAM: {checks.get('vram_gb', 0):.1f} GB")
    else:
        print(f"\n🖥️  GPU: ⚠️  Not available (CPU only)")

    # Packages
    print(f"\n📋 Required Packages:")
    for pkg, installed in checks.get("packages", {}).items():
        print(f"   {'✅' if installed else '❌'} {pkg}")

    # Overall
    all_ok = all([
        checks.get("python"),
        checks.get("docker"),
        checks.get("docker_compose"),
        all(checks.get("packages", {}).values()),
    ])
    print(f"\n{'='*60}")
    print(f"  {'✅ Ready to deploy!' if all_ok else '⚠️  Some checks failed, but you can still deploy.'}")
    print(f"{'='*60}")

    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description="Deploy Sentinel Cyber AI to production"
    )
    parser.add_argument(
        "--docker", action="store_true",
        help="Deploy with Docker Compose"
    )
    parser.add_argument(
        "--api-only", action="store_true",
        help="Deploy API server only (no Docker)"
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Check deployment requirements"
    )
    args = parser.parse_args()

    if args.check:
        checks = check_requirements()
        print_report(checks)
        return

    if args.docker:
        deploy_docker()
    elif args.api_only:
        deploy_api_only()
    else:
        # Interactive: check first, then ask
        print("\n🔐 Sentinel Cyber AI Deployment")
        print("=" * 60)
        checks = check_requirements()
        ready = print_report(checks)

        if ready:
            print("\n🚀 Ready to deploy!")
            print("\nOptions:")
            print("  1. Deploy with Docker Compose (recommended)")
            print("  2. Deploy API server only")
            print("  3. Exit")
            choice = input("\nChoose (1-3): ").strip()

            if choice == "1":
                deploy_docker()
            elif choice == "2":
                deploy_api_only()
            else:
                print("Deployment cancelled.")
        else:
            print("\n⚠️  Some requirements are missing.")
            print("Fix the issues above and try again.")
            print("Or use --api-only to deploy without Docker.")


if __name__ == "__main__":
    main()
