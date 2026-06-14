#!/usr/bin/env python3
"""Run the Sentinel multi-agent system.

Usage:
    # Analyze a security query
    python scripts/run_agent.py analyze "find vulnerabilities in eval(request.GET.get('code'))"
    
    # Interactive mode
    python scripts/run_agent.py interactive
    
    # Start API server
    python scripts/run_agent.py serve
    
    # Run benchmarks
    python scripts/run_agent.py benchmark
    
    # Scan a codebase
    python scripts/run_agent.py scan /path/to/project
    
    # Generate report from analysis
    python scripts/run_agent.py report --task-id <task_id>
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.main import main

if __name__ == "__main__":
    main()
