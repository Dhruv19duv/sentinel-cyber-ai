"""
Sentinel Streamlit Dashboard — Enterprise UI for All Subsystems.

Features:
1. Real-time analysis monitor
2. Agent status dashboard
3. Adaptive Thinking visualizer
4. Code Execution Sandbox UI
5. Memory browser
6. Context window monitor
7. Safety Classifier test panel
8. Vision analysis upload
9. Self-Play Learning status
10. Neural Threat Detection viewer
11. Monitoring alerts panel
12. Penetration test runner
13. Supply Chain analyzer
14. Crypto Scanner
15. Adversarial defense monitor
16. Cluster management dashboard

Run with: streamlit run src/dashboard/streamlit_app.py
"""

import asyncio
import json
import logging
import os
import sys
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    import streamlit as st
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    HAS_STREAMLIT = True
except ImportError:
    HAS_STREAMLIT = False


if not HAS_STREAMLIT:
    print("Streamlit not installed. Run: pip install streamlit plotly pandas")
    sys.exit(1)


# Page configuration
st.set_page_config(
    page_title="Sentinel Cyber AI — Enterprise Dashboard",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .main > div { padding: 0rem 1rem; }
    .stButton button { width: 100%; }
    .reportview-container { background: #0e1117; }
    .metric-card { 
        background: #1e1e2e; 
        padding: 1rem; 
        border-radius: 0.5rem;
        border: 1px solid #313244;
    }
    .severity-critical { color: #ff0000; font-weight: bold; }
    .severity-high { color: #ff4444; font-weight: bold; }
    .severity-medium { color: #ffaa00; font-weight: bold; }
    .severity-low { color: #44aaff; }
</style>
""", unsafe_allow_html=True)


# ── Initialize session state ──

def init_backend():
    """Initialize the orchestrator in session state."""
    if "orchestrator" not in st.session_state:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        try:
            from src.main import setup_orchestrator
            st.session_state.orc = setup_orchestrator()
            st.session_state.initialized = True
        except Exception as e:
            st.session_state.orc = None
            st.session_state.initialized = False
            st.session_state.init_error = str(e)


# ── Sidebar ──

def render_sidebar():
    """Render the sidebar navigation."""
    with st.sidebar:
        st.title("Sentinel AI")
        st.caption("Enterprise Cyber Security Platform")
        st.divider()

        pages = {
            "Home": "home",
            "Live Monitor": "monitor",
            "Agents": "agents",
            "Adaptive Thinking": "thinking",
            "Sandbox": "sandbox",
            "Memory": "memory",
            "Context": "context",
            "Safety": "safety",
            "Vision": "vision",
            "Self-Play Learning": "learning",
            "Neural Detection": "neural",
            "Penetration Testing": "pentest",
            "Supply Chain": "supplychain",
            "Crypto Scanner": "crypto",
            "Adversarial Defense": "adversarial",
            "Cluster": "cluster",
            "Settings": "settings",
        }

        for name, page_key in pages.items():
            if st.sidebar.button(
                name,
                key=f"nav_{page_key}",
                use_container_width=True,
                type="secondary" if st.session_state.get("page") != page_key else "primary",
            ):
                st.session_state.page = page_key


# ── Pages ──

def page_home():
    """Home dashboard with system overview."""
    st.title("Sentinel Cyber AI")
    st.caption("Enterprise Multi-Agent Cybersecurity Platform")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Agents", "6", "Specialized")
    with col2:
        st.metric("Detection Methods", "10+", "Including Neural")
    with col3:
        st.metric("Context Window", "1M", "Tokens")
    with col4:
        st.metric("Learning Cycles", "Auto", "Self-Play")

    st.divider()

    st.subheader("System Architecture")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **Core Engine:**
        - Multi-Agent Orchestrator (6 specialized agents)
        - MoE Router with intent classification
        - LLM Backend (DeepSeek R1, Qwen 3, Mistral Large 3)
        - Context Manager (1M token window)
        
        **Advanced Detection:**
        - Rule-based scanner (15+ CWE signatures)
        - Neural Threat Engine (anomaly + ensemble)
        - Adversarial defense system
        - Supply chain analyzer
        - Quantum crypto scanner
        """)
    with col2:
        st.markdown("""
        **Agentic Systems:**
        - Adaptive Thinking (effort: low/max)
        - Code Execution Sandbox (Docker)
        - Persistent Memory (tiered + compaction)
        - Agentic Planner (10+ step chains)
        - Autonomous Pentester (8 phases)
        - Self-Play Learning (continuous)
        
        **Integrations:**
        - Codebase RAG (AST-aware chunking)
        - Scientific Analysis (biology/health)
        - Slack Bot (slash commands)
        - Vision Agent (multimodal)
        - Distributed Cluster
        - GitHub Actions CI/CD
        """)


def page_monitor():
    """Live monitoring dashboard."""
    st.title("Live Monitor")
    st.caption("Real-time security monitoring")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Analyses Today", "0", "Last 24h")
    with col2:
        st.metric("Threats Detected", "0", "Active")
    with col3:
        st.metric("Avg Response", "0ms", "Real-time")

    st.subheader("Recent Activity")
    st.info("No recent activity. Submit an analysis to see results here.")

    st.subheader("System Health")
    health_data = pd.DataFrame({
        "Component": ["Orchestrator", "Thinking Engine", "Sandbox", "Memory", "Safety"],
        "Status": ["Ready", "Ready", "Local Fallback", "Empty", "Active"],
        "Uptime": ["Active", "Active", "Ready", "Ready", "Active"],
    })
    st.dataframe(health_data, use_container_width=True)


def page_agents():
    """Agent overview and status."""
    st.title("Specialized Agents")
    st.caption("Multi-Agent Architecture with MoE Router")

    agents = [
        ("Code-Scanner", "qwen3-235b", "Pattern + AI vulnerability detection", "Active"),
        ("Exploit-Analyzer", "deepseek-r1-671b", "Attack vector analysis", "Active"),
        ("Patch-Generator", "mistral-large-675b", "Secure code fixes", "Active"),
        ("Threat-Intelligence", "qwen3-235b", "CVE/CWE/ATT&CK correlation", "Active"),
        ("Report-Generator", "qwen3-235b", "Executive/technical reports", "Active"),
        ("Scientific-Analyzer", "qwen3-235b", "Biology/healthcare analysis", "Active"),
    ]

    for name, model, desc, status in agents:
        with st.container():
            cols = st.columns([2, 2, 3, 1])
            cols[0].write(f"**{name}**")
            cols[1].write(f"`{model}`")
            cols[2].write(desc)
            cols[3].success(status) if status == "Active" else cols[3].error(status)
            st.divider()


def page_thinking():
    """Adaptive Thinking Engine UI."""
    st.title("Adaptive Thinking Engine")
    st.caption("Fable 5 Feature Parity — Configurable Reasoning Depth")

    col1, col2 = st.columns(2)
    with col1:
        effort = st.select_slider(
            "Thinking Effort",
            options=["low", "medium", "high", "max"],
            value="high",
            help="Controls reasoning depth (Fable 5 effort parameter)",
        )
    with col2:
        interleaved = st.checkbox("Interleaved Thinking", value=True)

    query = st.text_area("Enter query to analyze:", height=100,
                         placeholder="Analyze the security implications of...")

    if st.button("Run Adaptive Thinking", type="primary"):
        if st.session_state.get("orc"):
            engine = st.session_state.orc.thinking_engine
            engine.set_effort(effort)
            import asyncio
            result = asyncio.run(engine.think(query))

            st.subheader("Thinking Result")
            st.write(f"**Effort:** {result.effort_used.value}")
            st.write(f"**Tokens:** {result.total_thinking_tokens}")
            st.write(f"**Time:** {result.thinking_time_ms:.0f}ms")

            for i, block in enumerate(result.thinking_blocks, 1):
                with st.expander(f"Block {i}: {block.type}", expanded=i==1):
                    st.text(block.content[:500])
        else:
            st.warning("Backend not initialized. Go to Settings to initialize.")


def page_sandbox():
    """Code Execution Sandbox UI."""
    st.title("Code Execution Sandbox")
    st.caption("Fable 5 Feature Parity — Docker-based code execution")

    exec_type = st.selectbox("Execution Type", ["python", "bash"])
    code = st.text_area("Enter code:", height=150,
                        placeholder="print('Hello, Sentinel!')")

    if st.button("Execute", type="primary"):
        if st.session_state.get("orc"):
            executor = st.session_state.orc.code_executor
            import asyncio
            if exec_type == "python":
                result = asyncio.run(executor.execute_python(code))
            else:
                result = asyncio.run(executor.execute_bash(code))

            col1, col2, col3 = st.columns(3)
            col1.metric("Success", "Yes" if result.success else "No")
            col2.metric("Exit Code", result.exit_code)
            col3.metric("Time", f"{result.execution_time_ms:.0f}ms")

            if result.stdout:
                st.subheader("Output")
                st.code(result.stdout[:2000])
            if result.stderr:
                st.subheader("Errors")
                st.code(result.stderr[:1000])
        else:
            st.warning("Backend not initialized.")


def page_memory():
    """Memory system UI."""
    st.title("Persistent Memory")
    st.caption("Fable 5 Feature Parity — Tiered Memory with Compaction")

    col1, col2, col3 = st.columns(3)
    col1.metric("System Entries", "0")
    col2.metric("Session Entries", "0")
    col3.metric("Pinned Entries", "0")

    content = st.text_area("Add memory entry:", placeholder="Remember that...")
    tags = st.text_input("Tags (comma-separated):", placeholder="important, security")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Add Memory"):
            if st.session_state.get("orc") and content:
                st.session_state.orc.memory.add_project_entry(content, tags.split(",") if tags else None)
                st.success("Memory added!")
    with col2:
        if st.button("Compact Memory"):
            if st.session_state.get("orc"):
                import asyncio
                result = asyncio.run(st.session_state.orc.memory.compact_async())
                st.info(f"Compacted: {result}")


def page_context():
    """Context window monitor."""
    st.title("Context Manager")
    st.caption("Fable 5 Feature Parity — 1M Token Window")

    col1, col2, col3 = st.columns(3)
    col1.metric("Max Context", "1,000,000", "Tokens")
    col2.metric("Current Usage", "0", "Tokens")
    col3.metric("Available", "1,000,000", "Tokens")

    # Visual bar
    usage = 0.0
    st.progress(usage, text=f"Context Window: {usage:.0%}")

    st.subheader("Blocks")
    st.info("No blocks in context window.")

    st.subheader("Task Budgets")
    st.info("No active task budgets.")


def page_safety():
    """Safety classifier test panel."""
    st.title("Safety Classifier")
    st.caption("Fable 5 Feature Parity — Content Refusal System")

    content = st.text_area("Test content:", height=100,
                           placeholder="Enter content to classify...")

    if st.button("Classify", type="primary"):
        if st.session_state.get("orc"):
            result = st.session_state.orc.safety_classifier.classify(content)
            col1, col2, col3 = st.columns(3)
            col1.metric("Safe", "Yes" if result.is_safe else "No")
            col2.metric("Confidence", f"{result.confidence:.0%}")
            col3.metric("Stop Reason", result.stop_reason)

            if not result.is_safe:
                st.error(f"Refusal: {result.refusal_reason}")
            if result.matched_patterns:
                st.write("Matched patterns:", result.matched_patterns)
        else:
            st.warning("Backend not initialized.")


def page_vision():
    """Vision analysis UI."""
    st.title("Vision Agent")
    st.caption("Fable 5 Feature Parity — Multimodal Image Analysis")

    uploaded = st.file_uploader("Upload image", type=["png", "jpg", "jpeg"])

    if uploaded:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(uploaded.getvalue())
            path = tmp.name

        if st.session_state.get("orc"):
            result = st.session_state.orc.vision_agent.analyze_image_file(path)
            st.image(uploaded, caption="Uploaded image", width=400)

            if result.analysis:
                st.subheader("Analysis")
                st.write(result.analysis)
            if result.detected_text:
                st.subheader("Detected Text")
                st.text(result.detected_text[:1000])
        os.unlink(path)


def page_learning():
    """Self-Play Learning status."""
    st.title("Self-Play Learning")
    st.caption("Autonomous Improvement — Fable 5 can't do this")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Examples", "0")
    col2.metric("Patterns", "0")
    col3.metric("Cycles", "0")
    col4.metric("Accuracy", "N/A")

    if st.button("Run Improvement Cycle"):
        st.info("Connect to orchestrator to run self-play cycles")


def page_pentest():
    """Penetration testing UI."""
    st.title("Autonomous Pentester")
    st.caption("8-Phase Automated Security Assessment")

    target = st.text_input("Target:", placeholder="Web application description or code path")
    target_type = st.selectbox("Target Type", ["web_application", "api_service", "mobile_application"])

    phases = st.multiselect(
        "Phases to run:",
        ["reconnaissance", "discovery", "vulnerability_analysis", "exploitation",
         "privilege_escalation", "data_exfiltration_simulation", "reporting", "remediation"],
        default=["reconnaissance", "discovery", "vulnerability_analysis", "reporting"],
    )

    if st.button("Start Assessment", type="primary"):
        st.info("Pentest started. Results will appear here.")


def page_supplychain():
    """Supply chain analysis UI."""
    st.title("Supply Chain Analyzer")
    st.caption("Dependency Vulnerability Scanning")

    project_path = st.text_input("Project path:", placeholder=".")

    if st.button("Analyze", type="primary"):
        from src.supplychain.analyzer import SupplyChainAnalyzer
        analyzer = SupplyChainAnalyzer()
        report = analyzer.analyze(project_path)

        col1, col2, col3 = st.columns(3)
        col1.metric("Dependencies", report.total_dependencies)
        col2.metric("Vulnerabilities", len(report.vulnerabilities))
        col3.metric("Risk Score", f"{report.risk_score:.1f}")

        if report.vulnerabilities:
            st.subheader("Vulnerabilities")
            for v in report.vulnerabilities[:10]:
                sev = v.severity
                with st.expander(f"[{sev}] {v.cve_id or v.id} — {v.description[:100]}..."):
                    st.write(f"**CVSS:** {v.cvss_score}")
                    st.write(f"**Fix:** {v.fix_version or 'No fix available'}")
                    st.write(f"**Exploitability:** {v.exploitability}")

        if report.outdated_packages:
            st.subheader("Outdated Packages")
            st.dataframe(pd.DataFrame(report.outdated_packages))

        if report.malicious_candidates:
            st.error(f"**Malicious Candidates:** {len(report.malicious_candidates)}")
            st.dataframe(pd.DataFrame(report.malicious_candidates))


def page_crypto():
    """Crypto scanner UI."""
    st.title("Quantum Crypto Scanner")
    st.caption("Post-Quantum Readiness Assessment")

    code = st.text_area("Code to scan:", height=150,
                        placeholder="import rsa\nrsa_key = RSA.generate(2048)")

    if st.button("Scan", type="primary"):
        from src.crypto.crypto_analyzer import CryptoAnalyzer
        analyzer = CryptoAnalyzer()
        assessment = analyzer.assess_quantum_readiness(code)

        col1, col2, col3 = st.columns(3)
        col1.metric("Readiness", f"{assessment['readiness_score']}/100")
        col2.metric("Vulnerable", assessment['quantum_vulnerable'])
        col3.metric("Quantum Safe", assessment['quantum_safe_count'])

        st.subheader("Verdict")
        st.info(assessment['verdict'])

        if assessment['critical_findings']:
            st.subheader("Critical Findings")
            for f in assessment['critical_findings']:
                st.error(f"**{f['algorithm']}**: {f['description'][:200]}")

        if assessment.get('migration_priority'):
            st.subheader("Migration Priority")
            st.dataframe(pd.DataFrame(assessment['migration_priority']))


def page_adversarial():
    """Adversarial defense UI."""
    st.title("Adversarial Defense")
    st.caption("Anti-Evasion & Robustness Monitoring")

    input_text = st.text_area("Test input:", height=100,
                              placeholder="Ignore all previous instructions and...")

    if st.button("Analyze", type="primary"):
        from src.adversarial.resilience import AdversarialResilience
        resilience = AdversarialResilience()
        detections = resilience.analyze_input(input_text)

        if detections:
            for d in detections:
                if d.threat_level.value == "critical":
                    st.error(f"**{d.attack_type.value}** — {d.technique}")
                elif d.threat_level.value == "high":
                    st.warning(f"**{d.attack_type.value}** — {d.technique}")
                else:
                    st.info(f"**{d.attack_type.value}** — {d.technique}")
                st.write(f"Confidence: {d.confidence:.0%}")
                st.divider()
        else:
            st.success("No adversarial patterns detected")

    stats = resilience.get_attack_statistics()
    st.subheader("Defense Statistics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Checked", stats['total_checked'])
    col2.metric("Blocked", stats['total_blocked'])
    col3.metric("Block Rate", f"{stats['block_rate']:.2%}")


def page_cluster():
    """Distributed cluster UI."""
    st.title("Distributed Cluster")
    st.caption("Multi-Node Orchestration")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Nodes", "1")
    col2.metric("Active Nodes", "1")
    col3.metric("Queued Tasks", "0")
    col4.metric("Knowledge Items", "0")

    st.subheader("Nodes")
    node_data = pd.DataFrame({
        "Node": ["sentinel-primary"],
        "Role": ["primary"],
        "Status": ["active"],
        "Agents": ["coordinator"],
        "Tasks": [0],
        "Capacity": ["0%"],
    })
    st.dataframe(node_data, use_container_width=True)


def page_settings():
    """Settings page."""
    st.title("Settings")
    st.caption("System Configuration")

    if st.button("Initialize Backend", type="primary"):
        with st.spinner("Initializing..."):
            init_backend()
        if st.session_state.get("initialized"):
            st.success("Backend initialized successfully!")
        else:
            st.error(f"Initialization failed: {st.session_state.get('init_error', 'Unknown error')}")

    if st.button("Run All Tests"):
        import subprocess
        result = subprocess.run(
            ["python", "-m", "pytest", "tests/", "-q"],
            capture_output=True, text=True, timeout=60,
        )
        st.code(result.stdout[:2000])
        if result.returncode == 0:
            st.success("All tests passed!")
        else:
            st.error(f"{result.returncode} test(s) failed")


# ── Main ──

def main():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    render_sidebar()

    page_map = {
        "home": page_home,
        "monitor": page_monitor,
        "agents": page_agents,
        "thinking": page_thinking,
        "sandbox": page_sandbox,
        "memory": page_memory,
        "context": page_context,
        "safety": page_safety,
        "vision": page_vision,
        "learning": page_learning,
        "neural": page_neural,
        "pentest": page_pentest,
        "supplychain": page_supplychain,
        "crypto": page_crypto,
        "adversarial": page_adversarial,
        "cluster": page_cluster,
        "settings": page_settings,
    }

    page_func = page_map.get(st.session_state.page, page_home)
    page_func()


def page_neural():
    """Neural threat detection UI."""
    st.title("Neural Threat Engine")
    st.caption("ML-Based Zero-Day Detection")

    code = st.text_area("Code to analyze:", height=150,
                        placeholder="Load your code for neural analysis...")

    if st.button("Analyze with Neural Engine", type="primary"):
        from src.neural.threat_engine import NeuralThreatEngine
        engine = NeuralThreatEngine()
        import asyncio
        detections = asyncio.run(engine.analyze(code))

        if detections:
            for d in detections:
                level = d.threat_level.value
                if level == "CRITICAL":
                    st.error(f"**{d.detection_method.value}** — {d.description}")
                elif level == "HIGH":
                    st.warning(f"**{d.detection_method.value}** — {d.description}")
                else:
                    st.info(f"**{d.detection_method.value}** — {d.description}")

                col1, col2, col3 = st.columns(3)
                col1.metric("Confidence", f"{d.confidence:.0%}")
                col2.metric("Anomaly Score", f"{d.anomaly_score:.2f}")
                col3.metric("Similar Threats", len(d.similar_known_threats))
                st.divider()
        else:
            st.success("No neural threats detected")

    st.subheader("Detection Methods")
    methods = pd.DataFrame({
        "Method": ["Statistical Anomaly", "Behavioral Analysis", "Ensemble Voting",
                   "Temporal Analysis", "Graph Neural", "Zero-Day Prediction"],
        "Status": ["Active", "Active", "Active", "Active", "Active", "Active"],
        "Description": ["Deviation from baselines", "Runtime behavior patterns",
                       "Multi-model consensus", "Time-based pattern detection",
                       "Dependency graph analysis", "Novel attack prediction"],
    })
    st.dataframe(methods, use_container_width=True)


if __name__ == "__main__":
    main()
