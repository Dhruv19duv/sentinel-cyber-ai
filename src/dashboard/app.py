"""Sentinel Web Dashboard — Streamlit-based UI for the cybersecurity platform.

Features:
- Live agent status monitoring
- Code analysis interface
- Benchmark results with charts
- Model registry management
- Task history viewer
- Threat intelligence feed
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    import streamlit as st
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_STREAMLIT = True
except ImportError:
    HAS_STREAMLIT = False


# ── Page Configuration ──

def setup_page():
    """Configure the Streamlit page."""
    st.set_page_config(
        page_title="Sentinel Cyber AI",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown("""
    <style>
        .main > div { padding: 0 2rem; }
        .stApp { background: #0a0a1a; }
        h1, h2, h3 { color: #00ff88 !important; }
        .metric-card {
            background: #1a1a3e;
            border: 1px solid #2a2a5e;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 0.5rem 0;
        }
        .finding-critical { color: #ff4444; font-weight: bold; }
        .finding-high { color: #ff8800; font-weight: bold; }
        .finding-medium { color: #ffcc00; }
        .finding-low { color: #44aaff; }
        code {
            background: #1a1a3e;
            color: #00ff88;
            padding: 0.2em 0.4em;
            border-radius: 3px;
        }
        .stButton button {
            background: #00ff88;
            color: #0a0a1a;
            font-weight: bold;
            border: none;
        }
        .stTextInput input { background: #1a1a3e; color: white; border: 1px solid #2a2a5e; }
        .stSelectbox div[data-baseweb="select"] { background: #1a1a3e; }
    </style>
    """, unsafe_allow_html=True)


# ── Initialization ──

def init_orchestrator():
    """Initialize or get the orchestrator from session state."""
    if "orchestrator" not in st.session_state:
        from src.main import setup_orchestrator
        st.session_state.orchestrator = setup_orchestrator()
        st.session_state.analysis_history = []
    return st.session_state.orchestrator


# ── Sidebar ──

def render_sidebar():
    """Render the sidebar navigation."""
    with st.sidebar:
        st.markdown("## 🔐 Sentinel")
        st.markdown("### Cyber AI Dashboard")
        st.markdown("---")

        page = st.radio(
            "Navigation",
            ["Home", "Code Analysis", "Agents", "Benchmarks", "Threat Intel", "Model Registry", "Settings"],
            label_visibility="collapsed",
        )

        st.markdown("---")
        st.markdown(f"**Status:** 🟢 Operational")
        st.markdown(f"**Version:** 2.0.0")

        if st.button("🔄 Refresh"):
            st.rerun()

        return page


# ── Pages ──

def render_home(orchestrator):
    """Home page with overview metrics."""
    st.title("🔐 Sentinel Cyber AI")
    st.markdown("### Enterprise Multi-Agent Cybersecurity Platform")

    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            "Active Agents",
            len(orchestrator.registered_agents),
            delta=None,
        )
    with col2:
        total_analyses = len(orchestrator.get_history())
        st.metric("Total Analyses", total_analyses, delta="+1")
    with col3:
        st.metric("System Status", "✅ Operational")
    with col4:
        st.metric("Models Available", "6", delta="MoE")

    # Agent status cards
    st.markdown("### 🤖 Agent Status")
    cols = st.columns(len(orchestrator.registered_agents))
    for i, agent_name in enumerate(orchestrator.registered_agents):
        agent = orchestrator.get_agent(agent_name)
        with cols[i]:
            if agent:
                st.markdown(
                    f"""<div class="metric-card">
                    <h4>{agent_name}</h4>
                    <p>Model: <code>{agent.model_name}</code></p>
                    <p>Tools: {', '.join(agent.tools[:3])}</p>
                    <p>Status: 🟢 Ready</p>
                    </div>""",
                    unsafe_allow_html=True,
                )

    # Recent activity
    st.markdown("### 📊 Recent Activity")
    history = orchestrator.get_history(limit=5)
    if history:
        for h in history:
            status_icon = {
                "success": "✅",
                "partial": "⚠️",
                "error": "❌",
            }.get(h.get("synthesis", {}).get("status", ""), "⚪")
            st.markdown(
                f"{status_icon} **{h.get('query', '')[:80]}...** — "
                f"*Confidence: {h.get('synthesis', {}).get('confidence', 0):.0%}*"
            )
    else:
        st.info("No analyses yet. Go to Code Analysis to scan some code!")


def render_code_analysis(orchestrator):
    """Code analysis page with input and results."""
    st.title("🔍 Code Analysis")
    st.markdown("Paste code below to analyze for security vulnerabilities.")

    # Input
    code_input = st.text_area(
        "Code to analyze",
        height=200,
        placeholder="Paste your code here...\n\ndef login(username, password):\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"",
    )

    col1, col2 = st.columns([1, 3])
    with col1:
        analyze_button = st.button("🚀 Analyze", type="primary", use_container_width=True)
    with col2:
        include_report = st.checkbox("Generate full report", value=True)

    if analyze_button and code_input:
        with st.spinner("🤖 Analyzing with multiple agents..."):
            # Streamlit handles event loops per-script-run
            result = asyncio.run(orchestrator.process(code_input))

        # Store in history
        st.session_state.analysis_history.append(result)

        # Display results
        st.markdown("---")
        st.markdown(f"### 📋 Analysis Results — `{result.get('task_id', 'N/A')}`")

        # Status banner
        status = result.get("status", "unknown")
        status_colors = {"success": "🟢", "partial": "🟡", "error": "🔴"}
        st.markdown(
            f"**{status_colors.get(status, '⚪')} Status:** {status.upper()} | "
            f"**Confidence:** {result.get('confidence', 0):.1%} | "
            f"**Agents:** {', '.join(result.get('agents_used', []))}"
        )

        # Findings
        findings = result.get("findings", [])
        if findings:
            st.markdown(f"#### Found {len(findings)} Issues")

            for i, finding in enumerate(findings):
                severity = finding.get("severity", "INFO")
                sev_class = f"finding-{severity.lower()}"

                with st.expander(
                    f"{'🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'} "
                    f"**{finding.get('title', f'Issue {i+1}')}** [{severity}]"
                ):
                    st.markdown(f"**Description:** {finding.get('description', 'N/A')}")
                    if finding.get("remediation"):
                        st.markdown(f"**💊 Remediation:** `{finding['remediation']}`")
                    if finding.get("cwe"):
                        st.markdown(f"**📋 CWE:** {finding['cwe']}")
                    if finding.get("location"):
                        st.markdown(f"**📍 Location:** {finding['location']}")
        else:
            st.success("✅ No vulnerabilities found!")

        # Agent results
        if result.get("agent_results"):
            st.markdown("#### 🤖 Agent Details")
            for ar in result["agent_results"]:
                st.markdown(
                    f"- **{ar.get('agent_name')}**: {ar.get('status')} "
                    f"(confidence: {ar.get('confidence', 0):.0%})"
                )

        # Generate report
        if include_report:
            from src.agents.report_agent import ReportGeneratorAgent
            report_gen = ReportGeneratorAgent()
            report = report_gen.generate_report(result, report_type="technical")
            st.markdown("#### 📄 Technical Report")
            st.markdown(report)

    elif analyze_button and not code_input:
        st.warning("Please enter some code to analyze.")


def render_agents(orchestrator):
    """Agent management page."""
    st.title("🤖 Agent Management")

    agents_data = []
    for name in orchestrator.registered_agents:
        agent = orchestrator.get_agent(name)
        if agent:
            agents_data.append({
                "Agent": name,
                "Model": agent.model_name,
                "Tools": ", ".join(agent.tools),
                "Status": "🟢 Active",
            })

    if agents_data:
        df = pd.DataFrame(agents_data)
        st.dataframe(df, use_container_width=True, hide_index=True)


def render_benchmarks(orchestrator):
    """Benchmark results page with charts."""
    st.title("📊 Security Benchmarks")

    if st.button("🏃 Run Benchmarks Now", type="primary"):
        with st.spinner("Running benchmark suite..."):
            from src.benchmark.ctf_benchmark import BenchmarkSuite
            suite = BenchmarkSuite(orchestrator)
            results = asyncio.run(suite.run_all())

        st.session_state.benchmark_results = results
        st.success("Benchmarks complete!")

    # Display cached results or placeholder
    results = st.session_state.get("benchmark_results")
    if results:
        details = results.get("details", [])

        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Passed", results.get("passed", 0))
        with col2:
            st.metric("Failed", results.get("failed", 0))
        with col3:
            st.metric("Success Rate", f"{results.get('success_rate', 0):.0%}")
        with col4:
            st.metric("Avg Confidence", f"{results.get('average_confidence', 0):.0%}")

        # Pass/fail pie chart
        fig = go.Figure(data=[go.Pie(
            labels=["Passed", "Failed"],
            values=[results.get("passed", 0), results.get("failed", 0)],
            marker_colors=["#00ff88", "#ff4444"],
        )])
        fig.update_layout(
            title="Test Results",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
        )
        st.plotly_chart(fig, use_container_width=True)

        # By category bar chart
        categories = results.get("by_category", {})
        if categories:
            cat_df = pd.DataFrame([
                {"Category": cat.replace("_", " ").title(), "Passed": data["passed"],
                 "Total": data["total"]}
                for cat, data in categories.items()
            ])
            fig2 = px.bar(
                cat_df, x="Category", y=["Passed", "Total"],
                barmode="group", title="Results by Category",
                color_discrete_sequence=["#00ff88", "#2a2a5e"],
            )
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig2, use_container_width=True)

        # Detailed results table
        if details:
            st.markdown("### Detailed Results")
            detail_rows = []
            for d in details:
                detail_rows.append({
                    "Test": d.get("name", "N/A"),
                    "Difficulty": d.get("difficulty", "N/A"),
                    "Status": "✅" if d.get("passed") else "❌",
                    "Confidence": f"{d.get('confidence', 0):.0%}",
                    "Detected": ", ".join(d.get("detected", [])) or "None",
                })
            st.dataframe(pd.DataFrame(detail_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No benchmark results yet. Click 'Run Benchmarks Now' to evaluate.")


def render_threat_intel(orchestrator):
    """Threat intelligence dashboard."""
    st.title("🌐 Threat Intelligence")

    # Search CVEs
    st.markdown("### Search Vulnerabilities")
    cve_query = st.text_input("Search CVE, CWE, or software name", placeholder="e.g., Log4j, CVE-2024-3094")
    if cve_query:
        from src.tools.search_tool import SearchTool
        search = SearchTool()
        results = asyncio.run(search.search_cve(cve_query))

        if results:
            for result in results:
                severity_color = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                }.get(result.get("severity", ""), "⚪")
                st.markdown(
                    f"""<div class="metric-card">
                    <h4>{severity_color} {result.get('id', 'N/A')}</h4>
                    <p><b>{result.get('summary', 'No summary')[:200]}</b></p>
                    <p>CVSS: {result.get('cvss_score', 'N/A')} | 
                    Published: {result.get('published', 'N/A')} | 
                    Status: {result.get('exploitability', 'Unknown')}</p>
                    <p>Patch: <code>{result.get('patch', 'No patch available')}</code></p>
                    </div>""",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No results found.")

    # Recent CVEs
    st.markdown("### Recent CVEs")
    recent = asyncio.run(search.get_recent_cves(days=90, limit=5))
    if recent:
        for cve in recent:
            st.markdown(f"- **{cve.get('id')}** ({cve.get('severity')}) — {cve.get('summary', '')[:100]}...")


def render_model_registry(orchestrator):
    """Model registry management page."""
    st.title("🧠 Model Registry")

    from src.models.llm_backend import AVAILABLE_MODELS, ModelRegistry

    # Model cards
    st.markdown("### Available Models")
    cols = st.columns(3)
    for i, (model_id, config) in enumerate(AVAILABLE_MODELS.items()):
        with cols[i % 3]:
            status = "🟢 Loaded" if config.loaded else "⚪ Available"
            st.markdown(
                f"""<div class="metric-card">
                <h4>{config.display_name}</h4>
                <p><code>{model_id}</code></p>
                <p>Parameters: {config.parameters}</p>
                <p>Min VRAM: {config.min_vram_gb}GB</p>
                <p>Status: {status}</p>
                </div>""",
                unsafe_allow_html=True,
            )

    # Cache stats
    st.markdown("### Cache Statistics")
    registry = ModelRegistry()
    cache_stats = registry.get_cache_stats()
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Cache Size", f"{cache_stats.get('total_size_gb', 0)} GB")
    with col2:
        st.metric("Models Cached", cache_stats.get("models_cached", 0))
    with col3:
        st.metric("Available VRAM", f"{cache_stats.get('available_vram_gb', 0)} GB")


def render_settings():
    """Settings page."""
    st.title("⚙️ Settings")

    st.markdown("### API Configuration")
    api_key = st.text_input("API Key", type="password",
                            value=os.environ.get("SENTINEL_API_KEY", ""))
    if api_key:
        os.environ["SENTINEL_API_KEY"] = api_key
        st.success("API key set!")

    st.markdown("### Model Settings")
    st.selectbox("Default Model", [
        "deepseek-r1-671b", "qwen3-235b", "mistral-large-675b",
        "deepseek-r1-7b", "qwen3-8b", "llama-4-8b",
    ])
    st.slider("Max Tokens", 512, 8192, 2048)
    st.slider("Temperature", 0.0, 1.0, 0.3)

    st.markdown("### System")
    st.markdown(f"**Python:** {sys.version}")
    st.markdown(f"**Data Directory:** `{os.path.abspath('data')}`")
    st.markdown(f"**Output Directory:** `{os.path.abspath('outputs')}`")


# ── Main ──

def main():
    if not HAS_STREAMLIT:
        print("Streamlit not installed. Run: pip install streamlit pandas plotly")
        print("Then: streamlit run src/dashboard/app.py")
        return

    setup_page()
    orchestrator = init_orchestrator()
    page = render_sidebar()

    pages = {
        "Home": render_home,
        "Code Analysis": render_code_analysis,
        "Agents": render_agents,
        "Benchmarks": render_benchmarks,
        "Threat Intel": render_threat_intel,
        "Model Registry": render_model_registry,
        "Settings": render_settings,
    }

    render_fn = pages.get(page, render_home)
    render_fn(orchestrator)


if __name__ == "__main__":
    main()
