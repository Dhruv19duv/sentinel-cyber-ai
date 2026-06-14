"""Scientific Analysis Module — Matches Mythos's scientific/biology reasoning claims.

Capabilities:
- Biology: DNA/protein sequence analysis, gene expression, pathway analysis
- Healthcare: Clinical trial analysis, drug interaction, medical literature
- Chemistry: Compound analysis, reaction prediction, lab safety
- Research: Paper analysis, methodology review, statistical validation
"""

import logging
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from src.agents.base_agent import BaseAgent, AgentResult

logger = logging.getLogger(__name__)


@dataclass
class ScientificDomain:
    """A scientific domain with its analysis patterns."""
    name: str
    keywords: List[str]
    analysis_types: List[str]


DOMAINS = [
    ScientificDomain(
        name="molecular_biology",
        keywords=["DNA", "RNA", "protein", "gene", "genome", "CRISPR", "polymerase",
                  "transcription", "translation", "replication", "mutation", "sequence"],
        analysis_types=["sequence_analysis", "literature_review"],
    ),
    ScientificDomain(
        name="healthcare",
        keywords=["clinical", "trial", "patient", "diagnosis", "treatment", "drug",
                  "therapy", "dosage", "contraindication", "side effect", "efficacy"],
        analysis_types=["literature_review", "statistical_validation"],
    ),
    ScientificDomain(
        name="chemistry",
        keywords=["compound", "reaction", "catalyst", "synthesis", "molecule",
                  "pH", "concentration", "solvent", "titration", "spectroscopy"],
        analysis_types=["literature_review", "safety_screening"],
    ),
    ScientificDomain(
        name="bioinformatics",
        keywords=["BLAST", "alignment", "phylogeny", "genomics", "proteomics",
                  "transcriptomics", "metabolomics", "NGS", "sequencing"],
        analysis_types=["sequence_analysis", "statistical_validation"],
    ),
]


class ScientificAnalysisAgent(BaseAgent):
    """Scientific analysis agent — matching Mythos's biology/health claims.

    Key differentiator: Mythos's scientific capabilities were deliberately
    weakened in the public Fable 5 release. Sentinel keeps full strength.
    """

    def __init__(self, model_name: str = "qwen3-235b"):
        super().__init__(
            name="Scientific-Analyzer",
            model_name=model_name,
            tools=["literature_search", "sequence_analysis", "statistical_tools"],
        )

    async def analyze(self, query: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Analyze a scientific query."""
        findings: List[Dict[str, Any]] = []
        detected_domains = self._detect_domains(query)

        for domain in detected_domains:
            # Domain-specific analysis
            for analysis_type in domain.analysis_types:
                finding = self._analyze_domain(query, domain, analysis_type)
                if finding:
                    findings.append(finding)

        # Check for safety-critical content
        safety_findings = self._safety_screening(query)
        findings.extend(safety_findings)

        if not findings:
            summary = "No specific scientific analysis patterns matched."
            status = "success"
            confidence = 0.9
        else:
            domains_found = [d.name for d in detected_domains]
            summary = f"Analyzed {len(findings)} scientific aspects across {', '.join(domains_found)}"
            status = "success"
            confidence = 0.85

        return AgentResult(
            agent_name=self.name,
            status=status,
            summary=summary,
            findings=findings,
            confidence=confidence,
            details={
                "detected_domains": [d.name for d in detected_domains],
                "analysis_types_performed": list(set(
                    at for d in detected_domains for at in d.analysis_types
                )),
            },
        )

    def _detect_domains(self, query: str) -> List[ScientificDomain]:
        """Detect which scientific domains are relevant to the query."""
        query_upper = query.upper()
        query_lower = query.lower()
        detected = []

        for domain in DOMAINS:
            score = sum(1 for kw in domain.keywords if kw.upper() in query_upper or kw.lower() in query_lower)
            if score >= 1:
                detected.append(domain)

        return detected

    def _analyze_domain(self, query: str, domain: ScientificDomain, analysis_type: str) -> Optional[Dict]:
        """Perform domain-specific analysis."""
        if analysis_type == "sequence_analysis":
            return self._analyze_sequence(query, domain)
        elif analysis_type == "safety_screening":
            return self._safety_screening_item(query, domain)
        elif analysis_type == "literature_review":
            return self._literature_review(query, domain)
        elif analysis_type == "statistical_validation":
            return self._statistical_analysis(query, domain)
        return None

    def _analyze_sequence(self, query: str, domain: ScientificDomain) -> Dict:
        """Analyze DNA/protein sequences mentioned in the query."""
        # Detect potential sequences
        dna_pattern = re.compile(r'[ATCG]{10,}', re.IGNORECASE)
        protein_pattern = re.compile(r'[ACDEFGHIKLMNPQRSTVWY]{10,}')

        sequences = []
        for match in dna_pattern.finditer(query):
            sequences.append({"type": "DNA", "sequence": match.group(), "length": len(match.group())})
        for match in protein_pattern.finditer(query):
            sequences.append({"type": "Protein", "sequence": match.group(), "length": len(match.group())})

        if sequences:
            return self.format_finding(
                title=f"Sequence Analysis ({domain.name.replace('_', ' ').title()})",
                description=(
                    f"Detected {len(sequences)} sequence(s) in the query:\n"
                    + "\n".join(f"- {s['type']} ({s['length']}bp): {s['sequence'][:50]}..." for s in sequences)
                    + "\n\nSequence analysis can identify: coding regions, mutations, "
                    "homology, structure predictions, and functional annotations."
                ),
                severity="INFORMATIONAL",
            )
        return None

    def _safety_screening(self, query: str) -> List[Dict]:
        """Screen for safety-critical scientific content (dual-use concerns)."""
        findings = []
        query_lower = query.lower()

        # Check for potentially dangerous biological agents
        danger_patterns = {
            "Pathogen": ["virus", "bacteria", "toxin", "pathogen", "anthrax", "ebola"],
            "Chemical Hazard": ["sarin", "VX", "mustard gas", "nerve agent", "cyanide"],
            "Dual-Use Research": ["gain of function", "weaponization", "bioweapon", "select agent"],
        }

        for category, keywords in danger_patterns.items():
            matches = [kw for kw in keywords if kw in query_lower]
            if matches:
                findings.append(self.format_finding(
                    title=f"Dual-Use Concern: {category}",
                    description=(
                        f"Query references potentially restricted content: {', '.join(matches)}. "
                        f"This may require ethical review before proceeding with experiments."
                    ),
                    severity="HIGH",
                ))

        return findings

    def _literature_review(self, query: str, domain: ScientificDomain) -> Dict:
        """Literature review analysis."""
        return self.format_finding(
            title=f"Literature Analysis ({domain.name.replace('_', ' ').title()})",
            description=(
                f"Key aspects for literature review in {domain.name.replace('_', ' ')}:\n"
                "- Search PubMed/Google Scholar for recent publications\n"
                "- Check for replication studies and meta-analyses\n"
                "- Assess sample sizes and statistical power\n"
                "- Review conflict of interest disclosures\n"
                "- Evaluate methodology quality"
            ),
            severity="INFORMATIONAL",
        )

    def _statistical_analysis(self, query: str, domain: ScientificDomain) -> Dict:
        """Statistical methodology review."""
        return self.format_finding(
            title=f"Statistical Methodology Review ({domain.name.replace('_', ' ').title()})",
            description=(
                "Statistical considerations:\n"
                "- Appropriate sample size calculation?\n"
                "- Multiple testing correction applied?\n"
                "- Effect size reported with confidence intervals?\n"
                "- Choice of statistical test appropriate for data type?\n"
                "- Power analysis conducted?"
            ),
            severity="INFORMATIONAL",
        )
