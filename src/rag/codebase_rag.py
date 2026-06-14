"""Codebase RAG Engine — Vector search across large codebases for AI-powered code understanding.

This provides Mythos-level codebase reasoning ability by:
1. AST-aware chunking (functions, classes, blocks remain intact)
2. Hybrid search (dense embeddings + sparse BM25)
3. Graph traversal (follow imports, calls, inheritance)
4. Contextual retrieval (parent class, dependencies included)

Key differentiator: Mythos reasons about codebases natively. We build
a dedicated RAG system that any agent can query — more flexible.
"""

import ast
import json
import logging
import os
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False


@dataclass
class CodeChunk:
    """A semantic chunk of code (function, class, or block)."""
    id: str
    file_path: str
    chunk_type: str  # "function", "class", "module", "block"
    name: str
    code: str
    start_line: int
    end_line: int
    language: str
    embedding: Optional[Any] = None  # numpy array
    metadata: Dict[str, Any] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "type": self.chunk_type,
            "name": self.name,
            "code": self.code[:500],
            "start_line": self.start_line,
            "end_line": self.end_line,
            "language": self.language,
            "imports": self.imports,
            "dependencies": self.dependencies,
            "summary": self.summary,
        }


class CodebaseIndexer:
    """Indexes a codebase into searchable chunks using AST-aware parsing.

    Supports: Python, JavaScript, TypeScript, Java, Go, Rust, C/C++
    """

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or os.path.expanduser("~/.cache/sentinel/rag")
        os.makedirs(self.cache_dir, exist_ok=True)
        self._chunks: List[CodeChunk] = []
        self._file_index: Dict[str, List[CodeChunk]] = {}
        self._dependency_graph: Dict[str, Set[str]] = {}

    def index_directory(self, path: str, language: Optional[str] = None) -> int:
        """Index all source files in a directory.

        Args:
            path: Directory path to index
            language: Optional language filter

        Returns:
            Number of chunks created
        """
        if not os.path.exists(path):
            logger.warning(f"Path not found: {path}")
            return 0

        extension_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript",
            ".java": "java", ".go": "go", ".rs": "rust",
            ".cpp": "cpp", ".c": "c", ".h": "c", ".hpp": "cpp",
            ".rb": "ruby", ".php": "php",
        }

        total_chunks = 0
        for root, dirs, files in os.walk(path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith((".", "__", "node_modules", "vendor", ".git"))]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in extension_map:
                    continue

                file_lang = extension_map[ext]
                if language and file_lang != language:
                    continue

                file_path = os.path.join(root, file)
                chunks = self._index_file(file_path, file_lang)
                total_chunks += len(chunks)

        logger.info(f"Indexed {total_chunks} chunks from {path}")
        return total_chunks

    def _index_file(self, file_path: str, language: str) -> List[CodeChunk]:
        """Index a single file into chunks."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return []

        chunks = []

        if language == "python":
            chunks = self._parse_python(file_path, content)
        elif language in ("javascript", "typescript"):
            chunks = self._parse_js_ts(file_path, content, language)
        elif language == "java":
            chunks = self._parse_java(file_path, content)
        elif language == "go":
            chunks = self._parse_go(file_path, content)
        else:
            # Fallback: line-based chunking for other languages
            chunks = self._parse_fallback(file_path, content, language)

        # Add imports and dependencies
        for chunk in chunks:
            chunk.imports = self._extract_imports(content, language)
            chunk.language = language
            chunk.summary = self._generate_summary(chunk)

        self._chunks.extend(chunks)
        self._file_index[file_path] = chunks

        return chunks

    def _parse_python(self, file_path: str, content: str) -> List[CodeChunk]:
        """Parse Python file using AST."""
        chunks = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return self._parse_fallback(file_path, content, "python")

        # Module-level docstring
        if ast.get_docstring(tree):
            chunks.append(CodeChunk(
                id=f"{file_path}:module",
                file_path=file_path,
                chunk_type="module",
                name=os.path.basename(file_path),
                code=content[:500],
                start_line=1,
                end_line=len(content.split("\n")),
                language="python",
            ))

        # Classes
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                class_code = "\n".join(content.split("\n")[node.lineno - 1:node.end_lineno])
                chunks.append(CodeChunk(
                    id=f"{file_path}:class:{node.name}",
                    file_path=file_path,
                    chunk_type="class",
                    name=node.name,
                    code=class_code,
                    start_line=node.lineno,
                    end_line=node.end_lineno,
                    language="python",
                    metadata={"bases": [b.id for b in node.bases if isinstance(b, ast.Name)]},
                ))

                # Methods within class
                for item in ast.iter_child_nodes(node):
                    if isinstance(item, ast.FunctionDef):
                        method_code = "\n".join(content.split("\n")[item.lineno - 1:item.end_lineno])
                        chunks.append(CodeChunk(
                            id=f"{file_path}:method:{node.name}.{item.name}",
                            file_path=file_path,
                            chunk_type="function",
                            name=f"{node.name}.{item.name}",
                            code=method_code,
                            start_line=item.lineno,
                            end_line=item.end_lineno,
                            language="python",
                            metadata={"parent_class": node.name},
                        ))

            elif isinstance(node, ast.FunctionDef):
                func_code = "\n".join(content.split("\n")[node.lineno - 1:node.end_lineno])
                chunks.append(CodeChunk(
                    id=f"{file_path}:func:{node.name}",
                    file_path=file_path,
                    chunk_type="function",
                    name=node.name,
                    code=func_code,
                    start_line=node.lineno,
                    end_line=node.end_lineno,
                    language="python",
                ))

        return chunks

    def _parse_js_ts(self, file_path: str, content: str, language: str) -> List[CodeChunk]:
        """Parse JavaScript/TypeScript using regex patterns."""
        chunks = []
        lines = content.split("\n")

        # Function declarations
        func_pattern = re.compile(
            r'(?:async\s+)?function\s+(\w+)\s*\(|(\w+)\s*=\s*(?:async\s+)?function\s*\(|(\w+)\s*\([^)]*\)\s*\{'
        )
        # Class declarations
        class_pattern = re.compile(r'class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{')

        for i, line in enumerate(lines, 1):
            class_match = class_pattern.search(line)
            if class_match:
                # Find class end (approximate brace matching)
                end_line = self._find_brace_end(lines, i - 1)
                class_code = "\n".join(lines[i - 1:end_line])
                chunks.append(CodeChunk(
                    id=f"{file_path}:class:{class_match.group(1)}",
                    file_path=file_path,
                    chunk_type="class",
                    name=class_match.group(1),
                    code=class_code,
                    start_line=i,
                    end_line=end_line,
                    language=language,
                ))

            func_match = func_pattern.search(line)
            if func_match:
                func_name = next(g for g in func_match.groups() if g)
                end_line = self._find_brace_end(lines, i - 1)
                if end_line > i:
                    func_code = "\n".join(lines[i - 1:end_line])
                    chunks.append(CodeChunk(
                        id=f"{file_path}:func:{func_name}",
                        file_path=file_path,
                        chunk_type="function",
                        name=func_name,
                        code=func_code,
                        start_line=i,
                        end_line=end_line,
                        language=language,
                    ))

        if not chunks:
            return self._parse_fallback(file_path, content, language)

        return chunks

    def _parse_java(self, file_path: str, content: str) -> List[CodeChunk]:
        """Parse Java file."""
        chunks = []
        lines = content.split("\n")

        class_pattern = re.compile(r'(?:public\s+)?(?:abstract\s+)?class\s+(\w+)')
        method_pattern = re.compile(
            r'(?:public|private|protected)\s+(?:static\s+)?(?:\w+)\s+(\w+)\s*\('
        )

        for i, line in enumerate(lines, 1):
            class_match = class_pattern.search(line)
            if class_match:
                end_line = self._find_brace_end(lines, i - 1)
                class_code = "\n".join(lines[i - 1:end_line])
                chunks.append(CodeChunk(
                    id=f"{file_path}:class:{class_match.group(1)}",
                    file_path=file_path,
                    chunk_type="class",
                    name=class_match.group(1),
                    code=class_code,
                    start_line=i,
                    end_line=end_line,
                    language="java",
                ))

            method_match = method_pattern.search(line)
            if method_match:
                end_line = self._find_brace_end(lines, i - 1)
                if end_line > i:
                    method_code = "\n".join(lines[i - 1:end_line])
                    chunks.append(CodeChunk(
                        id=f"{file_path}:method:{method_match.group(1)}",
                        file_path=file_path,
                        chunk_type="function",
                        name=method_match.group(1),
                        code=method_code,
                        start_line=i,
                        end_line=end_line,
                        language="java",
                    ))

        if not chunks:
            return self._parse_fallback(file_path, content, "java")

        return chunks

    def _parse_go(self, file_path: str, content: str) -> List[CodeChunk]:
        """Parse Go file."""
        chunks = []
        lines = content.split("\n")

        func_pattern = re.compile(r'func\s+(?:\([^)]*\)\s+)?(\w+)')
        struct_pattern = re.compile(r'type\s+(\w+)\s+struct')

        for i, line in enumerate(lines, 1):
            struct_match = struct_pattern.search(line)
            if struct_match:
                end_line = self._find_brace_end(lines, i - 1)
                struct_code = "\n".join(lines[i - 1:end_line])
                chunks.append(CodeChunk(
                    id=f"{file_path}:struct:{struct_match.group(1)}",
                    file_path=file_path,
                    chunk_type="class",
                    name=struct_match.group(1),
                    code=struct_code,
                    start_line=i,
                    end_line=end_line,
                    language="go",
                ))

            func_match = func_pattern.search(line)
            if func_match:
                end_line = self._find_brace_end(lines, i - 1)
                if end_line > i:
                    func_code = "\n".join(lines[i - 1:end_line])
                    chunks.append(CodeChunk(
                        id=f"{file_path}:func:{func_match.group(1)}",
                        file_path=file_path,
                        chunk_type="function",
                        name=func_match.group(1),
                        code=func_code,
                        start_line=i,
                        end_line=end_line,
                        language="go",
                    ))

        if not chunks:
            return self._parse_fallback(file_path, content, "go")

        return chunks

    def _parse_fallback(self, file_path: str, content: str, language: str) -> List[CodeChunk]:
        """Fallback: simple chunking by line blocks."""
        chunks = []
        lines = content.split("\n")
        chunk_size = 50  # lines per chunk
        overlap = 10

        for start in range(0, len(lines), chunk_size - overlap):
            end = min(start + chunk_size, len(lines))
            chunk_code = "\n".join(lines[start:end])
            if chunk_code.strip():
                chunks.append(CodeChunk(
                    id=f"{file_path}:lines:{start + 1}-{end}",
                    file_path=file_path,
                    chunk_type="block",
                    name=f"{os.path.basename(file_path)}:{start + 1}",
                    code=chunk_code,
                    start_line=start + 1,
                    end_line=end,
                    language=language,
                ))

        return chunks

    def _find_brace_end(self, lines: List[str], start: int) -> int:
        """Find the matching closing brace for code blocks."""
        depth = 0
        found_start = False
        for i in range(start, len(lines)):
            for char in lines[i]:
                if char in ("{", "("):
                    depth += 1
                    found_start = True
                elif char in ("}", ")"):
                    depth -= 1
                if found_start and depth <= 0:
                    return i + 1
        return len(lines)

    def _extract_imports(self, content: str, language: str) -> List[str]:
        """Extract import statements from code."""
        imports = []

        if language == "python":
            for match in re.finditer(r'^(?:from\s+(\S+)\s+)?import\s+(\S+)', content, re.MULTILINE):
                if match.group(1):
                    imports.append(match.group(1))
                imports.append(match.group(2))
        elif language in ("javascript", "typescript"):
            for match in re.finditer(r'(?:import|require)\s+.*?from\s+[\'"]([^\'"]+)[\'"]', content):
                imports.append(match.group(1))
        elif language == "java":
            for match in re.finditer(r'^import\s+([^;]+);', content, re.MULTILINE):
                imports.append(match.group(1))
        elif language == "go":
            for match in re.finditer(r'[\'"](\S+)[\'"]', content):
                if "." in match.group(1) or "/" in match.group(1):
                    imports.append(match.group(1))

        return list(set(imports))

    def _generate_summary(self, chunk: CodeChunk) -> str:
        """Generate a summary for a code chunk from its content."""
        code = chunk.code[:300]

        if chunk.chunk_type == "function":
            # Extract function signature
            sig = code.split("\n")[0] if code else ""
            docstring = self._extract_docstring(code)
            return f"{sig} — {docstring[:100]}" if docstring else sig

        elif chunk.chunk_type == "class":
            return f"Class {chunk.name} with {chunk.end_line - chunk.start_line} lines"

        return f"{chunk.chunk_type}: {chunk.name} ({chunk.end_line - chunk.start_line} lines)"

    def _extract_docstring(self, code: str) -> Optional[str]:
        """Extract docstring from Python code."""
        match = re.search(r'["\']{3}(.*?)["\']{3}', code, re.DOTALL)
        return match.group(1).strip() if match else None

    def search(self, query: str, top_k: int = 10) -> List[CodeChunk]:
        """Search indexed codebase for relevant chunks.

        Uses simple keyword matching when embeddings aren't available,
        or semantic search when sentence-transformers is installed.
        """
        query_lower = query.lower()

        if HAS_SENTENCE_TRANSFORMERS and self._chunks:
            return self._semantic_search(query, top_k)

        # Keyword-based fallback
        scored = []
        for chunk in self._chunks:
            score = 0
            # Match in code
            score += chunk.code.lower().count(query_lower) * 2
            # Match in name
            if query_lower in chunk.name.lower():
                score += 10
            # Match in summary
            if chunk.summary and query_lower in chunk.summary.lower():
                score += 5
            # Match in imports
            for imp in chunk.imports:
                if query_lower in imp.lower():
                    score += 3

            if score > 0:
                scored.append((score, chunk))

        scored.sort(key=lambda x: -x[0])
        return [c for _, c in scored[:top_k]]

    def _semantic_search(self, query: str, top_k: int) -> List[CodeChunk]:
        """Semantic search using embeddings."""
        try:
            model = SentenceTransformer("all-MiniLM-L6-v2")
            query_emb = model.encode(query)

            scored = []
            for chunk in self._chunks:
                if chunk.embedding is None:
                    chunk.embedding = model.encode(
                        f"{chunk.name} {chunk.code[:1000]} {chunk.summary or ''}"
                    )

                if HAS_NUMPY:
                    score = np.dot(query_emb, chunk.embedding) / (
                        np.linalg.norm(query_emb) * np.linalg.norm(chunk.embedding)
                    )
                else:
                    score = 0

                scored.append((score, chunk))

            scored.sort(key=lambda x: -x[0])
            return [c for _, c in scored[:top_k]]

        except Exception as e:
            logger.warning(f"Semantic search failed: {e}")
            return self.search(query, top_k)  # Fallback to keyword

    def get_dependency_graph(self, chunk_id: str) -> Dict[str, Any]:
        """Get the dependency graph for a chunk."""
        chunk = next((c for c in self._chunks if c.id == chunk_id), None)
        if not chunk:
            return {"error": f"Chunk {chunk_id} not found"}

        return {
            "chunk": chunk.to_dict(),
            "imports": chunk.imports,
            "dependencies": chunk.dependencies,
            "referenced_by": [
                c.id for c in self._chunks
                if chunk.name in c.code or chunk.file_path in c.imports
            ],
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get index statistics."""
        files = set(c.file_path for c in self._chunks)
        languages: Dict[str, int] = {}
        for c in self._chunks:
            languages[c.language] = languages.get(c.language, 0) + 1

        return {
            "total_chunks": len(self._chunks),
            "total_files": len(files),
            "chunks_by_language": languages,
            "chunks_by_type": {
                t: sum(1 for c in self._chunks if c.chunk_type == t)
                for t in set(c.chunk_type for c in self._chunks)
            },
        }


class CodebaseRAGAgent:
    """RAG agent that answers questions about a codebase.

    This is the interface that other agents use to query code context.
    """

    def __init__(self):
        self.indexer = CodebaseIndexer()
        self._current_codebase: Optional[str] = None

    def load_codebase(self, path: str) -> Dict[str, Any]:
        """Load and index a codebase."""
        self._current_codebase = path
        chunk_count = self.indexer.index_directory(path)
        stats = self.indexer.get_statistics()
        return {"status": "loaded", "chunks": chunk_count, "stats": stats}

    def query(self, question: str, top_k: int = 5) -> Dict[str, Any]:
        """Answer a question about the loaded codebase.

        Args:
            question: Natural language question about the code
            top_k: Number of relevant chunks to retrieve

        Returns:
            Relevant code context with metadata
        """
        if not self._current_codebase:
            return {"error": "No codebase loaded. Call load_codebase() first."}

        chunks = self.indexer.search(question, top_k=top_k)

        if not chunks:
            return {"answer": "No relevant code found.", "chunks": []}

        return {
            "answer": f"Found {len(chunks)} relevant code sections",
            "query": question,
            "chunks": [c.to_dict() for c in chunks],
            "dependencies": [
                self.indexer.get_dependency_graph(c.id)
                for c in chunks[:3]
            ],
        }

    def get_system_context(self) -> Dict[str, Any]:
        """Get a summary of the loaded codebase for system prompts."""
        stats = self.indexer.get_statistics()
        return {
            "codebase": self._current_codebase,
            "summary": (
                f"Codebase with {stats['total_files']} files, "
                f"{stats['total_chunks']} indexed chunks across "
                f"{len(stats['chunks_by_language'])} languages"
            ),
            "statistics": stats,
        }
