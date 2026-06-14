"""
Persistent Memory System — Fable 5's memory tool reimplementation.

Matches Fable 5's memory capabilities:
- Tiered memory architecture (System > Persistent > Session)
- CLAUDE.md-style persistent memory file
- Compaction via summarization
- Pinning of critical context
- MCP-style memory server integration

Fable 5 spec:
- CLAUDE.md-style persistent files for project/user preferences
- Memory MCP servers for database-backed storage
- Compaction (/compact) to summarize conversation history
- Selective preservation (pinning) of critical context
- Tier 1: System Prompt/Rules, Tier 2: Memory Files, Tier 3: Session History
"""

import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MemoryConfig:
    """Configuration for the memory system."""
    memory_dir: str = "~/.sentinel/memory"
    project_memory_file: str = "SENTINEL.md"  # Like CLAUDE.md
    max_session_tokens: int = 32000
    compaction_threshold_tokens: int = 24000
    max_pinned_items: int = 10


@dataclass
class MemoryEntry:
    """A single memory entry."""
    id: str
    content: str
    entry_type: str  # "system", "project", "session", "compacted"
    priority: int  # Higher = more important, excluded from compaction
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = field(default_factory=list)
    pinned: bool = False
    token_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content[:500],
            "type": self.entry_type,
            "priority": self.priority,
            "timestamp": self.timestamp,
            "tags": self.tags,
            "pinned": self.pinned,
            "tokens": self.token_count,
        }


@dataclass
class MemoryState:
    """Current state of the memory system."""
    system_entries: List[MemoryEntry] = field(default_factory=list)
    project_entries: List[MemoryEntry] = field(default_factory=list)
    session_entries: List[MemoryEntry] = field(default_factory=list)
    compacted_entries: List[MemoryEntry] = field(default_factory=list)
    pinned_entries: List[MemoryEntry] = field(default_factory=list)

    @property
    def total_token_count(self) -> int:
        return sum(
            e.token_count for entries in [
                self.system_entries, self.project_entries,
                self.session_entries, self.compacted_entries,
            ]
            for e in entries if not e.pinned  # Pinned counted separately
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_entries": len(self.system_entries),
            "project_entries": len(self.project_entries),
            "session_entries": len(self.session_entries),
            "compacted_entries": len(self.compacted_entries),
            "pinned_entries": len(self.pinned_entries),
            "total_tokens": self.total_token_count,
        }


class PersistentMemory:
    """Tiered memory system matching Fable 5's memory architecture.
    
    Memory Tiers (matching Fable 5):
    Tier 1: System Prompt/Rules — Stable, high-priority instructions
    Tier 2: Memory Files (SENTINEL.md) — Important summaries of past progress
    Tier 3: Active Session History — Immediate conversation flow
    
    Features:
    - Persistent SENTINEL.md file (like CLAUDE.md)
    - Compaction via summarization
    - Pinning for critical context
    - Auto-compaction when token threshold exceeded
    """
    
    def __init__(self, config: Optional[MemoryConfig] = None):
        self.config = config or MemoryConfig()
        self.state = MemoryState()
        
        # Resolve memory directory
        self.memory_dir = os.path.expanduser(self.config.memory_dir)
        os.makedirs(self.memory_dir, exist_ok=True)
        
        # Load existing memory
        self._load_persistent_memory()
        
        logger.info(f"Memory system initialized at {self.memory_dir}")
    
    def _get_project_memory_path(self) -> str:
        """Get path to the project memory file (like CLAUDE.md)."""
        # Look for project root
        cwd = os.getcwd()
        memory_file = os.path.join(cwd, self.config.project_memory_file)
        
        # Also check parent directories
        for parent in [cwd] + [os.path.dirname(cwd)]:
            test_path = os.path.join(parent, self.config.project_memory_file)
            if os.path.exists(test_path):
                return test_path
        
        return memory_file
    
    def _load_persistent_memory(self):
        """Load existing memory from persistent storage."""
        # Load project memory file
        memory_file = self._get_project_memory_path()
        if os.path.exists(memory_file):
            try:
                with open(memory_file, "r") as f:
                    content = f.read()
                if content.strip():
                    self.state.project_entries.append(MemoryEntry(
                        id="project-memory",
                        content=content,
                        entry_type="project",
                        priority=8,
                        pinned=True,
                        tags=["persistent", "project"],
                        token_count=len(content.split()),
                    ))
                    logger.info(f"Loaded project memory ({len(content.split())} tokens)")
            except Exception as e:
                logger.warning(f"Could not load project memory: {e}")
        
        # Load session memory from disk cache
        session_cache = os.path.join(self.memory_dir, "session_cache.json")
        if os.path.exists(session_cache):
            try:
                with open(session_cache, "r") as f:
                    cached = json.load(f)
                for entry_data in cached.get("session_entries", []):
                    self.state.session_entries.append(MemoryEntry(**entry_data))
                for entry_data in cached.get("compacted_entries", []):
                    self.state.compacted_entries.append(MemoryEntry(**entry_data))
                logger.info(f"Loaded session cache ({len(cached.get('session_entries', []))} entries)")
            except Exception as e:
                logger.warning(f"Could not load session cache: {e}")
    
    def _save_session_cache(self):
        """Save session memory to disk cache."""
        session_cache = os.path.join(self.memory_dir, "session_cache.json")
        try:
            data = {
                "session_entries": [e.to_dict() for e in self.state.session_entries],
                "compacted_entries": [e.to_dict() for e in self.state.compacted_entries],
            }
            with open(session_cache, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save session cache: {e}")
    
    def add_system_entry(self, content: str, priority: int = 10, tags: Optional[List[str]] = None):
        """Add a Tier 1 system-level memory entry (high priority, never compacted)."""
        entry = MemoryEntry(
            id=f"sys-{len(self.state.system_entries) + 1}",
            content=content,
            entry_type="system",
            priority=priority,
            pinned=True,
            tags=tags or ["system"],
            token_count=len(content.split()),
        )
        self.state.system_entries.append(entry)
        logger.info(f"Added system entry: {content[:50]}...")
    
    def add_project_entry(self, content: str, tags: Optional[List[str]] = None):
        """Add a Tier 2 project-level memory entry.
        
        These are persisted to the SENTINEL.md file and survive restarts.
        """
        entry = MemoryEntry(
            id=f"proj-{len(self.state.project_entries) + 1}",
            content=content,
            entry_type="project",
            priority=7,
            pinned=True,
            tags=tags or ["project"],
            token_count=len(content.split()),
        )
        self.state.project_entries.append(entry)
        self._persist_project_memory()
        logger.info(f"Added project entry: {content[:50]}...")
    
    def add_session_entry(
        self,
        content: str,
        priority: int = 5,
        tags: Optional[List[str]] = None,
        pinned: bool = False,
    ):
        """Add a Tier 3 session-level memory entry.
        
        These are subject to compaction when the token limit is exceeded.
        Use pinned=True for critical context that should survive compaction.
        """
        entry = MemoryEntry(
            id=f"sess-{len(self.state.session_entries) + 1}",
            content=content,
            entry_type="session",
            priority=priority,
            tags=tags or ["session"],
            pinned=pinned,
            token_count=len(content.split()),
        )
        
        if pinned:
            self.state.pinned_entries.append(entry)
        else:
            self.state.session_entries.append(entry)
        
        self._save_session_cache()
        
        # Check if compaction is needed
        if self.state.total_token_count > self.config.compaction_threshold_tokens:
            self._compact()
            # Note: in sync context, compaction runs synchronously
            # In async context, compact_async() should be called instead
        
        logger.info(f"Added session entry: {content[:50]}...")
        return entry
    
    def add_conversation_turn(self, role: str, content: str):
        """Add a conversation turn to session memory."""
        entry = MemoryEntry(
            id=f"turn-{len(self.state.session_entries) + 1}",
            content=f"[{role.upper()}] {content}",
            entry_type="session",
            priority=3,
            tags=["conversation", role],
            token_count=len(content.split()),
        )
        self.state.session_entries.append(entry)
        self._save_session_cache()
        return entry
    
    def pin_entry(self, entry_id: str) -> bool:
        """Pin a memory entry to protect it from compaction."""
        for entry in self.state.session_entries:
            if entry.id == entry_id:
                entry.pinned = True
                entry.priority = max(entry.priority, 9)
                self.state.pinned_entries.append(entry)
                self.state.session_entries.remove(entry)
                logger.info(f"Pinned entry {entry_id}")
                return True
        return False
    
    def unpin_entry(self, entry_id: str) -> bool:
        """Unpin a memory entry."""
        for entry in self.state.pinned_entries:
            if entry.id == entry_id:
                entry.pinned = False
                entry.priority = max(entry.priority - 2, 3)
                self.state.session_entries.append(entry)
                self.state.pinned_entries.remove(entry)
                logger.info(f"Unpinned entry {entry_id}")
                return True
        return False
    
    def _compact(self) -> Dict[str, Any]:
        """Compact session memory by summarizing old entries.
        
        Matches Fable 5's /compact command behavior:
        - Pinned entries are preserved as-is
        - Old session entries are summarized into compacted blocks
        - Recent entries (last 5) are kept in full
        """
        if len(self.state.session_entries) <= 5:
            return {"compacted": 0, "total": len(self.state.session_entries)}
        
        # Keep the last 5 entries as-is
        keep_count = min(5, len(self.state.session_entries))
        recent_entries = self.state.session_entries[-keep_count:]
        old_entries = self.state.session_entries[:-keep_count]
        
        if not old_entries:
            return {"compacted": 0, "total": len(self.state.session_entries)}
        
        # Summarize old entries into a compacted block
        summary_lines = []
        for entry in old_entries:
            # Extract the gist of each entry
            content = entry.content[:200]
            summary_lines.append(f"[{entry.tags[0] if entry.tags else 'general'}] {content}")
        
        compacted_content = f"Compacted History ({len(old_entries)} entries):\n" + "\n".join(summary_lines)
        
        compacted_entry = MemoryEntry(
            id=f"compact-{len(self.state.compacted_entries) + 1}",
            content=compacted_content,
            entry_type="compacted",
            priority=4,
            tags=["compacted", "history"],
            token_count=len(compacted_content.split()),
        )
        
        self.state.compacted_entries.append(compacted_entry)
        self.state.session_entries = recent_entries
        
        logger.info(f"Compacted {len(old_entries)} entries into 1 summary block")
        
        self._save_session_cache()
        
        return {
            "compacted": len(old_entries),
            "remaining": len(self.state.session_entries),
            "total": len(self.state.session_entries) + len(self.state.compacted_entries),
        }
    
    async def compact_async(self) -> Dict[str, Any]:
        """Async version of compaction."""
        return self._compact()
    
    def get_compressed_context(self, max_tokens: int = 16000) -> str:
        """Get the full memory context compressed into a prompt string.
        
        This is the main output used to feed memory into the agent's context.
        """
        parts = []
        
        # Tier 1: System entries (always included in full)
        if self.state.system_entries:
            system_content = "\n".join(e.content for e in self.state.system_entries)
            parts.append(f"[SYSTEM]\n{system_content}")
        
        # Tier 2: Project entries (always included)
        if self.state.project_entries:
            project_content = "\n".join(
                e.content for e in self.state.project_entries
            )
            parts.append(f"[PROJECT MEMORY]\n{project_content}")
        
        # Pinned entries (always included)
        if self.state.pinned_entries:
            pinned_content = "\n".join(
                f"- {e.content[:300]}" for e in self.state.pinned_entries
            )
            parts.append(f"[PINNED]\n{pinned_content}")
        
        # Compacted history (summarized)
        if self.state.compacted_entries:
            compacted_content = "\n".join(
                e.content[:500] for e in self.state.compacted_entries[-3:]  # Last 3 compactions
            )
            parts.append(f"[HISTORY]\n{compacted_content}")
        
        # Recent session entries (latest first, truncated by token budget)
        if self.state.session_entries:
            session_parts = []
            token_budget = max_tokens - sum(len(p.split()) for p in parts)
            current_tokens = 0
            
            for entry in reversed(self.state.session_entries):
                entry_tokens = len(entry.content.split())
                if current_tokens + entry_tokens > token_budget:
                    break
                session_parts.append(entry.content)
                current_tokens += entry_tokens
            
            if session_parts:
                parts.append(f"[RECENT SESSION]\n" + "\n".join(reversed(session_parts)))
        
        return "\n\n".join(parts)
    
    def _persist_project_memory(self):
        """Write project memory to the SENTINEL.md file."""
        memory_file = self._get_project_memory_path()
        try:
            content = f"# Sentinel Project Memory\n"
            content += f"Last updated: {datetime.utcnow().isoformat()}\n\n"
            
            for entry in self.state.project_entries:
                content += f"## {entry.tags[0] if entry.tags else 'Memory'} #{entry.id}\n"
                content += f"{entry.content}\n\n"
            
            if self.state.pinned_entries:
                content += "## Pinned Context\n"
                for entry in self.state.pinned_entries:
                    content += f"- {entry.content[:300]}\n"
                content += "\n"
            
            with open(memory_file, "w") as f:
                f.write(content)
            logger.info(f"Persisted project memory to {memory_file}")
        except Exception as e:
            logger.warning(f"Could not persist project memory: {e}")
    
    def forget(self, pattern: str) -> int:
        """Remove memory entries matching a pattern."""
        count = 0
        for entry_list in [self.state.session_entries, self.state.compacted_entries]:
            to_remove = [
                e for e in entry_list
                if pattern.lower() in e.content.lower() or pattern.lower() in (e.tags or [])
            ]
            for e in to_remove:
                entry_list.remove(e)
                count += 1
        
        if count > 0:
            self._save_session_cache()
            logger.info(f"Forgot {count} entries matching '{pattern}'")
        
        return count
    
    def clear_session(self):
        """Clear session memory (keeps system and project memory)."""
        self.state.session_entries.clear()
        self.state.compacted_entries.clear()
        self.state.pinned_entries.clear()
        self._save_session_cache()
        logger.info("Session memory cleared")
    
    def get_status(self) -> Dict[str, Any]:
        """Get memory system status."""
        return {
            "memory_dir": self.memory_dir,
            "project_memory_file": self._get_project_memory_path(),
            "state": self.state.to_dict(),
            "tokens_total": self.state.total_token_count,
            "compaction_threshold": self.config.compaction_threshold_tokens,
            "needs_compaction": self.state.total_token_count > self.config.compaction_threshold_tokens,
        }
