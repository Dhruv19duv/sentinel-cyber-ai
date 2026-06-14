"""
Context Management — Fable 5's 1M token context window reimplementation.

Matches Fable 5's context capabilities:
- 1M token context window support
- 128K output token support
- Context editing (via context-management beta)
- Intelligent compaction and summarization
- Sliding window management
- Tiered context architecture

Fable 5 spec:
- 1M token context window
- 128K max output tokens
- Context editing via context-management beta header
- Intelligent compaction
- Task budgets (beta)
"""

import json
import logging
import re
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class CompactionStrategy(str, Enum):
    """Strategies for context compaction."""
    NONE = "none"              # No compaction
    SLIDING_WINDOW = "sliding" # Keep last N tokens
    SUMMARIZE = "summarize"    # Summarize old content
    TIERED = "tiered"          # Tiered preservation (high priority kept)


@dataclass
class ContextConfig:
    """Configuration for the context manager.
    
    Matches Fable 5's context window specs.
    """
    max_context_tokens: int = 1_000_000  # 1M tokens (Fable 5 spec)
    max_output_tokens: int = 128_000     # 128K output (Fable 5 spec)
    compaction_threshold: int = 800_000  # Compact when 80% full
    compaction_target: int = 400_000     # Compact to 40% full
    strategy: CompactionStrategy = CompactionStrategy.TIERED
    enable_task_budgets: bool = True
    enable_context_editing: bool = True  # Context-management beta


@dataclass
class ContextBlock:
    """A block of context content with metadata."""
    id: str
    content: str
    block_type: str  # "system", "memory", "conversation", "code", "result", "compacted"
    priority: int  # Higher = preserved during compaction
    token_count: int = 0
    is_editable: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.block_type,
            "priority": self.priority,
            "tokens": self.token_count,
            "content_preview": self.content[:200],
        }


@dataclass
class TaskBudget:
    """Task budget for long-running operations (Fable 5 beta feature)."""
    task_id: str
    max_tokens: int
    used_tokens: int = 0
    max_steps: int = 100
    current_step: int = 0
    start_time: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def remaining_tokens(self) -> int:
        return self.max_tokens - self.used_tokens
    
    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time
    
    @property
    def is_exhausted(self) -> bool:
        return (self.used_tokens >= self.max_tokens or 
                self.current_step >= self.max_steps)


class ContextManager:
    """Manages the model's context window up to 1M tokens.
    
    Matches Fable 5's context management capabilities:
    - 1M token context window
    - Automatic compaction when threshold exceeded
    - Context editing (insert/update/delete blocks)
    - Task budgets for long-running operations
    - Token tracking and budgeting
    """
    
    def __init__(self, config: Optional[ContextConfig] = None):
        self.config = config or ContextConfig()
        self._blocks: List[ContextBlock] = []
        self._task_budgets: Dict[str, TaskBudget] = {}
        self._compaction_count = 0
        self._total_tokens_processed = 0
        
        # Token estimation: ~1.3 tokens per word for English
        self._token_multiplier = 1.3
        
        logger.info(
            f"Context manager initialized: {self.config.max_context_tokens:,} token limit, "
            f"{self.config.max_output_tokens:,} output limit"
        )
    
    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        # Rough estimate: words * 1.3 + special chars
        words = len(text.split())
        special = len(re.findall(r'[^\w\s]', text))
        return int(words * self._token_multiplier + special * 0.5)
    
    def add_block(
        self,
        content: str,
        block_type: str = "conversation",
        priority: int = 5,
        metadata: Optional[Dict] = None,
    ) -> ContextBlock:
        """Add a context block.
        
        If the context window would exceed the limit, compaction is triggered.
        """
        tokens = self._estimate_tokens(content)
        
        block = ContextBlock(
            id=f"ctx-{len(self._blocks) + 1}-{int(time.time())}",
            content=content,
            block_type=block_type,
            priority=priority,
            token_count=tokens,
            metadata=metadata or {},
        )
        
        self._blocks.append(block)
        self._total_tokens_processed += tokens
        
        # Check if compaction needed
        if self.current_tokens > self.config.compaction_threshold:
            self.compact()
        
        return block
    
    def add_system_block(self, content: str) -> ContextBlock:
        """Add a high-priority system block (survives compaction)."""
        return self.add_block(content, block_type="system", priority=10)
    
    def add_code_block(self, content: str, language: str = "") -> ContextBlock:
        """Add a code block with language metadata."""
        formatted = f"```{language}\n{content}\n```" if language else content
        return self.add_block(
            formatted, block_type="code", priority=7,
            metadata={"language": language},
        )
    
    def add_result_block(self, content: str, source: str = "") -> ContextBlock:
        """Add a result/response block."""
        return self.add_block(
            content, block_type="result", priority=4,
            metadata={"source": source},
        )
    
    def update_block(self, block_id: str, new_content: str) -> bool:
        """Edit/update an existing context block.
        
        Matches Fable 5's context-management beta feature
        that allows editing context blocks in-place.
        """
        for block in self._blocks:
            if block.id == block_id:
                if not block.is_editable:
                    logger.warning(f"Block {block_id} is not editable")
                    return False
                old_tokens = block.token_count
                block.content = new_content
                block.token_count = self._estimate_tokens(new_content)
                self._total_tokens_processed += (block.token_count - old_tokens)
                logger.info(f"Updated block {block_id}")
                return True
        return False
    
    def remove_block(self, block_id: str) -> bool:
        """Remove a context block."""
        for i, block in enumerate(self._blocks):
            if block.id == block_id:
                self._blocks.pop(i)
                logger.info(f"Removed block {block_id}")
                return True
        return False
    
    def get_block(self, block_id: str) -> Optional[ContextBlock]:
        """Get a specific context block."""
        for block in self._blocks:
            if block.id == block_id:
                return block
        return None
    
    @property
    def current_tokens(self) -> int:
        """Get current token usage."""
        return sum(b.token_count for b in self._blocks)
    
    @property
    def available_tokens(self) -> int:
        """Get remaining tokens in the context window."""
        return self.config.max_context_tokens - self.current_tokens
    
    @property
    def usage_ratio(self) -> float:
        """Get context window usage as a ratio (0-1)."""
        return self.current_tokens / self.config.max_context_tokens
    
    def compact(self) -> Dict[str, Any]:
        """Compact the context window by summarizing low-priority blocks.
        
        Matches Fable 5's intelligent compaction:
        - High-priority blocks (system, pinned memories) preserved as-is
        - Medium-priority blocks (code, recent conversation) selectively kept
        - Low-priority blocks (old conversation, results) summarized
        """
        self._compaction_count += 1
        
        before_count = len(self._blocks)
        before_tokens = self.current_tokens
        
        # Categorize blocks by priority
        preserved = [b for b in self._blocks if b.priority >= 8 or b.block_type == "system"]
        high_priority = [b for b in self._blocks if 5 <= b.priority < 8]
        medium_priority = [b for b in self._blocks if 3 <= b.priority < 5]
        low_priority = [b for b in self._blocks if b.priority < 3]
        
        # Always preserve high priority
        kept = list(preserved)
        kept.extend(high_priority)
        
        # Summarize medium-priority blocks (keep last N)
        medium_to_keep = []
        if len(medium_priority) > 3:
            # Keep last 3
            medium_to_keep = medium_priority[-3:]
            # Summarize the rest
            old_medium = medium_priority[:-3]
            if old_medium:
                summary = self._summarize_blocks(old_medium, "Conversation History")
                kept.append(ContextBlock(
                    id=f"compact-{self._compaction_count}-medium",
                    content=summary,
                    block_type="compacted",
                    priority=3,
                    token_count=self._estimate_tokens(summary),
                ))
        else:
            medium_to_keep = medium_priority
        
        kept.extend(medium_to_keep)
        
        # Summarize low-priority blocks
        if low_priority:
            summary = self._summarize_blocks(low_priority, "Additional Context")
            kept.append(ContextBlock(
                id=f"compact-{self._compaction_count}-low",
                content=summary,
                block_type="compacted",
                priority=2,
                token_count=self._estimate_tokens(summary),
            ))
        
        self._blocks = kept
        
        after_tokens = self.current_tokens
        
        stats = {
            "compaction_id": self._compaction_count,
            "blocks_before": before_count,
            "blocks_after": len(kept),
            "tokens_before": before_tokens,
            "tokens_after": after_tokens,
            "tokens_saved": before_tokens - after_tokens,
            "compression_ratio": round((1 - after_tokens / before_tokens) * 100, 1) if before_tokens > 0 else 0,
        }
        
        logger.info(
            f"Context compacted: {stats['tokens_saved']:,} tokens saved "
            f"({stats['compression_ratio']}%)"
        )
        
        return stats
    
    def _summarize_blocks(self, blocks: List[ContextBlock], label: str) -> str:
        """Summarize a list of context blocks into a concise string."""
        if not blocks:
            return ""
        
        lines = [f"[{label} — {len(blocks)} blocks]"]
        
        for i, block in enumerate(blocks):
            content = block.content[:200].replace("\n", " ").strip()
            lines.append(f"  {i+1}. [{block.block_type}] {content}")
        
        return "\n".join(lines)
    
    def get_full_context(self) -> str:
        """Get the complete context as a single string.
        
        This is the main output used to feed context into the agent.
        """
        parts = []
        for block in self._blocks:
            parts.append(block.content)
        return "\n\n".join(parts)
    
    def get_context_by_type(self, block_type: str) -> List[ContextBlock]:
        """Get all blocks of a specific type."""
        return [b for b in self._blocks if b.block_type == block_type]
    
    def clear(self, keep_system: bool = True):
        """Clear all context blocks.
        
        Args:
            keep_system: If True, keep system blocks
        """
        if keep_system:
            self._blocks = [b for b in self._blocks if b.block_type == "system"]
        else:
            self._blocks.clear()
        logger.info(f"Context cleared (keep_system={keep_system})")
    
    # ── Task Budgets (Fable 5 beta feature) ──
    
    def create_task_budget(
        self,
        task_id: str,
        max_tokens: int = 10000,
        max_steps: int = 100,
        metadata: Optional[Dict] = None,
    ) -> TaskBudget:
        """Create a task budget for a long-running operation.
        
        Matches Fable 5's task budgets beta feature.
        """
        budget = TaskBudget(
            task_id=task_id,
            max_tokens=max_tokens,
            max_steps=max_steps,
            metadata=metadata or {},
        )
        self._task_budgets[task_id] = budget
        logger.info(f"Created task budget: {task_id} ({max_tokens:,} tokens, {max_steps} steps)")
        return budget
    
    def consume_task_budget(self, task_id: str, tokens: int, steps: int = 1) -> bool:
        """Consume from a task budget.
        
        Returns:
            False if budget is exhausted
        """
        budget = self._task_budgets.get(task_id)
        if not budget:
            return False
        
        budget.used_tokens += tokens
        budget.current_step += steps
        
        if budget.is_exhausted:
            logger.warning(f"Task budget exhausted: {task_id}")
            return False
        return True
    
    def get_task_budget(self, task_id: str) -> Optional[TaskBudget]:
        return self._task_budgets.get(task_id)
    
    def get_status(self) -> Dict[str, Any]:
        """Get context manager status."""
        return {
            "max_context_tokens": self.config.max_context_tokens,
            "max_output_tokens": self.config.max_output_tokens,
            "current_tokens": self.current_tokens,
            "available_tokens": self.available_tokens,
            "usage_ratio": self.usage_ratio,
            "compaction_count": self._compaction_count,
            "total_tokens_processed": self._total_tokens_processed,
            "blocks_count": len(self._blocks),
            "blocks_by_type": {
                t: len([b for b in self._blocks if b.block_type == t])
                for t in set(b.block_type for b in self._blocks)
            },
            "active_task_budgets": len(self._task_budgets),
            "config": {
                "compaction_threshold": self.config.compaction_threshold,
                "strategy": self.config.strategy.value,
                "context_editing": self.config.enable_context_editing,
                "task_budgets": self.config.enable_task_budgets,
            },
        }
