"""
Collaborative Multi-Orchestrator — Distributed Sentinel Deployment.

Fable 5 is a single API endpoint. Sentinel can be a distributed cluster:
1. Multi-node deployment with load balancing
2. Agent sharding across nodes
3. Distributed task queue
4. Cross-node knowledge sharing
5. High availability with failover
6. Horizontal scaling for large codebases
"""

import asyncio
import json
import logging
import os
import time
import uuid
import hashlib
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque

logger = logging.getLogger(__name__)


class NodeRole(str, Enum):
    PRIMARY = "primary"
    WORKER = "worker"
    GATEWAY = "gateway"
    STANDBY = "standby"


class TaskStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DELEGATED = "delegated"


@dataclass
class ClusterNode:
    """A node in the distributed Sentinel cluster."""
    node_id: str
    host: str
    port: int
    role: NodeRole
    agents: List[str]  # Which agents this node hosts
    capacity: float  # 0.0 to 1.0, how loaded the node is
    status: str = "active"  # active, overloaded, offline
    last_heartbeat: float = field(default_factory=time.time)
    task_count: int = 0
    max_tasks: int = 10
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "role": self.role.value,
            "agents": self.agents[:5],
            "capacity": self.capacity,
            "status": self.status,
            "last_heartbeat": datetime.fromtimestamp(self.last_heartbeat).isoformat(),
            "task_count": self.task_count,
        }


@dataclass
class DistributedTask:
    """A task distributed across cluster nodes."""
    task_id: str
    query: str
    assigned_node: str
    status: TaskStatus
    priority: int = 5
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "node": self.assigned_node,
            "status": self.status.value,
            "priority": self.priority,
            "query": self.query[:100],
            "age_seconds": time.time() - self.created_at,
        }


class DistributedOrchestrator:
    """Distributed multi-node orchestrator for horizontal scaling.

    Features:
    - Automatic task distribution across nodes
    - Agent sharding (nodes specialize in different tasks)
    - Load-based routing (busy nodes get fewer tasks)
    - Heartbeat monitoring with automatic failover
    - Cross-node knowledge synchronization
    - Horizontal scaling (add nodes dynamically)
    """

    def __init__(self, node_id: Optional[str] = None):
        self.node_id = node_id or f"sentinel-{uuid.uuid4().hex[:8]}"
        self._nodes: Dict[str, ClusterNode] = {}
        self._tasks: Dict[str, DistributedTask] = {}
        self._task_queue: deque = deque(maxlen=1000)
        self._completed_tasks: deque = deque(maxlen=100)
        self._knowledge_cache: Dict[str, Any] = {}
        self._local_orchestrator = None

        # Register self as primary
        self._register_self()

        logger.info(f"Distributed Orchestrator initialized: {self.node_id}")

    def _register_self(self):
        """Register this node as the primary coordinator."""
        self._nodes[self.node_id] = ClusterNode(
            node_id=self.node_id,
            host="localhost",
            port=0,
            role=NodeRole.PRIMARY,
            agents=["coordinator"],
            capacity=0.0,
            status="active",
        )

    def set_local_orchestrator(self, orchestrator):
        """Set the local orchestrator instance."""
        self._local_orchestrator = orchestrator
        logger.info("Local orchestrator registered with distributed system")

    def register_node(self, node_id: str, host: str, port: int,
                      role: NodeRole, agents: List[str],
                      max_tasks: int = 10) -> ClusterNode:
        """Register a new node in the cluster."""
        node = ClusterNode(
            node_id=node_id,
            host=host,
            port=port,
            role=role,
            agents=agents,
            capacity=0.0,
            max_tasks=max_tasks,
        )
        self._nodes[node_id] = node
        logger.info(f"Node registered: {node_id} ({role.value}) at {host}:{port}")
        return node

    def remove_node(self, node_id: str):
        """Remove a node from the cluster."""
        if node_id in self._nodes:
            node = self._nodes[node_id]
            node.status = "offline"

            # Reassign tasks from offline node
            reassigned = self._reassign_tasks(node_id)
            logger.info(f"Node removed: {node_id} ({reassigned} tasks reassigned)")

    def heartbeat(self, node_id: str, capacity: float,
                  task_count: int) -> bool:
        """Receive heartbeat from a node.

        Returns:
            True if node is still registered
        """
        node = self._nodes.get(node_id)
        if not node:
            return False

        node.last_heartbeat = time.time()
        node.capacity = capacity
        node.task_count = task_count
        node.status = "active" if capacity < 0.9 else "overloaded"

        return True

    def check_heartbeats(self, timeout_seconds: int = 30):
        """Check for stale nodes and mark them offline."""
        now = time.time()
        for node_id, node in list(self._nodes.items()):
            if node_id == self.node_id:
                continue
            if now - node.last_heartbeat > timeout_seconds:
                node.status = "offline"
                logger.warning(f"Node heartbeat timeout: {node_id} "
                              f"(last: {datetime.fromtimestamp(node.last_heartbeat).isoformat()})")

    def _select_best_node(self, query: str,
                          required_agents: Optional[List[str]] = None) -> Optional[ClusterNode]:
        """Select the best node for a task based on:
        1. Agent availability (node has the required agent)
        2. Load (least loaded node wins)
        3. Role (prefer workers over primary for actual work)
        """
        candidates = []

        for node_id, node in self._nodes.items():
            if node_id == self.node_id:
                continue
            if node.status != "active":
                continue
            if node.task_count >= node.max_tasks:
                continue

            # Check agent availability
            if required_agents:
                has_agents = any(
                    agent in node.agents for agent in required_agents
                )
                if not has_agents:
                    continue

            # Score: lower capacity = better
            score = node.capacity + (node.task_count / node.max_tasks) * 0.5
            if node.role == NodeRole.WORKER:
                score -= 0.2  # Prefer workers
            elif node.role == NodeRole.STANDBY:
                score += 0.3  # Less prefer standby

            candidates.append((score, node))

        if not candidates:
            return None

        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]

    async def submit_task(self, query: str, priority: int = 5,
                          required_agents: Optional[List[str]] = None,
                          timeout_seconds: int = 120) -> DistributedTask:
        """Submit a task to the distributed system.

        Args:
            query: Analysis query
            priority: Task priority (1-10, higher = more important)
            required_agents: Which agents are needed
            timeout_seconds: Task timeout

        Returns:
            DistributedTask with assignment info
        """
        task_id = f"dtask-{uuid.uuid4().hex[:12]}"

        # Select best node
        node = self._select_best_node(query, required_agents)

        if node is None:
            # Fall back to local orchestrator
            task = DistributedTask(
                task_id=task_id,
                query=query,
                assigned_node=self.node_id,
                status=TaskStatus.QUEUED,
                priority=priority,
            )
            self._tasks[task_id] = task
            self._task_queue.append(task_id)

            if self._local_orchestrator:
                try:
                    task.status = TaskStatus.PROCESSING
                    task.started_at = time.time()
                    result = await self._local_orchestrator.process(query)
                    task.status = TaskStatus.COMPLETED
                    task.completed_at = time.time()
                    task.result = result
                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.error = str(e)

            return task

        # Assign to remote node
        node.task_count += 1
        task = DistributedTask(
            task_id=task_id,
            query=query,
            assigned_node=node.node_id,
            status=TaskStatus.DELEGATED,
            priority=priority,
        )
        self._tasks[task_id] = task
        self._completed_tasks.append(task)

        logger.info(f"Task {task_id} delegated to node {node.node_id} "
                    f"(capacity: {node.capacity:.2f})")

        return task

    def _reassign_tasks(self, node_id: str) -> int:
        """Reassign tasks from an offline node to other nodes."""
        count = 0
        for task_id, task in list(self._tasks.items()):
            if task.assigned_node == node_id and task.status == TaskStatus.DELEGATED:
                task.status = TaskStatus.QUEUED
                task.assigned_node = ""
                self._task_queue.append(task_id)
                count += 1
        return count

    def sync_knowledge(self, source_node_id: str,
                       knowledge: Dict[str, Any]):
        """Synchronize knowledge from another node."""
        self._knowledge_cache.update(knowledge)
        logger.info(f"Knowledge synced from {source_node_id}: "
                    f"{len(knowledge)} items")

    def get_knowledge(self, key: Optional[str] = None) -> Any:
        """Get synced knowledge."""
        if key:
            return self._knowledge_cache.get(key)
        return self._knowledge_cache

    def get_node_count(self) -> Dict[str, int]:
        """Get node counts by role."""
        counts = {}
        for node in self._nodes.values():
            role = node.role.value
            counts[role] = counts.get(role, 0) + 1
        return counts

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster-wide status."""
        active_nodes = sum(1 for n in self._nodes.values() if n.status == "active")
        offline_nodes = sum(1 for n in self._nodes.values() if n.status == "offline")
        total_capacity = sum(n.capacity for n in self._nodes.values())
        avg_capacity = total_capacity / len(self._nodes) if self._nodes else 0

        return {
            "cluster_id": self.node_id,
            "total_nodes": len(self._nodes),
            "active_nodes": active_nodes,
            "offline_nodes": offline_nodes,
            "node_roles": self.get_node_count(),
            "avg_capacity": round(avg_capacity, 2),
            "total_tasks": len(self._tasks),
            "queued_tasks": len(self._task_queue),
            "total_completed": len(self._completed_tasks),
            "knowledge_items": len(self._knowledge_cache),
            "nodes": [n.to_dict() for n in self._nodes.values()],
        }
