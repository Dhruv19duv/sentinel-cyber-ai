"""
Sentinel Cyber AI — Background Worker.

Processes background tasks:
- Asynchronous alert delivery (Slack, Discord, webhooks)
- Metric aggregation and trend analysis
- Active threat lifecycle management
- Periodic housekeeping and cleanup
- Redis-backed job queue processing
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


class SentinelWorker:
    """Background worker for Sentinel Cyber AI.

    Processes queued jobs from Redis, delivers alerts,
    aggregates metrics, and manages threat lifecycles.
    """

    def __init__(self, concurrency: int = 2):
        self.concurrency = concurrency
        self._running = False
        self._monitor: Optional[object] = None
        self._redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        self._api_key = os.environ.get("SENTINEL_API_KEY", "")
        self._poll_interval = float(os.environ.get("SENTINEL_WORKER_POLL", "1.0"))
        self._start_time = time.time()

        logging.basicConfig(
            level=getattr(logging, os.environ.get("SENTINEL_LOG_LEVEL", "INFO")),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )

    @property
    def uptime(self) -> float:
        return time.time() - self._start_time

    def _init_monitor(self):
        """Initialize the monitoring system (lazy import)."""
        if self._monitor is None:
            try:
                from src.monitoring.monitor import (
                    MonitoringSystem,
                    AlertSeverity,
                    AlertChannel,
                )
                self._monitor = MonitoringSystem()
                self._AlertSeverity = AlertSeverity
                self._AlertChannel = AlertChannel

                # Configure webhooks from environment
                slack_url = os.environ.get("SLACK_WEBHOOK_URL")
                if slack_url:
                    self._monitor.register_webhook(AlertChannel.SLACK, slack_url)
                    logger.info("Configured Slack webhook")

                discord_url = os.environ.get("DISCORD_WEBHOOK_URL")
                if discord_url:
                    self._monitor.register_webhook(AlertChannel.DISCORD, discord_url)
                    logger.info("Configured Discord webhook")

                logger.info("Monitoring system initialized")
            except ImportError as e:
                logger.warning(f"Monitoring system not available: {e}")
                self._monitor = None

    async def _process_analysis_job(self, job: dict):
        """Process an analysis job from the queue."""
        job_id = job.get("id", "unknown")
        job_type = job.get("type", "unknown")
        payload = job.get("payload", {})

        logger.info(f"Processing job {job_id} ({job_type})")

        try:
            # Record metric for job processing
            if self._monitor:
                self._monitor.record_metric("jobs_processed", 1, {"type": job_type})
                self._monitor.record_metric("job_latency_ms", time.time() - job.get("queued_at", time.time()))

            # Simulate processing time
            await asyncio.sleep(0.1)

            if job_type == "analysis":
                await self._handle_analysis(job_id, payload)
            elif job_type == "alert_delivery":
                await self._handle_alert_delivery(job_id, payload)
            elif job_type == "threat_update":
                await self._handle_threat_update(job_id, payload)
            elif job_type == "housekeeping":
                await self._handle_housekeeping()
            else:
                logger.warning(f"Unknown job type: {job_type}")

            if self._monitor:
                self._monitor.record_metric("jobs_completed", 1, {"type": job_type})

        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            if self._monitor:
                self._monitor.record_metric("jobs_failed", 1, {"type": job_type})

    async def _handle_analysis(self, job_id: str, payload: dict):
        """Handle a security analysis job."""
        target = payload.get("target", "unknown")
        logger.info(f"Analysis completed for {target}")

    async def _handle_alert_delivery(self, job_id: str, payload: dict):
        """Handle alert delivery to external channels."""
        if not self._monitor:
            return

        alert_data = payload.get("alert", {})
        await self._monitor.send_alert(
            title=alert_data.get("title", "Worker Alert"),
            message=alert_data.get("message", ""),
            severity=getattr(self._AlertSeverity, alert_data.get("severity", "INFO").upper(), self._AlertSeverity.INFO),
            source="worker",
            channel=getattr(self._AlertChannel, alert_data.get("channel", "CONSOLE").upper(), self._AlertChannel.CONSOLE),
            metadata=alert_data.get("metadata", {}),
        )

    async def _handle_threat_update(self, job_id: str, payload: dict):
        """Handle a threat status update."""
        if not self._monitor:
            return
        threat_id = payload.get("threat_id")
        status = payload.get("status", "analyzing")
        note = payload.get("note")
        if threat_id:
            self._monitor.update_threat_status(threat_id, status, note)

    async def _handle_housekeeping(self):
        """Perform periodic housekeeping tasks."""
        if not self._monitor:
            return

        # Log current metrics summary
        summary = self._monitor.get_status()
        if summary.get("total_alerts", 0) > 0:
            logger.info(
                f"Housekeeping: {summary['total_alerts']} alerts, "
                f"{summary['active_threats']} active threats, "
                f"{summary['metrics_collected']} metrics"
            )

        # Record worker health metric
        self._monitor.record_metric("worker_uptime_seconds", self.uptime, {"status": "healthy"})

    async def _poll_redis(self):
        """Poll Redis for new jobs (when Redis is available)."""
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(self._redis_url, decode_responses=True)

            logger.info(f"Connected to Redis at {self._redis_url}")

            while self._running:
                try:
                    # Blocking pop from job queue
                    result = await r.blpop("sentinel:jobs", timeout=self._poll_interval)
                    if result and len(result) == 2:
                        _, job_data = result
                        try:
                            job = json.loads(job_data)
                            await self._process_analysis_job(job)
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid job data: {e}")
                except Exception as e:
                    logger.error(f"Redis poll error: {e}")
                    await asyncio.sleep(5)
        except ImportError:
            logger.warning("redis.asyncio not available. Running in standalone mode.")
            await self._standalone_mode()
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            logger.info("Falling back to standalone mode")
            await self._standalone_mode()

    async def _standalone_mode(self):
        """Run in standalone mode without Redis — periodic housekeeping only."""
        logger.info(f"Starting standalone worker (housekeeping every 60s, concurrency={self.concurrency})")
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _do_housekeeping():
            async with semaphore:
                logger.debug("Running housekeeping cycle")
                if self._monitor:
                    self._monitor.record_metric("worker_heartbeat", 1)
                await self._handle_housekeeping()

        while self._running:
            await _do_housekeeping()
            # Process sequential tasks
            await asyncio.sleep(60)

    async def run(self):
        """Start the worker."""
        self._running = True
        self._init_monitor()

        logger.info(f"Sentinel Worker starting (concurrency={self.concurrency})")
        logger.info(f"Redis URL: {self._redis_url}")
        logger.info("Monitoring: %s", "enabled" if self._monitor else "disabled (no module)")

        try:
            await self._poll_redis()
        except asyncio.CancelledError:
            logger.info("Worker cancelled")
        finally:
            self._running = False
            logger.info("Sentinel Worker stopped")

    def stop(self):
        """Stop the worker gracefully."""
        self._running = False
        logger.info("Stop signal received, shutting down...")


def main():
    """Entry point for the worker process."""
    concurrency = int(os.environ.get("SENTINEL_WORKER_CONCURRENCY", "2"))

    worker = SentinelWorker(concurrency=concurrency)

    def _signal_handler(sig, frame):
        worker.stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        asyncio.run(worker.run())
    except KeyboardInterrupt:
        worker.stop()


if __name__ == "__main__":
    main()
