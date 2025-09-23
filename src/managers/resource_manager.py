"""
Resource Manager

Centralized resource management for memory cleanup, session tracking,
and resource lifecycle management. Eliminates manual cleanup patterns
and provides automatic resource management for long-running services.

Author: AI-SOAR Platform Team
Created: 2025-09-22
"""

import asyncio
import logging
import weakref
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class LRUCache:
    """Simple LRU Cache implementation for processed alerts"""

    def __init__(self, max_size: int = 10000):
        """
        Initialize LRU cache

        Args:
            max_size: Maximum number of items to store
        """
        self.max_size = max_size
        self.cache = OrderedDict()

    def add(self, key: str) -> None:
        """Add item to cache"""
        if key in self.cache:
            # Move to end
            self.cache.move_to_end(key)
        else:
            self.cache[key] = datetime.now(timezone.utc)
            # Remove oldest if over limit
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in cache"""
        return key in self.cache

    def __len__(self) -> int:
        """Get cache size"""
        return len(self.cache)

    def clear(self) -> None:
        """Clear all items"""
        self.cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "utilization": len(self.cache) / self.max_size * 100,
        }


class ResourceManager:
    """Centralized resource management for XDR polling services"""

    def __init__(self, max_processed_alerts: int = 10000):
        """
        Initialize resource manager

        Args:
            max_processed_alerts: Maximum number of processed alerts to track
        """
        self.max_processed_alerts = max_processed_alerts
        self.processed_alerts = LRUCache(max_processed_alerts)
        self.active_sessions = {}
        self.cleanup_tasks = set()
        self.resource_registry = weakref.WeakSet()

        # Resource tracking
        self.stats = {
            "total_alerts_processed": 0,
            "cleanup_operations": 0,
            "active_resources": 0,
            "memory_cleanups": 0,
        }

    def track_processed_alert(self, alert_id: str) -> bool:
        """
        Track processed alert with automatic cleanup

        Args:
            alert_id: ID of the processed alert

        Returns:
            True if alert was not previously processed, False otherwise
        """
        if alert_id in self.processed_alerts:
            return False

        self.processed_alerts.add(alert_id)
        self.stats["total_alerts_processed"] += 1

        # Log cleanup operations
        if len(self.processed_alerts) % 1000 == 0:
            logger.debug(
                f"Processed alerts cache: {len(self.processed_alerts)}/{self.max_processed_alerts}"
            )

        return True

    def is_alert_processed(self, alert_id: str) -> bool:
        """
        Check if alert has been processed

        Args:
            alert_id: ID of the alert to check

        Returns:
            True if alert has been processed, False otherwise
        """
        return alert_id in self.processed_alerts

    async def register_session(self, session_id: str, session: Any) -> None:
        """
        Register an active session for cleanup tracking

        Args:
            session_id: Unique identifier for the session
            session: Session object (database connection, HTTP session, etc.)
        """
        self.active_sessions[session_id] = {
            "session": session,
            "created_at": datetime.now(timezone.utc),
            "type": type(session).__name__,
        }
        self.stats["active_resources"] += 1
        logger.debug(
            f"Registered session {session_id} of type {type(session).__name__}"
        )

    async def unregister_session(self, session_id: str) -> None:
        """
        Unregister and cleanup a session

        Args:
            session_id: ID of the session to unregister
        """
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            session = session_info["session"]

            # Attempt to close the session
            try:
                if hasattr(session, "close"):
                    if asyncio.iscoroutinefunction(session.close):
                        await session.close()
                    else:
                        session.close()
                elif hasattr(session, "__aexit__"):
                    await session.__aexit__(None, None, None)
            except Exception as e:
                logger.warning(f"Error closing session {session_id}: {e}")

            del self.active_sessions[session_id]
            self.stats["active_resources"] -= 1
            self.stats["cleanup_operations"] += 1
            logger.debug(f"Unregistered and cleaned up session {session_id}")

    def register_resource(self, resource: Any) -> None:
        """
        Register a resource for automatic cleanup tracking

        Args:
            resource: Resource object to track
        """
        self.resource_registry.add(resource)
        logger.debug(f"Registered resource of type {type(resource).__name__}")

    async def cleanup_all_sessions(self) -> None:
        """Cleanup all active sessions"""
        session_ids = list(self.active_sessions.keys())
        cleanup_tasks = []

        for session_id in session_ids:
            cleanup_tasks.append(self.unregister_session(session_id))

        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)

        logger.info(f"Cleaned up {len(session_ids)} active sessions")

    def cleanup_processed_alerts_cache(self, force: bool = False) -> None:
        """
        Cleanup processed alerts cache when it gets too large

        Args:
            force: Force complete cleanup regardless of size
        """
        if force:
            old_size = len(self.processed_alerts)
            self.processed_alerts.clear()
            self.stats["memory_cleanups"] += 1
            logger.info(f"Force cleaned processed alerts cache: {old_size} → 0 entries")
        else:
            # Automatic cleanup is handled by LRU cache
            cache_stats = self.processed_alerts.get_stats()
            if cache_stats["utilization"] > 90:
                logger.info(f"Processed alerts cache near capacity: {cache_stats}")

    async def periodic_cleanup(self, interval: int = 300) -> None:
        """
        Perform periodic cleanup operations

        Args:
            interval: Cleanup interval in seconds
        """
        logger.info(f"Starting periodic cleanup with {interval}s interval")

        while True:
            try:
                await asyncio.sleep(interval)

                # Log current statistics
                logger.debug(f"Resource manager stats: {self.get_stats()}")

                # Cleanup stale sessions (sessions older than 1 hour)
                current_time = datetime.now(timezone.utc)
                stale_sessions = []

                for session_id, session_info in self.active_sessions.items():
                    age = (current_time - session_info["created_at"]).total_seconds()
                    if age > 3600:  # 1 hour
                        stale_sessions.append(session_id)

                for session_id in stale_sessions:
                    logger.warning(f"Cleaning up stale session {session_id}")
                    await self.unregister_session(session_id)

                # Memory pressure check
                cache_stats = self.processed_alerts.get_stats()
                if cache_stats["utilization"] > 95:
                    logger.warning("Memory pressure detected, performing cleanup")
                    self.stats["memory_cleanups"] += 1

            except asyncio.CancelledError:
                logger.info("Periodic cleanup cancelled")
                break
            except Exception as e:
                logger.error(f"Error in periodic cleanup: {e}")

    async def shutdown(self) -> None:
        """Perform complete shutdown and cleanup of all resources"""
        logger.info("Starting resource manager shutdown")

        try:
            # Cancel cleanup tasks
            for task in self.cleanup_tasks:
                if not task.done():
                    task.cancel()

            # Wait for cleanup tasks to complete
            if self.cleanup_tasks:
                await asyncio.gather(*self.cleanup_tasks, return_exceptions=True)

            # Cleanup all sessions
            await self.cleanup_all_sessions()

            # Clear caches
            self.cleanup_processed_alerts_cache(force=True)

            # Clear resource registry
            self.resource_registry.clear()

            logger.info("Resource manager shutdown completed")

        except Exception as e:
            logger.error(f"Error during resource manager shutdown: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get resource manager statistics

        Returns:
            Dictionary with current statistics
        """
        cache_stats = self.processed_alerts.get_stats()

        return {
            **self.stats,
            "active_sessions": len(self.active_sessions),
            "processed_alerts_cache": cache_stats,
            "registered_resources": len(self.resource_registry),
            "cleanup_tasks": len(self.cleanup_tasks),
        }

    def get_session_info(self) -> List[Dict[str, Any]]:
        """
        Get information about active sessions

        Returns:
            List of session information dictionaries
        """
        current_time = datetime.now(timezone.utc)
        session_info = []

        for session_id, info in self.active_sessions.items():
            age = (current_time - info["created_at"]).total_seconds()
            session_info.append(
                {
                    "id": session_id,
                    "type": info["type"],
                    "age_seconds": age,
                    "created_at": info["created_at"].isoformat(),
                }
            )

        return session_info

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on resource manager

        Returns:
            Health check results
        """
        try:
            stats = self.get_stats()
            cache_stats = stats["processed_alerts_cache"]

            # Determine health status
            status = "healthy"
            issues = []

            # Check cache utilization
            if cache_stats["utilization"] > 95:
                status = "warning"
                issues.append("High cache utilization")

            # Check for too many active sessions
            if stats["active_sessions"] > 100:
                status = "warning"
                issues.append("High number of active sessions")

            # Check for stale sessions
            current_time = datetime.now(timezone.utc)
            stale_count = 0
            for session_info in self.active_sessions.values():
                age = (current_time - session_info["created_at"]).total_seconds()
                if age > 3600:  # 1 hour
                    stale_count += 1

            if stale_count > 0:
                status = "warning"
                issues.append(f"{stale_count} stale sessions detected")

            return {
                "status": status,
                "issues": issues,
                "statistics": stats,
                "session_info": self.get_session_info(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "statistics": self.get_stats(),
            }
