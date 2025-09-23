"""
Performance Monitoring and Optimization

Performance monitoring utilities for tracking and optimizing system performance.

Author: AI-SOAR Platform Team
Created: 2025-09-11
"""

import functools
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, Callable, Dict

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Simple performance monitoring utility"""

    def __init__(self):
        self.metrics = {}
        self.query_cache = {}
        self.cache_hit_count = 0
        self.cache_miss_count = 0

    def record_metric(self, name: str, value: float, tags: Dict[str, Any] = None):
        """Record a performance metric"""
        if name not in self.metrics:
            self.metrics[name] = []

        self.metrics[name].append(
            {"value": value, "timestamp": time.time(), "tags": tags or {}}
        )

        # Keep only last 100 entries per metric
        if len(self.metrics[name]) > 100:
            self.metrics[name] = self.metrics[name][-100:]

    def get_average(self, name: str) -> float:
        """Get average value for a metric"""
        if name not in self.metrics or not self.metrics[name]:
            return 0.0

        values = [m["value"] for m in self.metrics[name]]
        return sum(values) / len(values)

    def cache_result(self, key: str, result: Any, ttl: int = 300):
        """Cache a result with TTL"""
        self.query_cache[key] = {"result": result, "expires": time.time() + ttl}

    def get_cached_result(self, key: str) -> Any:
        """Get cached result if not expired"""
        if key in self.query_cache:
            cached = self.query_cache[key]
            if time.time() < cached["expires"]:
                self.cache_hit_count += 1
                return cached["result"]
            else:
                del self.query_cache[key]

        self.cache_miss_count += 1
        return None

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        total_requests = self.cache_hit_count + self.cache_miss_count
        hit_rate = (
            (self.cache_hit_count / total_requests * 100) if total_requests > 0 else 0
        )

        return {
            "cache_hits": self.cache_hit_count,
            "cache_misses": self.cache_miss_count,
            "hit_rate_percent": round(hit_rate, 2),
            "cached_items": len(self.query_cache),
        }


# Global performance monitor instance
perf_monitor = PerformanceMonitor()


def performance_timer(metric_name: str):
    """Decorator to time function execution"""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                perf_monitor.record_metric(metric_name, duration)
                if duration > 1.0:  # Log slow operations
                    logger.warning(f"Slow operation {metric_name}: {duration:.3f}s")

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                perf_monitor.record_metric(metric_name, duration)
                if duration > 1.0:  # Log slow operations
                    logger.warning(f"Slow operation {metric_name}: {duration:.3f}s")

        return async_wrapper if functools.iscoroutinefunction(func) else sync_wrapper

    return decorator


@asynccontextmanager
async def performance_context(operation_name: str):
    """Context manager for timing operations"""
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        perf_monitor.record_metric(operation_name, duration)


def get_performance_summary() -> Dict[str, Any]:
    """Get performance summary for monitoring"""
    summary = {"cache_stats": perf_monitor.get_cache_stats(), "metric_averages": {}}

    for metric_name in perf_monitor.metrics:
        summary["metric_averages"][metric_name] = {
            "average_seconds": round(perf_monitor.get_average(metric_name), 3),
            "sample_count": len(perf_monitor.metrics[metric_name]),
        }

    return summary
