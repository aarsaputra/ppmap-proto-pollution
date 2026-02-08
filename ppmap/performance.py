"""
Performance Optimization Module for PPMAP v5.0
Dynamic worker scaling based on system resources.
"""
import os
import psutil
import logging
from typing import Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


@dataclass
class SystemResources:
    """Current system resource measurements."""
    cpu_count: int
    cpu_percent: float
    memory_available_mb: float
    memory_percent: float
    recommended_workers: int


class DynamicWorkerScaler:
    """
    Dynamically scale worker count based on system resources.
    
    Features:
    - Auto-detect available CPU cores
    - Monitor memory usage
    - Adjust workers during scan
    - Prevent resource exhaustion
    """
    
    # Configuration thresholds
    MIN_WORKERS = 1
    MAX_WORKERS = 10
    HIGH_CPU_THRESHOLD = 80.0      # Reduce workers above this %
    HIGH_MEMORY_THRESHOLD = 85.0   # Reduce workers above this %
    LOW_MEMORY_MB = 512            # Minimum MB before reducing workers
    
    def __init__(self, 
                 initial_workers: Optional[int] = None,
                 min_workers: int = 1,
                 max_workers: int = 10):
        """
        Initialize dynamic scaler.
        
        Args:
            initial_workers: Starting worker count (auto-detect if None)
            min_workers: Minimum allowed workers
            max_workers: Maximum allowed workers
        """
        self.min_workers = max(1, min_workers)
        self.max_workers = max_workers
        self._current_workers = initial_workers or self._calculate_optimal_workers()
        self._executor: Optional[ThreadPoolExecutor] = None
    
    def get_system_resources(self) -> SystemResources:
        """Get current system resource status."""
        try:
            cpu_count = os.cpu_count() or 2
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            memory_available_mb = memory.available / (1024 * 1024)
            memory_percent = memory.percent
            
            recommended = self._calculate_optimal_workers(
                cpu_count, cpu_percent, memory_available_mb, memory_percent
            )
            
            return SystemResources(
                cpu_count=cpu_count,
                cpu_percent=cpu_percent,
                memory_available_mb=memory_available_mb,
                memory_percent=memory_percent,
                recommended_workers=recommended
            )
        except Exception as e:
            logger.warning(f"Could not get system resources: {e}")
            return SystemResources(
                cpu_count=2,
                cpu_percent=50.0,
                memory_available_mb=1024.0,
                memory_percent=50.0,
                recommended_workers=2
            )
    
    def _calculate_optimal_workers(self,
                                    cpu_count: Optional[int] = None,
                                    cpu_percent: Optional[float] = None,
                                    memory_mb: Optional[float] = None,
                                    memory_percent: Optional[float] = None) -> int:
        """Calculate optimal worker count based on resources."""
        # Get defaults if not provided
        if cpu_count is None:
            cpu_count = os.cpu_count() or 2
        if cpu_percent is None:
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
            except:
                cpu_percent = 50.0
        if memory_mb is None or memory_percent is None:
            try:
                mem = psutil.virtual_memory()
                memory_mb = mem.available / (1024 * 1024)
                memory_percent = mem.percent
            except:
                memory_mb = 2048.0
                memory_percent = 50.0
        
        # Base calculation: 1 worker per 2 cores
        base_workers = max(1, cpu_count // 2)
        
        # Adjust for CPU load
        if cpu_percent > self.HIGH_CPU_THRESHOLD:
            base_workers = max(1, base_workers - 1)
        elif cpu_percent < 30.0:
            base_workers = min(base_workers + 1, cpu_count)
        
        # Adjust for memory
        if memory_percent > self.HIGH_MEMORY_THRESHOLD:
            base_workers = max(1, base_workers - 2)
        elif memory_mb < self.LOW_MEMORY_MB:
            base_workers = max(1, base_workers - 1)
        
        # Clamp to limits
        return max(self.min_workers, min(self.max_workers, base_workers))
    
    @property
    def current_workers(self) -> int:
        """Get current worker count."""
        return self._current_workers
    
    def scale_workers(self, force: bool = False) -> Tuple[int, int]:
        """
        Scale workers based on current resources.
        
        Args:
            force: Force recalculation even if recent
            
        Returns:
            Tuple of (old_count, new_count)
        """
        resources = self.get_system_resources()
        old_count = self._current_workers
        new_count = resources.recommended_workers
        
        # Only change if difference is significant
        if abs(new_count - old_count) >= 1 or force:
            self._current_workers = new_count
            logger.info(
                f"Worker scaling: {old_count} -> {new_count} "
                f"(CPU: {resources.cpu_percent}%, MEM: {resources.memory_percent}%)"
            )
        
        return old_count, self._current_workers
    
    def get_executor(self, refresh: bool = False) -> ThreadPoolExecutor:
        """
        Get or create ThreadPoolExecutor with current worker count.
        
        Args:
            refresh: Force recreation of executor
            
        Returns:
            ThreadPoolExecutor instance
        """
        if self._executor is None or refresh:
            if self._executor:
                self._executor.shutdown(wait=False)
            self._executor = ThreadPoolExecutor(max_workers=self._current_workers)
        return self._executor
    
    def shutdown(self):
        """Shutdown executor cleanly."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup."""
        self.shutdown()
        return False


def adaptive_parallel_map(func, items, scaler: Optional[DynamicWorkerScaler] = None):
    """
    Execute function on items with adaptive parallelism.
    
    Args:
        func: Function to apply to each item
        items: Iterable of items
        scaler: Optional DynamicWorkerScaler instance
        
    Yields:
        Results as they complete
    """
    if scaler is None:
        scaler = DynamicWorkerScaler()
    
    items_list = list(items)
    if not items_list:
        return
    
    executor = scaler.get_executor()
    futures = {executor.submit(func, item): item for item in items_list}
    
    completed = 0
    for future in as_completed(futures):
        try:
            result = future.result()
            yield result
        except Exception as e:
            logger.error(f"Task failed: {e}")
            yield None
        
        completed += 1
        
        # Rescale every 10 tasks
        if completed % 10 == 0:
            old, new = scaler.scale_workers()
            if old != new:
                # Recreate executor with new worker count
                executor = scaler.get_executor(refresh=True)


# Singleton instance
_scaler: Optional[DynamicWorkerScaler] = None


def get_scaler(initial_workers: Optional[int] = None) -> DynamicWorkerScaler:
    """Get or create global scaler instance."""
    global _scaler
    if _scaler is None:
        _scaler = DynamicWorkerScaler(initial_workers=initial_workers)
    return _scaler


def log_resource_status():
    """Log current system resource status."""
    scaler = get_scaler()
    resources = scaler.get_system_resources()
    
    logger.info(
        f"System Resources:\n"
        f"  CPU: {resources.cpu_count} cores, {resources.cpu_percent:.1f}% used\n"
        f"  Memory: {resources.memory_available_mb:.0f}MB free, {resources.memory_percent:.1f}% used\n"
        f"  Recommended Workers: {resources.recommended_workers}"
    )
    
    return resources
