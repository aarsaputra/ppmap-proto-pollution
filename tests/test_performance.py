"""
Unit tests for Performance Optimization Module
"""
import pytest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ppmap.performance import (
    DynamicWorkerScaler,
    SystemResources,
    get_scaler,
    adaptive_parallel_map,
    log_resource_status
)


class TestSystemResources:
    """Tests for SystemResources dataclass."""
    
    def test_create_resources(self):
        """Should create SystemResources instance."""
        resources = SystemResources(
            cpu_count=4,
            cpu_percent=50.0,
            memory_available_mb=8192.0,
            memory_percent=25.0,
            recommended_workers=2
        )
        
        assert resources.cpu_count == 4
        assert resources.recommended_workers == 2


class TestDynamicWorkerScaler:
    """Tests for DynamicWorkerScaler class."""
    
    @pytest.fixture
    def scaler(self):
        """Create scaler instance."""
        return DynamicWorkerScaler(initial_workers=2, min_workers=1, max_workers=8)
    
    def test_initial_workers(self, scaler):
        """Should use provided initial workers."""
        assert scaler.current_workers == 2
    
    def test_min_workers_enforced(self):
        """Should not go below min_workers."""
        scaler = DynamicWorkerScaler(initial_workers=0, min_workers=1)
        # Auto-calculation should be at least 1
        assert scaler.current_workers >= 1
    
    def test_get_system_resources(self, scaler):
        """Should return SystemResources."""
        resources = scaler.get_system_resources()
        
        assert isinstance(resources, SystemResources)
        assert resources.cpu_count >= 1
        assert 0 <= resources.cpu_percent <= 100
        assert resources.memory_available_mb > 0
    
    def test_scale_workers(self, scaler):
        """Should return old and new worker counts."""
        old, new = scaler.scale_workers()
        
        assert isinstance(old, int)
        assert isinstance(new, int)
        assert new >= scaler.min_workers
        assert new <= scaler.max_workers
    
    def test_get_executor(self, scaler):
        """Should return ThreadPoolExecutor."""
        executor = scaler.get_executor()
        
        assert executor is not None
        # Cleanup
        scaler.shutdown()
    
    def test_context_manager(self):
        """Should work as context manager."""
        with DynamicWorkerScaler(initial_workers=2) as scaler:
            assert scaler.current_workers == 2
        # After exit, should be shutdown
    
    @patch('ppmap.performance.psutil')
    def test_high_cpu_reduces_workers(self, mock_psutil, scaler):
        """High CPU should reduce recommended workers."""
        mock_psutil.cpu_percent.return_value = 95.0
        mock_psutil.virtual_memory.return_value = MagicMock(
            available=8 * 1024 * 1024 * 1024,  # 8GB
            percent=30.0
        )
        
        # Force recalculation
        resources = scaler.get_system_resources()
        
        # Should recommend fewer workers under high load
        assert resources.recommended_workers >= 1
    
    @patch('ppmap.performance.psutil')
    def test_low_memory_reduces_workers(self, mock_psutil, scaler):
        """Low memory should reduce recommended workers."""
        mock_psutil.cpu_percent.return_value = 20.0
        mock_psutil.virtual_memory.return_value = MagicMock(
            available=256 * 1024 * 1024,  # 256MB only
            percent=95.0
        )
        
        resources = scaler.get_system_resources()
        
        # Should recommend fewer workers with low memory
        assert resources.recommended_workers >= 1


class TestAdaptiveParallelMap:
    """Tests for adaptive_parallel_map function."""
    
    def test_empty_items(self):
        """Empty items should work."""
        results = list(adaptive_parallel_map(lambda x: x, []))
        assert results == []
    
    def test_simple_map(self):
        """Should execute function on all items."""
        items = [1, 2, 3, 4, 5]
        results = list(adaptive_parallel_map(lambda x: x * 2, items))
        
        assert len(results) == 5
        assert sorted(results) == [2, 4, 6, 8, 10]
    
    def test_with_custom_scaler(self):
        """Should use provided scaler."""
        scaler = DynamicWorkerScaler(initial_workers=2)
        items = [1, 2, 3]
        
        results = list(adaptive_parallel_map(lambda x: x, items, scaler))
        
        assert len(results) == 3
        scaler.shutdown()
    
    def test_handles_exceptions(self):
        """Should handle exceptions in tasks."""
        def failing_func(x):
            if x == 2:
                raise ValueError("Test error")
            return x
        
        items = [1, 2, 3]
        results = list(adaptive_parallel_map(failing_func, items))
        
        # Should have 3 results, one is None (failed)
        assert len(results) == 3
        assert None in results


class TestGetScaler:
    """Tests for get_scaler singleton."""
    
    def test_returns_scaler(self):
        """Should return DynamicWorkerScaler instance."""
        scaler = get_scaler()
        assert isinstance(scaler, DynamicWorkerScaler)
    
    def test_singleton(self):
        """Should return same instance."""
        scaler1 = get_scaler()
        scaler2 = get_scaler()
        assert scaler1 is scaler2


class TestLogResourceStatus:
    """Tests for log_resource_status function."""
    
    def test_returns_resources(self):
        """Should return SystemResources."""
        resources = log_resource_status()
        assert isinstance(resources, SystemResources)
