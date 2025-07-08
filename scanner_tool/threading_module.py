"""
Threading Module - Handles thread creation and management
This module provides efficient parallel processing capabilities for the port scanner.
"""

import threading
import queue
import logging
import time
import os
from typing import List, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class ThreadingModule:
    """
    Manages thread creation and synchronization for efficient port scanning.
    Provides advanced thread pooling with safeguards for performance.
    """
    
    def __init__(self):
        """Initialize the threading module."""
        self.stop_event = threading.Event()
        # Set reasonable limits for thread count based on system capabilities
        cpu_count = os.cpu_count() or 4  # Default to 4 if cpu_count returns None
        self.MAX_THREAD_COUNT = min(100, cpu_count * 5)
        
    def execute_tasks(self, tasks: List[Tuple[Callable, Tuple]], thread_count: int) -> List[Any]:
        """
        Execute a list of tasks using a thread pool with optimized thread count.
        
        Args:
            tasks: List of (function, args) tuples to execute
            thread_count: Number of threads to use (will be capped if too high)
            
        Returns:
            List[Any]: List of results from the tasks
        """
        # Reset stop event
        self.stop_event.clear()
        
        # Safety: Ensure thread count is reasonable - limit to max threads
        # Use a reasonable limit based on the number of tasks and system capabilities
        optimal_thread_count = min(thread_count, len(tasks), self.MAX_THREAD_COUNT)
        
        # Log if thread count was reduced for performance
        if thread_count > optimal_thread_count:
            logger.warning(f"Thread count reduced from {thread_count} to {optimal_thread_count} for optimal performance")
        
        # Use ThreadPoolExecutor for modern thread management
        results = []
        
        logger.info(f"Starting execution of {len(tasks)} tasks with {optimal_thread_count} threads")
        
        with ThreadPoolExecutor(max_workers=optimal_thread_count) as executor:
            # Submit all tasks to the executor
            futures = []
            for func, args in tasks:
                if self.stop_event.is_set():
                    break
                future = executor.submit(func, *args)
                futures.append(future)
            
            # Collect results as they complete
            for future in futures:
                if self.stop_event.is_set():
                    break
                try:
                    result = future.result(timeout=30)  # Add timeout to prevent hanging
                    if result:  # Only append non-None results
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error in thread execution: {e}")
        
        logger.info(f"Completed execution of {len(tasks)} tasks")
        return results
    
    def stop(self):
        """Signal all threads to stop execution."""
        self.stop_event.set()
        logger.info("Stop signal sent to all threads")
