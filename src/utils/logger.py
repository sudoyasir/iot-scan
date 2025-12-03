"""Logger utility for IoT-Scan."""
import logging
from rich.console import Console
from rich.logging import RichHandler
from typing import Optional

console = Console()


class Logger:
    """Custom logger with rich formatting."""
    
    _instance: Optional[logging.Logger] = None
    
    @classmethod
    def get_logger(cls, name: str = "iot-scan", level: int = logging.INFO) -> logging.Logger:
        """Get or create a logger instance.
        
        Args:
            name: Logger name
            level: Logging level
            
        Returns:
            Logger instance
        """
        if cls._instance is None:
            cls._instance = logging.getLogger(name)
            cls._instance.setLevel(level)
            
            # Remove existing handlers
            cls._instance.handlers.clear()
            
            # Add rich handler
            handler = RichHandler(
                console=console,
                rich_tracebacks=True,
                show_time=True,
                show_path=False,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            cls._instance.addHandler(handler)
        
        return cls._instance
    
    @classmethod
    def set_level(cls, level: int) -> None:
        """Set logging level.
        
        Args:
            level: Logging level
        """
        if cls._instance:
            cls._instance.setLevel(level)


def get_logger(name: str = "iot-scan", level: int = logging.INFO) -> logging.Logger:
    """Convenience function to get logger.
    
    Args:
        name: Logger name
        level: Logging level
        
    Returns:
        Logger instance
    """
    return Logger.get_logger(name, level)
