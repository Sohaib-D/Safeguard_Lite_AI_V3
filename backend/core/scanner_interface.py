"""
Abstract scanner interface for plugin-style scanner modules.
All scanner modules should implement this interface for consistency.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from backend.schemas.findings import (
    Finding,
    ModuleScanResult,
    ScanMetadata,
)

logger = logging.getLogger(__name__)


class ScannerConfig(ABC):
    """Base configuration for scanner modules."""

    def __init__(
        self,
        timeout: float = 30.0,
        max_concurrency: int = 50,
        max_retries: int = 2,
        retry_delay: float = 1.0,
        rate_limit_delay: float = 0.1,
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.rate_limit_delay = rate_limit_delay


class DefaultScannerConfig(ScannerConfig):
    """Default scanner configuration."""
    pass


class BaseScannerModule(ABC):
    """
    Abstract base class for all scanner modules.
    Provides structured logging, timeout handling, retry logic,
    and evidence collection.
    """

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or DefaultScannerConfig()
        self.logger = logging.getLogger(f"scanner.{self.module_name}")
        self._findings: list[Finding] = []
        self._scan_id: str = ""
        self._target: str = ""
        self._start_time: Optional[datetime] = None

    @property
    @abstractmethod
    def module_name(self) -> str:
        """Unique name for this scanner module."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this module scans."""
        ...

    @property
    def is_passive_only(self) -> bool:
        """Whether this module uses only passive techniques."""
        return True

    @abstractmethod
    async def _execute_scan(self, target: str, **kwargs) -> dict[str, Any]:
        """
        Execute the actual scan logic.
        Returns module-specific raw data dict.
        Subclasses implement this.
        """
        ...

    async def scan(self, target: str, **kwargs) -> ModuleScanResult:
        """
        Public scan method with structured error handling, logging, and timing.
        """
        self._scan_id = str(uuid.uuid4())
        self._target = target
        self._findings = []
        self._start_time = datetime.utcnow()
        start = time.monotonic()

        self.logger.info(
            f"Starting {self.module_name} scan",
            extra={"scan_id": self._scan_id, "target": target}
        )

        metadata = ScanMetadata(
            scan_id=self._scan_id,
            target=target,
            scanner_module=self.module_name,
            start_time=self._start_time,
            passive_only=self.is_passive_only,
        )

        try:
            raw_data = await asyncio.wait_for(
                self._execute_scan(target, **kwargs),
                timeout=self.config.timeout,
            )
            metadata.success = True
        except asyncio.TimeoutError:
            self.logger.warning(
                f"{self.module_name} scan timed out after {self.config.timeout}s",
                extra={"scan_id": self._scan_id, "target": target}
            )
            raw_data = {"error": f"Scan timed out after {self.config.timeout}s", "timed_out": True}
            metadata.success = False
            metadata.error_message = f"Timeout after {self.config.timeout}s"
        except Exception as e:
            self.logger.error(
                f"{self.module_name} scan failed: {e}",
                extra={"scan_id": self._scan_id, "target": target},
                exc_info=True,
            )
            raw_data = {"error": str(e), "failed": True}
            metadata.success = False
            metadata.error_message = str(e)

        elapsed = time.monotonic() - start
        metadata.end_time = datetime.utcnow()
        metadata.duration_seconds = round(elapsed, 3)

        self.logger.info(
            f"Completed {self.module_name} scan in {elapsed:.2f}s "
            f"({len(self._findings)} findings)",
            extra={"scan_id": self._scan_id, "target": target, "duration": elapsed}
        )

        return ModuleScanResult(
            metadata=metadata,
            findings=self._findings.copy(),
            raw_data=raw_data,
        )

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the current scan results."""
        self._findings.append(finding)

    async def _retry_operation(self, coro_factory, operation_name: str = "operation"):
        """Execute an async operation with retry logic."""
        last_error = None
        for attempt in range(self.config.max_retries + 1):
            try:
                return await coro_factory()
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (attempt + 1)
                    self.logger.debug(
                        f"{operation_name} attempt {attempt + 1} failed, "
                        f"retrying in {delay}s: {e}"
                    )
                    await asyncio.sleep(delay)
        raise last_error


class ScannerRegistry:
    """Registry for scanner module plugins."""

    _modules: dict[str, type[BaseScannerModule]] = {}

    @classmethod
    def register(cls, module_class: type[BaseScannerModule]) -> type[BaseScannerModule]:
        """Register a scanner module class."""
        # Instantiate temporarily to get module_name
        # We use the class attribute pattern instead
        name = module_class.__name__
        cls._modules[name] = module_class
        return module_class

    @classmethod
    def get_all(cls) -> dict[str, type[BaseScannerModule]]:
        """Get all registered scanner modules."""
        return cls._modules.copy()

    @classmethod
    def get(cls, name: str) -> Optional[type[BaseScannerModule]]:
        """Get a specific scanner module by class name."""
        return cls._modules.get(name)