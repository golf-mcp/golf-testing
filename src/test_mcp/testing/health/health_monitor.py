import time
from datetime import datetime
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from ...shared.progress_tracker import ProgressTracker, ExecutionStatus
from ...shared.result_models import BaseTestResult, SuiteCategory


class MCPHealthMetrics(BaseModel):
    """MCP server health metrics"""

    response_time_ms: float = Field(
        ..., description="Server response time in milliseconds"
    )
    is_responsive: bool = Field(..., description="Whether server is responding")
    protocol_version: str | None = Field(
        default=None, description="MCP protocol version"
    )
    capabilities_count: int = Field(default=0, description="Number of capabilities")
    tools_count: int = Field(default=0, description="Number of tools available")
    resources_count: int = Field(default=0, description="Number of resources available")
    error_rate: float = Field(default=0.0, description="Error rate in recent requests")
    uptime_minutes: float | None = Field(default=None, description="Estimated uptime")


class MCPHealthTestResult(BaseTestResult):
    """Result of MCP health monitoring test (extends BaseTestResult)"""

    test_type: SuiteCategory = Field(
        default=SuiteCategory.COMPLIANCE, description="Test type identifier"
    )

    # Health-specific fields
    check_name: str = Field(..., description="Name of health check")
    category: str = Field(..., description="Health check category")
    health_status: str = Field(..., description="healthy, degraded, unhealthy")
    metrics: MCPHealthMetrics | None = Field(default=None, description="Health metrics")
    alert_level: str = Field(
        default="info", description="info, warning, error, critical"
    )


class MCPHealthMonitor:
    """MCP server health and performance monitoring"""

    def __init__(
        self, server_url: str, progress_tracker: ProgressTracker | None = None
    ):
        self.server_url = server_url
        self.progress_tracker = progress_tracker
        self.baseline_metrics: MCPHealthMetrics | None = None

    async def run_health_checks(self) -> list[MCPHealthTestResult]:
        """Run comprehensive health checks on MCP server"""
        results = []

        # Basic connectivity health check
        results.append(await self._test_server_connectivity())

        # Response time health check
        results.append(await self._test_response_time())

        # Protocol health check
        results.append(await self._test_protocol_health())

        return results

    async def _test_server_connectivity(self) -> MCPHealthTestResult:
        """Test basic server connectivity and health"""
        test_id = uuid4()
        start_time = datetime.now()

        if self.progress_tracker:
            self.progress_tracker.update_test_status(
                str(test_id),
                SuiteCategory.COMPLIANCE,
                ExecutionStatus.RUNNING,
                step_description="Testing server connectivity",
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                ping_start = time.perf_counter()

                # Send basic ping/health check
                health_request = {"jsonrpc": "2.0", "id": 999, "method": "ping"}

                response = await client.post(self.server_url, json=health_request)
                response_time = (time.perf_counter() - ping_start) * 1000

                is_healthy = response.status_code == 200
                health_status = "healthy" if is_healthy else "unhealthy"

                metrics = MCPHealthMetrics(
                    response_time_ms=response_time,
                    is_responsive=is_healthy,
                    error_rate=0.0 if is_healthy else 1.0,
                )

                end_time = datetime.now()
                return MCPHealthTestResult(
                    test_id=str(test_id),
                    check_name="Server Connectivity",
                    category="Health",
                    health_status=health_status,
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=is_healthy,
                    metrics=metrics,
                    alert_level="error" if not is_healthy else "info",
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPHealthTestResult(
                test_id=str(test_id),
                check_name="Server Connectivity",
                category="Health",
                health_status="unhealthy",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                error_message=str(e),
                alert_level="critical",
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_response_time(self) -> MCPHealthTestResult:
        """Test server response time performance"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            async with httpx.AsyncClient() as client:
                # Measure response time for multiple requests
                response_times = []

                for i in range(5):  # Test with 5 requests
                    ping_start = time.perf_counter()

                    try:
                        response = await client.post(
                            self.server_url,
                            json={"jsonrpc": "2.0", "id": i, "method": "ping"},
                        )

                        if response.status_code == 200:
                            response_time = (time.perf_counter() - ping_start) * 1000
                            response_times.append(response_time)

                    except Exception:
                        pass  # Skip failed requests

                if response_times:
                    avg_response_time = sum(response_times) / len(response_times)

                    # Determine health based on response time
                    if avg_response_time < 1000:  # < 1 second
                        health_status = "healthy"
                        alert_level = "info"
                    elif avg_response_time < 5000:  # < 5 seconds
                        health_status = "degraded"
                        alert_level = "warning"
                    else:
                        health_status = "unhealthy"
                        alert_level = "error"

                    metrics = MCPHealthMetrics(
                        response_time_ms=avg_response_time,
                        is_responsive=True,
                        error_rate=1.0 - (len(response_times) / 5),
                    )

                    end_time = datetime.now()
                    return MCPHealthTestResult(
                        test_id=str(test_id),
                        check_name="Response Time",
                        category="Performance",
                        health_status=health_status,
                        start_time=start_time,
                        end_time=end_time,
                        status=ExecutionStatus.COMPLETED,
                        success=health_status != "unhealthy",
                        metrics=metrics,
                        alert_level=alert_level,
                        duration=(end_time - start_time).total_seconds(),
                    )
                else:
                    # No successful responses
                    end_time = datetime.now()
                    return MCPHealthTestResult(
                        test_id=str(test_id),
                        check_name="Response Time",
                        category="Performance",
                        health_status="unhealthy",
                        start_time=start_time,
                        end_time=end_time,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error_message="No successful responses",
                        alert_level="critical",
                        duration=(end_time - start_time).total_seconds(),
                    )

        except Exception as e:
            end_time = datetime.now()
            return MCPHealthTestResult(
                test_id=str(test_id),
                check_name="Response Time",
                category="Performance",
                health_status="unhealthy",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                error_message=str(e),
                alert_level="error",
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_protocol_health(self) -> MCPHealthTestResult:
        """Test MCP protocol health and capabilities"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            async with httpx.AsyncClient() as client:
                # Send initialize request to check protocol health
                init_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "mcp-health-monitor",
                            "version": "1.0.0",
                        },
                    },
                }

                response = await client.post(self.server_url, json=init_request)

                if response.status_code == 200:
                    init_response = response.json()

                    if "result" in init_response:
                        result = init_response["result"]
                        capabilities = result.get("capabilities", {})

                        metrics = MCPHealthMetrics(
                            response_time_ms=100,  # Placeholder
                            is_responsive=True,
                            protocol_version=result.get("protocolVersion"),
                            capabilities_count=len(capabilities),
                            error_rate=0.0,
                        )

                        end_time = datetime.now()
                        return MCPHealthTestResult(
                            test_id=str(test_id),
                            check_name="Protocol Health",
                            category="Protocol",
                            health_status="healthy",
                            start_time=start_time,
                            end_time=end_time,
                            status=ExecutionStatus.COMPLETED,
                            success=True,
                            metrics=metrics,
                            alert_level="info",
                            duration=(end_time - start_time).total_seconds(),
                        )

                # Protocol initialization failed
                end_time = datetime.now()
                return MCPHealthTestResult(
                    test_id=str(test_id),
                    check_name="Protocol Health",
                    category="Protocol",
                    health_status="unhealthy",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.FAILED,
                    success=False,
                    error_message="MCP protocol initialization failed",
                    alert_level="error",
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPHealthTestResult(
                test_id=str(test_id),
                check_name="Protocol Health",
                category="Protocol",
                health_status="unhealthy",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                error_message=str(e),
                alert_level="error",
                duration=(end_time - start_time).total_seconds(),
            )

    def get_health_summary(self, results: list[MCPHealthTestResult]) -> dict[str, Any]:
        """Generate health summary from test results"""
        healthy_checks = len([r for r in results if r.health_status == "healthy"])
        total_checks = len(results)

        overall_status = "healthy"
        if healthy_checks == 0:
            overall_status = "unhealthy"
        elif healthy_checks < total_checks:
            overall_status = "degraded"

        return {
            "overall_status": overall_status,
            "healthy_checks": healthy_checks,
            "total_checks": total_checks,
            "health_percentage": (
                (healthy_checks / total_checks) * 100 if total_checks > 0 else 0
            ),
            "timestamp": datetime.now().isoformat(),
        }
