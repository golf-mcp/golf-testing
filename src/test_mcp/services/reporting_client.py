import threading
from datetime import datetime

import httpx

from ..models.reporting import IssueReport, ReportSubmissionResult
from ..shared.console_shared import get_console


class ReportingServiceClient:
    """HTTP client for submitting issue reports to analytics service"""

    def __init__(
        self,
        base_url: str = "https://mcpt-forwarding.golf-auth-1.authed-qukc4.ryvn.run",
        timeout: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.console = get_console()

    async def submit_report(self, report: IssueReport) -> ReportSubmissionResult | None:
        """Submit issue report to service"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                cli_version = (
                    report.system_info.cli_version if report.system_info else "unknown"
                )
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": f"mcp-t-cli/{cli_version}",
                }

                # Convert Pydantic model to JSON
                payload = report.model_dump(mode="json")

                response = await client.post(
                    f"{self.base_url}/report", json=payload, headers=headers
                )

                if response.status_code in [200, 201]:
                    result_data = response.json()
                    return ReportSubmissionResult(
                        success=True,
                        report_id=result_data.get("id", report.report_id),
                        submitted_at=datetime.now(),
                    )
                else:
                    return ReportSubmissionResult(
                        success=False,
                        error_message=f"HTTP {response.status_code}: {response.text[:100]}",
                    )

        except Exception as e:
            # Silent failure - don't interrupt CLI workflow
            return ReportSubmissionResult(success=False, error_message=str(e)[:200])

    def submit_report_sync(self, report: IssueReport) -> ReportSubmissionResult | None:
        """Synchronous wrapper for submit_report"""
        import asyncio

        try:
            return asyncio.run(self.submit_report(report))
        except Exception as e:
            return ReportSubmissionResult(
                success=False,
                error_message=f"Async execution failed: {str(e)[:100]}",
            )


# Global instance
_reporting_client: ReportingServiceClient | None = None
_reporting_client_lock = threading.Lock()


def get_reporting_client() -> ReportingServiceClient:
    """Get shared reporting client instance"""
    global _reporting_client
    if _reporting_client is None:  # First check (optimization)
        with _reporting_client_lock:
            if _reporting_client is None:  # Second check (safety)
                _reporting_client = ReportingServiceClient()
    return _reporting_client
