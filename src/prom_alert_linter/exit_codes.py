"""Exit code decision logic."""

from __future__ import annotations

from prom_alert_linter.models import AnalysisResult, Severity


def compute_exit_code(result: AnalysisResult, fail_on: Severity) -> int:
    """Calculate the POSIX exit code for the CLI given the result and thresholds.
    
    Returns:
    - 0: Successful run, no findings meeting the `fail_on` criteria.
    - 1: Finished run, but findings matched or exceeded `fail_on` severity.
    - 2: Severe errors occurred (like config failure or complete inability to run).
    """
    
    # Check if there are any parse errors
    # Typically, if fail_on is warning or error, a parse failure is considered a hard failure.
    if result.parse_errors and fail_on in (Severity.WARNING, Severity.ERROR):
        return 1
        
    for finding in result.findings:
        if finding.severity >= fail_on:
            return 1
            
    return 0
