"""SARIF 2.1.0 output for single and batch MCP scans."""

from pathlib import Path

from mcpscan.rules import ALL_RULES, Severity
from mcpscan.scanner import MCPBatchReport, MCPScanResult

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(report: MCPScanResult | MCPBatchReport, paths: list[Path] | None = None) -> dict:
    """Convert findings to SARIF; optional paths identify each scanned input file."""
    scans = report.results if isinstance(report, MCPBatchReport) else [report]
    if paths is not None and len(paths) != len(scans):
        raise ValueError("One source path is required for each scan result")
    rules = [
        {
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.description},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": _LEVELS[rule.severity]},
        }
        for rule in ALL_RULES
    ]
    indexes = {rule.id: i for i, rule in enumerate(ALL_RULES)}
    findings = []
    notifications = []
    for i, scan in enumerate(scans):
        if scan.error:
            notifications.append({"level": "error", "message": {"text": scan.error}})
        for finding in scan.findings:
            result = {
                "ruleId": finding.rule_id,
                "ruleIndex": indexes[finding.rule_id],
                "level": _LEVELS[finding.severity],
                "message": {"text": "\n".join(finding.snippets) or finding.rule.description},
            }
            if paths is not None:
                result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": paths[i].resolve().as_uri()}}}
                ]
            findings.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "mcpscan", "rules": rules}},
                "results": findings,
                "invocations": [
                    {
                        "executionSuccessful": not notifications,
                        "toolExecutionNotifications": notifications,
                    }
                ],
            }
        ],
    }
