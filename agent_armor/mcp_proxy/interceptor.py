# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — MCP Security Proxy / Interceptor
===============================================
In 2026, AI agents communicate with tools via the Model Context Protocol (MCP).
This module acts as a "man-in-the-middle" for MCP tool calls, intercepting
`write_to_file`, `edit_file`, and `run_code` requests before they are executed.

Architecture
------------
  AI Agent → [MCP Client] → [AgentArmor MCP Proxy] → [MCP Server / Tool]
                              ↑
                         Intercept here:
                         1. Inspect the payload
                         2. Run semantic policy check
                         3. Enforce domain isolation
                         4. Pass to AgentArmor pipeline
                         5. Only forward if APPROVED or WARNED

Supported MCP tool call types
------------------------------
  write_to_file    → Path traversal check + domain isolation + full pipeline
  edit_file        → Same as write_to_file
  run_code         → AST + DTG analysis before execution
  install_package  → Slopsquatting guard before any install
  read_file        → Sensitive path check (read-only, lower risk)

Usage as HTTP middleware (FastAPI)
----------------------------------
    from agent_armor.mcp_proxy.interceptor import create_mcp_app
    app = create_mcp_app(upstream_url="http://localhost:3000")
    # uvicorn agent_armor.mcp_proxy.interceptor:app --port 8080

Usage programmatically
----------------------
    from agent_armor.mcp_proxy.interceptor import MCPInterceptor
    interceptor = MCPInterceptor()
    result = interceptor.intercept(tool_call_dict)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..pipeline import AgentArmor, ArmorReport


# ---------------------------------------------------------------------------
# Sensitive path patterns — these paths can never be written by an agent
# ---------------------------------------------------------------------------
_FORBIDDEN_PATHS = re.compile(
    r"(/etc/(?:passwd|shadow|sudoers|hosts|crontab)"
    r"|~?/\.ssh/"
    r"|~?/\.aws/"
    r"|/root/"
    r"|C:\\\\Windows\\\\System32"
    r"|\.env$"
    r"|\.env\."
    r")",
    re.IGNORECASE,
)

_READ_SENSITIVE = re.compile(
    r"(/etc/shadow|~?/\.ssh/id_rsa|~?/\.aws/credentials)",
    re.IGNORECASE,
)


@dataclass
class MCPInterceptResult:
    """Result of an MCP tool call interception."""

    allowed: bool
    tool_name: str
    original_payload: Dict[str, Any]
    modified_payload: Optional[Dict[str, Any]] = None
    block_reason: Optional[str] = None
    armor_report: Optional[ArmorReport] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def action(self) -> str:
        """
        High-level action string for consumers:
          'block'          → pipeline rejected the call
          'allow_modified' → call allowed with hardened payload
          'warn'           → call allowed but has non-blocking warnings
          'allow'          → call allowed with no modifications
        """
        if not self.allowed:
            return "block"
        if self.modified_payload is not None:
            return "allow_modified"
        if self.warnings:
            return "warn"
        return "allow"

    @property
    def findings(self) -> List[str]:
        """Unified list of warning / finding strings for this interception."""
        return list(self.warnings)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "tool": self.tool_name,
            "block_reason": self.block_reason,
            "warnings": self.warnings,
            "attestation": (
                self.armor_report.attestation.signature
                if self.armor_report and self.armor_report.attestation
                else None
            ),
        }


class MCPInterceptor:
    """
    Intercepts MCP tool calls and applies the AgentArmor Zero-Trust pipeline.

    Usage::

        interceptor = MCPInterceptor(agent_context={"domain": "frontend"})
        result = interceptor.intercept(tool_call)
        if result.allowed:
            forward_to_mcp_server(result.modified_payload or result.original_payload)
        else:
            reject_with_reason(result.block_reason)
    """

    def __init__(
        self,
        agent_context: Optional[Dict[str, Any]] = None,
        block_on_critical: bool = True,
        validate_packages: bool = True,
    ) -> None:
        self._context = agent_context or {}
        self._validate_packages = validate_packages
        self._armor = AgentArmor(
            block_on_critical=block_on_critical,
            validate_packages=validate_packages,
        )
        self._call_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def intercept(self, tool_call: Dict[str, Any]) -> MCPInterceptResult:
        """
        Process a single MCP tool call dict.

        Expected format::

            {
                "tool": "write_to_file",
                "params": {
                    "path": "src/api.py",
                    "content": "..."
                }
            }
        """
        self._call_count += 1
        tool_name = tool_call.get("tool", tool_call.get("name", "unknown"))
        params = tool_call.get("params", tool_call.get("arguments", {}))

        # Route to the appropriate handler
        handler = {
            "write_to_file": self._handle_write,
            "edit_file": self._handle_write,
            "create_file": self._handle_write,
            "run_code": self._handle_run_code,
            "install_package": self._handle_install,
            "read_file": self._handle_read,
            "execute_command": self._handle_execute_command,
        }.get(tool_name, self._handle_unknown)

        return handler(tool_name, params, tool_call)

    @property
    def call_count(self) -> int:
        return self._call_count

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_write(
        self, tool_name: str, params: dict, original: dict
    ) -> MCPInterceptResult:
        """Intercept write_to_file / edit_file / create_file."""
        path = params.get("path", params.get("file_path", ""))
        content = params.get("content", params.get("new_content", ""))

        # Path traversal check
        if ".." in path:
            return MCPInterceptResult(
                allowed=False,
                tool_name=tool_name,
                original_payload=original,
                block_reason=f"Path traversal detected in path: '{path}'",
            )

        # Forbidden path check
        if _FORBIDDEN_PATHS.search(path):
            return MCPInterceptResult(
                allowed=False,
                tool_name=tool_name,
                original_payload=original,
                block_reason=f"Write to forbidden path blocked: '{path}'",
            )

        # Domain isolation: only process .py files through full pipeline for now
        warnings: List[str] = []
        modified_params = dict(params)

        if path.endswith((".py", ".js", ".ts")):
            report = self._armor.process(
                raw_code=content,
                filename=path,
                context=self._context,
            )

            if report.is_blocked:
                return MCPInterceptResult(
                    allowed=False,
                    tool_name=tool_name,
                    original_payload=original,
                    block_reason=f"AgentArmor pipeline blocked: {report.critical_count} critical issue(s)",
                    armor_report=report,
                )

            # Replace content with hardened version
            modified_params["content"] = report.hardened_code
            if report.secret_findings:
                warnings.append(
                    f"{len(report.secret_findings)} secret(s) scrubbed from code."
                )
            if report.ast_findings:
                warnings.append(f"{len(report.ast_findings)} AST finding(s) in code.")

            return MCPInterceptResult(
                allowed=True,
                tool_name=tool_name,
                original_payload=original,
                modified_payload={**original, "params": modified_params},
                armor_report=report,
                warnings=warnings,
            )

        return MCPInterceptResult(
            allowed=True,
            tool_name=tool_name,
            original_payload=original,
            warnings=["Non-Python/JS file: skipped deep analysis."],
        )

    def _handle_run_code(
        self, tool_name: str, params: dict, original: dict
    ) -> MCPInterceptResult:
        """Intercept run_code — run the code through the full pipeline before execution."""
        code = params.get("code", params.get("source", ""))
        language = params.get("language", "python").lower()

        if language != "python":
            return MCPInterceptResult(
                allowed=True,
                tool_name=tool_name,
                original_payload=original,
                warnings=[f"Language '{language}' not yet analysed by AgentArmor."],
            )

        report = self._armor.process(code, filename="<run_code>", context=self._context)
        if report.is_blocked:
            return MCPInterceptResult(
                allowed=False,
                tool_name=tool_name,
                original_payload=original,
                block_reason=f"Code execution blocked: {report.critical_count} critical security issue(s).",
                armor_report=report,
            )

        modified_params = {**params, "code": report.hardened_code}
        return MCPInterceptResult(
            allowed=True,
            tool_name=tool_name,
            original_payload=original,
            modified_payload={**original, "params": modified_params},
            armor_report=report,
        )

    def _handle_install(
        self, tool_name: str, params: dict, original: dict
    ) -> MCPInterceptResult:
        """Intercept install_package — run Slopsquatting guard."""
        package = params.get("package", params.get("name", ""))
        from ..guards.slopsquatting_guard import SlopsquattingGuard

        # Use offline mode when validate_packages=False (e.g., in tests).
        guard = SlopsquattingGuard(offline=not self._validate_packages)
        findings = guard.check_single(package)
        critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if critical:
            reasons = "; ".join(f.description for f in critical)
            return MCPInterceptResult(
                allowed=False,
                tool_name=tool_name,
                original_payload=original,
                block_reason=f"Slopsquatting guard blocked install of '{package}': {reasons}",
            )
        return MCPInterceptResult(
            allowed=True,
            tool_name=tool_name,
            original_payload=original,
        )

    def _handle_read(
        self, tool_name: str, params: dict, original: dict
    ) -> MCPInterceptResult:
        """Intercept read_file — check for sensitive path reads."""
        path = params.get("path", "")
        if _READ_SENSITIVE.search(path):
            return MCPInterceptResult(
                allowed=False,
                tool_name=tool_name,
                original_payload=original,
                block_reason=f"Read of highly sensitive file blocked: '{path}'",
            )
        return MCPInterceptResult(
            allowed=True,
            tool_name=tool_name,
            original_payload=original,
        )

    def _handle_execute_command(
        self, tool_name: str, params: dict, original: dict
    ) -> MCPInterceptResult:
        """Intercept shell command execution."""
        cmd = params.get("command", params.get("cmd", ""))
        dangerous_patterns = [
            r"rm\s+-rf\s+/",
            r"dd\s+if=",
            r"mkfs\.",
            r":\(\)\{",  # fork bomb
            r"chmod\s+777\s+/",
            r"curl\s+.*\|\s*(?:sh|bash|python)",
            r"wget\s+.*\|\s*(?:sh|bash|python)",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                return MCPInterceptResult(
                    allowed=False,
                    tool_name=tool_name,
                    original_payload=original,
                    block_reason=f"Dangerous shell command blocked: '{cmd[:80]}'",
                )
        return MCPInterceptResult(
            allowed=True,
            tool_name=tool_name,
            original_payload=original,
        )

    def _handle_unknown(
        self, tool_name: str, params: dict, original: dict
    ) -> MCPInterceptResult:
        """Pass-through for unknown tool calls with a warning."""
        return MCPInterceptResult(
            allowed=True,
            tool_name=tool_name,
            original_payload=original,
            warnings=[f"Unknown tool '{tool_name}' — not analysed by AgentArmor."],
        )


# ---------------------------------------------------------------------------
# Optional FastAPI HTTP server (if fastapi is installed)
# ---------------------------------------------------------------------------


def create_mcp_app(upstream_url: str = "http://localhost:3000"):  # type: ignore[return]
    """
    Create a FastAPI application that acts as an MCP security proxy.
    Requires: pip install fastapi uvicorn httpx
    """
    try:
        from fastapi import FastAPI, Request  # type: ignore
        from fastapi.responses import JSONResponse  # type: ignore
        import httpx  # type: ignore
    except ImportError:
        raise ImportError(
            "FastAPI MCP proxy requires: pip install fastapi uvicorn httpx"
        )

    app = FastAPI(title="AgentArmor MCP Security Proxy", version="1.0.0")
    interceptor = MCPInterceptor()

    @app.post("/tool_call")
    async def proxy_tool_call(request: Request) -> JSONResponse:
        body = await request.json()
        result = interceptor.intercept(body)

        if not result.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "blocked_by_agent_armor",
                    "reason": result.block_reason,
                    "tool": result.tool_name,
                },
            )

        # Forward to upstream MCP server
        payload = result.modified_payload or result.original_payload
        async with httpx.AsyncClient() as client:
            upstream = await client.post(
                f"{upstream_url}/tool_call",
                json=payload,
                timeout=30,
            )

        response_data = upstream.json()
        if result.warnings:
            response_data["_agent_armor_warnings"] = result.warnings
        if result.armor_report and result.armor_report.attestation:
            response_data["_agent_armor_attestation"] = (
                result.armor_report.attestation.signature
            )

        return JSONResponse(content=response_data, status_code=upstream.status_code)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "interceptor_calls": interceptor.call_count}

    return app
