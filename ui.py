"""Terminal UI for the DevOps agent REPL.

Renders each agent turn as a live stream:

* ``You:`` prompt in bold green.
* A spinner showing the current phase — ``Thinking...``, ``Running tool: <name>``,
  ``Processing results...``.
* The final assistant reply rendered as Markdown inside a green panel so
  lists, bold, inline code and headings look right in a TTY.
* A summary table of every tool invocation (name, args, status, finding count).

Events come from ``Agent.stream_async`` in Strands 1.35. That stream
intermixes three event families (raw provider events, typed chunk events
and result envelopes); we just sniff each dict for the fields we care
about. Tool calls are indexed by ``toolUseId`` so multi-tool turns show
the correct status for each row.

When ``rich`` is unavailable the module falls back to a plain stdout path
so the agent keeps working (e.g. piped into a file or automated tests).
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.spinner import Spinner
    from rich.table import Table
    from rich.text import Text

    _RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - defensive fallback
    _RICH_AVAILABLE = False


class AgentUI:
    """Render a Strands agent conversation turn in the terminal."""

    def __init__(self) -> None:
        self._console = Console() if _RICH_AVAILABLE else None

    # ------------------------------------------------------------------
    # Static banners / headers
    # ------------------------------------------------------------------

    def show_banner(
        self,
        session_id: str,
        is_new: bool,
        model_name: str,
        mcp_tools: list[str] | None = None,
    ) -> None:
        verb = "New session" if is_new else "Resumed session"
        if mcp_tools is None:
            mcp_line = "[dim]MCP: not configured[/dim]"
            mcp_line_plain = "MCP: not configured"
        elif not mcp_tools:
            mcp_line = "[yellow]MCP: connected but no tools exposed[/yellow]"
            mcp_line_plain = "MCP: connected but no tools exposed"
        else:
            joined = ", ".join(mcp_tools)
            mcp_line = f"[bold]MCP:[/bold] [green]{len(mcp_tools)} tool(s)[/green] — {joined}"
            mcp_line_plain = f"MCP: {len(mcp_tools)} tool(s) — {joined}"
        if self._console:
            body = Text.from_markup(
                f"[bold]{verb}:[/bold] [cyan]{session_id}[/cyan]\n"
                f"[bold]Model:[/bold] {model_name}\n"
                f"{mcp_line}\n"
                "[dim]Type 'exit' to quit, 'sessions' to list, 'mcp' to recheck MCP.[/dim]"
            )
            self._console.print(Panel(body, title="DevOps Agent", border_style="blue"))
        else:
            print(f"\n{verb}: {session_id}  (model: {model_name})")
            print(mcp_line_plain)
            print("Type 'exit' to quit, 'sessions' to list known sessions.\n")

    def prompt_user(self) -> str:
        if self._console:
            return self._console.input("\n[bold green]You:[/bold green] ")
        return input("\nYou: ")

    def print_sessions(self, listing: str) -> None:
        if self._console:
            self._console.print(Panel(listing, title="Sessions", border_style="cyan"))
        else:
            print(listing)

    def print_error(self, message: str) -> None:
        if self._console:
            self._console.print(f"[bold red]error:[/bold red] {message}")
        else:
            print(f"error: {message}")

    # ------------------------------------------------------------------
    # Streaming the agent's response
    # ------------------------------------------------------------------

    async def stream_turn(self, stream: AsyncIterator[Any]) -> str:
        """Consume a Strands ``stream_async`` iterator and render it live.

        We do NOT render token chunks progressively. Strands' stream emits
        the same text through multiple event shapes (raw provider events,
        typed ``data`` events, and a final wrapped ``result`` envelope),
        which makes de-duplication fragile. Instead we show a rich
        spinner reflecting the current phase (thinking / running tool X /
        responding) and, once the stream completes, render a single
        authoritative ``Panel`` from the final ``result`` text. Output is
        always deterministic: one tool-call table + one answer panel.
        """

        if not self._console:
            return await self._stream_fallback(stream)

        final_text = ""
        # Ordered list of tool calls by first-seen toolUseId so the summary
        # table preserves invocation order.
        tool_order: list[str] = []
        tool_calls: dict[str, dict[str, Any]] = {}

        def current_spinner() -> Any:
            pending = [
                tool_calls[tid]["name"]
                for tid in tool_order
                if tool_calls[tid].get("status") is None
            ]
            if pending:
                label = (
                    f"Running tool: {pending[0]}"
                    if len(pending) == 1
                    else f"Running {len(pending)} tools: {', '.join(pending)}"
                )
                return Spinner("dots", text=Text(label, style="cyan"))
            if tool_order:
                # At least one tool finished already → model is now writing.
                return Spinner("dots", text=Text("Responding…", style="green"))
            return Spinner("dots", text=Text("Thinking…", style="yellow"))

        with Live(
            current_spinner(),
            console=self._console,
            refresh_per_second=12,
            transient=True,
        ) as live:
            async for event in stream:
                if not isinstance(event, dict):
                    continue

                # --- Tool invocation starting ---------------------------
                tool_use = _extract_tool_use_start(event)
                if tool_use:
                    tid = tool_use["id"]
                    if tid and tid not in tool_calls:
                        tool_order.append(tid)
                        tool_calls[tid] = {
                            "name": tool_use["name"],
                            "input": "",
                            "status": None,
                            "result_preview": "(running…)",
                        }
                    live.update(current_spinner())
                    continue

                # --- Tool input delta (args being streamed) -------------
                tool_delta = _extract_tool_input_delta(event)
                if tool_delta and tool_order:
                    tool_calls[tool_order[-1]]["input"] += tool_delta

                # --- Tool results (server returned) ---------------------
                tool_results = _extract_tool_results(event)
                if tool_results:
                    for tr in tool_results:
                        tid = tr.get("toolUseId")
                        if tid and tid in tool_calls:
                            status, preview = _summarize_tool_result(tr)
                            tool_calls[tid]["status"] = status
                            tool_calls[tid]["result_preview"] = preview
                    live.update(current_spinner())
                    continue

                # --- Transition spinner on first text chunk -------------
                if _is_text_chunk(event) and tool_order:
                    live.update(current_spinner())
                    continue

                # --- Final authoritative answer -------------------------
                final = _extract_final_text(event)
                if final:
                    final_text = final

        # Live is transient — now print static output the user can scroll.
        if tool_order:
            self._console.print(
                _render_tool_summary([tool_calls[tid] for tid in tool_order])
            )
        final_text = final_text.strip()
        if final_text:
            self._console.print(
                Panel(
                    Markdown(final_text),
                    title="Agent",
                    border_style="green",
                    padding=(0, 1),
                )
            )
        return final_text

    async def _stream_fallback(self, stream: AsyncIterator[Any]) -> str:
        """Rich-less fallback. Still uses the final ``result`` text only."""

        final_text = ""
        async for event in stream:
            if not isinstance(event, dict):
                continue
            tool = _extract_tool_use_start(event)
            if tool:
                print(f"> tool: {tool['name']}", flush=True)
                continue
            final = _extract_final_text(event)
            if final:
                final_text = final
        if final_text:
            print(final_text)
        return final_text.strip()


# ---------------------------------------------------------------------------
# Event extractors
# ---------------------------------------------------------------------------


def _extract_tool_use_start(event: dict[str, Any]) -> dict[str, Any] | None:
    block = (
        event.get("event", {})
        .get("contentBlockStart", {})
        .get("start", {})
        .get("toolUse")
    )
    if block and block.get("name"):
        return {"name": block["name"], "id": block.get("toolUseId")}
    return None


def _extract_tool_input_delta(event: dict[str, Any]) -> str | None:
    delta = (
        event.get("event", {})
        .get("contentBlockDelta", {})
        .get("delta", {})
        .get("toolUse", {})
        .get("input")
    )
    return delta if isinstance(delta, str) else None


def _extract_tool_results(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every ``toolResult`` block found in a single stream event.

    Strands packs all tool results from a parallel call cycle into a single
    ``{'message': {'role': 'user', 'content': [{'toolResult': …}, …]}}``
    envelope, so yielding the first block only leaves later rows marked as
    still running.
    """

    msg = event.get("message")
    if not isinstance(msg, dict) or msg.get("role") != "user":
        return []
    results: list[dict[str, Any]] = []
    for block in msg.get("content", []):
        if isinstance(block, dict) and isinstance(block.get("toolResult"), dict):
            results.append(block["toolResult"])
    return results


def _is_text_chunk(event: dict[str, Any]) -> bool:
    """Return True when the event carries an assistant text token.

    We never render the chunk itself (Strands duplicates tokens across
    several event shapes); we only use the signal to flip the spinner
    from "running tool" to "responding".
    """

    if isinstance(event.get("data"), str):
        return True
    text = (
        event.get("event", {})
        .get("contentBlockDelta", {})
        .get("delta", {})
        .get("text")
    )
    return isinstance(text, str)


def _extract_final_text(event: dict[str, Any]) -> str | None:
    result = event.get("result")
    if result is None:
        return None
    message = getattr(result, "message", None)
    if not isinstance(message, dict):
        return None
    for block in message.get("content", []):
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            return block["text"]
    return None


def _summarize_tool_result(tool_result: dict[str, Any]) -> tuple[str, str]:
    """Return ``(status, preview)`` for a toolResult block.

    ``status`` is the Strands-level status (``success`` / ``error``).
    ``preview`` is the per-tool JSON summary if parseable, otherwise a
    truncated text snippet.
    """

    status = tool_result.get("status", "?")
    try:
        for block in tool_result.get("content", []):
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if not isinstance(text, str):
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return status, _truncate(text, 50)
            if isinstance(parsed, dict):
                inner_status = parsed.get("status", status)
                count = parsed.get("findings_count")
                if count is not None:
                    return inner_status, f"{count} findings"
                msg = parsed.get("message")
                if msg:
                    return inner_status, _truncate(str(msg), 50)
                return inner_status, "(no findings)"
    except Exception:  # noqa: BLE001 - defensive; preview is best-effort
        pass
    return status, "(result received)"


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _render_tool_summary(tool_calls: list[dict[str, Any]]) -> Any:
    """Render a compact table summarizing every tool invocation."""

    if not _RICH_AVAILABLE:
        return "\n".join(
            f"> {c['name']} — {c.get('status') or '?'} {c.get('result_preview', '')}"
            for c in tool_calls
        )
    table = Table(
        title="Tool calls",
        title_style="bold cyan",
        show_header=True,
        header_style="bold",
        border_style="dim",
        expand=False,
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Args", overflow="fold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Result", style="white", overflow="fold")
    for idx, call in enumerate(tool_calls, 1):
        args = call.get("input", "") or "-"
        if len(args) > 60:
            args = args[:57] + "..."
        status_raw = call.get("status") or "pending"
        status_display = {
            "success": "[green]✓ success[/green]",
            "error": "[red]✗ error[/red]",
            "pending": "[yellow]… running[/yellow]",
        }.get(status_raw, status_raw)
        table.add_row(
            str(idx),
            call["name"],
            args,
            Text.from_markup(status_display),
            call.get("result_preview", ""),
        )
    return table
