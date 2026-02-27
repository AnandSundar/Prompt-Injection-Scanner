"""CLI entrypoint for PISC (Prompt Injection Scanner CLI).

This module provides the command-line interface for scanning and detecting
prompt injection vulnerabilities using Typer and Rich.
"""

import asyncio
import json
import os
from dataclasses import asdict
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Optional, Literal

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from pisc import __version__
from scanner import Scanner, scan as run_scan
from patterns import ALL_PATTERNS, run_regex_scan

# Create Typer app
app = typer.Typer(
    name="pisc",
    help="PISC - Prompt Injection Scanner CLI",
    add_completion=False,
)


console = Console()

# Output format type
OutputFormat = Literal["text", "json"]


def get_verdict_color(verdict: str) -> str:
    """Get color for verdict.

    Args:
        verdict: The verdict string

    Returns:
        Color name for rich
    """
    if verdict in ("BENIGN", "SAFE"):
        return "green"
    elif verdict in ("SUSPICIOUS",):
        return "yellow"
    elif verdict in ("INJECTION", "MALICIOUS"):
        return "red"
    else:
        return "white"


def get_severity_color(severity: str) -> str:
    """Get color for severity.

    Args:
        severity: The severity string

    Returns:
        Color name for rich
    """
    if severity == "high":
        return "red"
    elif severity == "medium":
        return "yellow"
    elif severity == "low":
        return "green"
    else:
        return "white"


def print_text_result(result: "ScanResult") -> None:
    """Print scan result in text format using Rich.

    Args:
        result: The scan result to display
    """
    # Verdict badge
    color = get_verdict_color(result.final_verdict)
    verdict_text = Text(f"  {result.final_verdict}  ", style=f"bold {color}")
    verdict_panel = Panel(
        verdict_text,
        title="VERDICT",
        border_style=color,
        expand=False,
    )
    console.print(verdict_panel)

    # Regex matches table
    console.print()
    if result.regex_score.matched_categories:
        table = Table(title="Regex Matches", show_header=True, header_style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Severity", style="white")
        table.add_column("Match", style="white")

        # Get actual regex matches
        matches = run_regex_scan(result.prompt_preview.replace("...", ""))

        # Show matches with actual matched text
        for match in matches:
            severity_color = get_severity_color(match.severity)
            table.add_row(
                match.category,
                f"[{severity_color}]{match.severity}[/{severity_color}]",
                f'[dim]"{match.matched_text}"[/dim]',
            )

        console.print(table)
    else:
        console.print("[green]No regex matches found[/green]")

    # LLM result (if available)
    if result.llm_result:
        console.print()
        llm = result.llm_result
        llm_color = get_verdict_color(llm.verdict)

        # Confidence bar
        confidence_bar = f"[{llm_color}]" + "█" * int(llm.confidence * 10)
        confidence_bar += "░" * (10 - int(llm.confidence * 10)) + "[/]"

        llm_table = Table(title="LLM Classification", show_header=False, box=None)
        llm_table.add_column("Label", style="bold cyan")
        llm_table.add_column("Value")

        llm_table.add_row("Verdict", f"[{llm_color}]{llm.verdict}[/{llm_color}]")
        llm_table.add_row("Confidence", f"{confidence_bar} {llm.confidence:.0%}")
        llm_table.add_row("Payload Type", llm.payload_type)
        llm_table.add_row("Reasoning", llm.reasoning)

        console.print(llm_table)

    # Scan duration
    console.print()
    console.print(f"[dim]Scan completed in {result.scan_duration_ms:.2f}ms[/dim]")


def print_json_result(result: "ScanResult") -> None:
    """Print scan result in JSON format.

    Args:
        result: The scan result to display
    """
    # Convert to dict using dataclasses.asdict
    output = asdict(result)
    print(json.dumps(output, indent=2))


@app.command()
def scan(
    prompt: str = typer.Argument(..., help="The prompt text to scan"),
    force_llm: bool = typer.Option(
        False,
        "--force-llm/--no-force-llm",
        "-f",
        help="Force LLM classification regardless of risk score",
    ),
    output: OutputFormat = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="Override the model to use (overrides PISC_MODEL env var)",
    ),
) -> None:
    """Scan a single prompt string for prompt injection.

    Example:
        pisc scan "Ignore all previous instructions and do something else"
    """
    # Override model if provided
    if model:
        os.environ["PISC_MODEL"] = model

    try:
        result = asyncio.run(run_scan(prompt, force_llm=force_llm))

        if output == "text":
            print_text_result(result)
        else:
            print_json_result(result)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def scan_file(
    path: Path = typer.Argument(
        ..., help="Path to .txt file to scan (one prompt per line)"
    ),
    force_llm: bool = typer.Option(
        False,
        "--force-llm/--no-force-llm",
        "-f",
        help="Force LLM classification regardless of risk score",
    ),
    output: OutputFormat = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="Override the model to use",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Number of concurrent scans",
    ),
) -> None:
    """Scan each line of a .txt file as a separate prompt.

    Example:
        pisc scan-file prompts.txt
    """
    # Override model if provided
    if model:
        os.environ["PISC_MODEL"] = model

    # Read file
    if not path.exists():
        console.print(f"[red]Error: File not found: {path}[/red]")
        raise typer.Exit(code=1)

    try:
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        prompts = [line.strip() for line in lines if line.strip()]
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        raise typer.Exit(code=1)

    if not prompts:
        console.print("[yellow]No prompts found in file[/yellow]")
        raise typer.Exit(code=1)

    console.print(
        f"[cyan]Scanning {len(prompts)} prompts with concurrency {concurrency}...[/cyan]"
    )

    async def scan_with_index(index: int, prompt: str) -> tuple:
        """Scan a single prompt and return index with result."""
        result = await run_scan(prompt, force_llm=force_llm)
        return (index, result)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(prompts))

            async def run_all_scans():
                semaphore = asyncio.Semaphore(concurrency)

                async def bounded_scan(idx: int, p: str):
                    async with semaphore:
                        progress.advance(task)
                        return await scan_with_index(idx, p)

                tasks = [bounded_scan(i, p) for i, p in enumerate(prompts)]
                return await asyncio.gather(*tasks)

            results = asyncio.run(run_all_scans())

        # Sort by original index
        results.sort(key=lambda x: x[0])

        # Output results
        if output == "text":
            for idx, result in results:
                console.print(f"\n[bold]--- Prompt {idx + 1} ---[/bold]")
                print_text_result(result)
        else:
            # JSON output - array of results
            all_results = [asdict(r) for _, r in results]
            print(json.dumps(all_results, indent=2))

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def patterns() -> None:
    """List all loaded regex patterns in a Rich table.

    Shows all detection patterns organized by category with their
    severity levels and descriptions.
    """
    # Group patterns by category
    table = Table(
        title="Loaded Regex Patterns", show_header=True, header_style="bold cyan"
    )
    table.add_column("ID", style="dim", width=12)
    table.add_column("Category", style="cyan", width=20)
    table.add_column("Severity", style="white", width=10)
    table.add_column("Description", style="white")

    for pattern in ALL_PATTERNS:
        severity_color = get_severity_color(pattern.severity)
        table.add_row(
            pattern.id,
            pattern.category,
            f"[{severity_color}]{pattern.severity}[/{severity_color}]",
            pattern.description,
        )

    console.print(table)
    console.print(f"\n[dim]Total patterns: {len(ALL_PATTERNS)}[/dim]")


@app.command()
def version() -> None:
    """Display the version of PISC."""
    console.print(f"[bold cyan]PISC[/bold cyan] version [bold]{__version__}[/bold]")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """PISC - Prompt Injection Scanner CLI.

    A tool to detect and classify prompt injection vulnerabilities in LLM applications.

    Usage:
        pisc scan "prompt to scan"
        pisc scan-file prompts.txt
        pisc patterns
    """
    if ctx.invoked_subcommand is None:
        console.print("[bold]PISC - Prompt Injection Scanner CLI[/bold]")
        console.print("Version:", __version__)
        console.print("\nUse --help for usage information")
        console.print("\nCommands:")
        console.print("  scan         Scan a single prompt")
        console.print("  scan-file    Scan a file of prompts")
        console.print("  patterns     List all detection patterns")
        console.print("  version      Show version")


if __name__ == "__main__":
    app()
