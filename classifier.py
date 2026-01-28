#!/usr/bin/env python3
'''
POC: Scan PE files for malware using EMBER2024 models

Follow the documentation at https://github.com/FutureComputing4AI/EMBER2024 for installation instructions.

Usage:
    python classifier.py <file_or_directory>
    python classifier.py C:/Windows/System32/notepad.exe
    python classifier.py C:/Windows/System32
'''

import argparse
import sys
from pathlib import Path

import lightgbm as lgb
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

import thrember


# Default paths
SCRIPT_DIR = Path(__file__).parent.resolve()
MODELS_DIR = SCRIPT_DIR.parent / "models"
DEFAULT_MODEL = "EMBER2024_PE.model"

console = Console()


def load_model(models_dir: Path, model_name: str = DEFAULT_MODEL) -> lgb.Booster:
    """Load a LightGBM model."""
    model_path = models_dir / model_name
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    return lgb.Booster(model_file=str(model_path))


def scan_file(model: lgb.Booster, file_path: Path) -> dict:
    """
    Scan a single file and return prediction results.

    Returns:
        dict with keys: path, name, malware_probability, prediction, error
    """
    result = {
        "path": str(file_path),
        "name": file_path.name,
        "malware_probability": None,
        "prediction": None,
        "error": None,
    }

    try:
        file_data = file_path.read_bytes()
        probability = thrember.predict_sample(model, file_data)

        result["malware_probability"] = probability
        result["prediction"] = "MALICIOUS" if probability > 0.5 else "BENIGN"

    except Exception as e:
        result["error"] = str(e)

    return result


def scan_directory(model: lgb.Booster, dir_path: Path, extensions: list = None) -> list:
    """Scan all files in a directory."""
    if extensions is None:
        extensions = [".exe", ".dll"]

    results = []
    files = [f for f in dir_path.iterdir() if f.is_file() and f.suffix.lower() in extensions]

    if not files:
        console.print(f"[yellow]No PE files found in {dir_path}[/yellow]")
        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {len(files)} files...", total=len(files))

        for file_path in files:
            progress.update(task, description=f"Scanning [cyan]{file_path.name}[/cyan]...")
            result = scan_file(model, file_path)
            results.append(result)
            progress.advance(task)

    return results


def print_results_table(results: list) -> None:
    """Print results in a rich table."""
    table = Table(title="Scan Results", box=box.ROUNDED)

    table.add_column("File", style="cyan", no_wrap=True)
    table.add_column("Prediction", justify="center")
    table.add_column("Probability", justify="right")
    table.add_column("Status", justify="center")

    for r in results:
        if r["error"]:
            table.add_row(
                r["name"],
                "-",
                "-",
                f"[red]Error: {r['error'][:30]}...[/red]" if len(r["error"]) > 30 else f"[red]{r['error']}[/red]"
            )
        else:
            prob = r["malware_probability"]
            pred = r["prediction"]

            if pred == "MALICIOUS":
                pred_style = "[bold red]MALICIOUS[/bold red]"
                prob_style = f"[red]{prob:.4f}[/red]"
            else:
                pred_style = "[bold green]BENIGN[/bold green]"
                prob_style = f"[green]{prob:.4f}[/green]"

            table.add_row(r["name"], pred_style, prob_style, "[green]OK[/green]")

    console.print(table)


def print_summary(results: list) -> None:
    """Print a summary table."""
    total = len(results)
    errors = sum(1 for r in results if r["error"])
    scanned = total - errors
    malicious = sum(1 for r in results if r["prediction"] == "MALICIOUS")
    benign = sum(1 for r in results if r["prediction"] == "BENIGN")

    table = Table(title="Summary", box=box.ROUNDED)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Total files", str(total))
    table.add_row("Scanned", f"[cyan]{scanned}[/cyan]")
    table.add_row("Errors", f"[red]{errors}[/red]" if errors > 0 else "0")
    table.add_row("Benign", f"[green]{benign}[/green]")
    table.add_row("Malicious", f"[bold red]{malicious}[/bold red]" if malicious > 0 else "0")

    console.print(table)


def print_single_result(result: dict) -> None:
    """Print result for a single file scan."""
    table = Table(title=f"Scan Result: {result['name']}", box=box.ROUNDED)

    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("File", f"[cyan]{result['path']}[/cyan]")

    if result["error"]:
        table.add_row("Status", f"[red]Error: {result['error']}[/red]")
    else:
        prob = result["malware_probability"]
        pred = result["prediction"]

        if pred == "MALICIOUS":
            table.add_row("Prediction", "[bold red]MALICIOUS[/bold red]")
            table.add_row("Probability", f"[red]{prob:.4f}[/red]")
        else:
            table.add_row("Prediction", "[bold green]BENIGN[/bold green]")
            table.add_row("Probability", f"[green]{prob:.4f}[/green]")

        table.add_row("Status", "[green]OK[/green]")

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Scan PE files for malware using EMBER2024 models"
    )
    parser.add_argument(
        "target",
        type=str,
        help="File or directory to scan"
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default=str(MODELS_DIR),
        help=f"Directory containing models (default: {MODELS_DIR})"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=DEFAULT_MODEL,
        help=f"Model file to use (default: {DEFAULT_MODEL})"
    )

    args = parser.parse_args()
    target = Path(args.target)
    models_dir = Path(args.models_dir)

    if not target.exists():
        console.print(f"[red]Error: Target not found: {target}[/red]")
        sys.exit(1)

    # Load model
    console.print(f"Loading model: [cyan]{args.model}[/cyan]")
    try:
        model = load_model(models_dir, args.model)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[yellow]Hint: Download models first with thrember.download_models()[/yellow]")
        sys.exit(1)

    console.print()

    # Scan target
    if target.is_file():
        result = scan_file(model, target)
        print_single_result(result)

    elif target.is_dir():
        results = scan_directory(model, target)
        if results:
            print_results_table(results)
            console.print()
            print_summary(results)

    else:
        console.print(f"[red]Error: Invalid target: {target}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
