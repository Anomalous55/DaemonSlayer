import argparse
import subprocess
import requests
import time
import sys
import json
import os
import concurrent.futures

# Rich UI Imports
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

# ==========================================
# CONFIGURATION
# ==========================================
API_KEY = "YOUR_API_KEY_HERE"
CACHE_FILE = "pkg_scan_cache.json"

def get_installed_packages(console):
    """Detects the Linux package manager and returns a list of installed packages."""
    packages = []

    try:
        result = subprocess.run(['dpkg-query', '-W', "-f=${Package} ${Version}\n"],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n'):
            if line:
                name, version = line.split(' ', 1)
                packages.append((name, version, "deb"))
        return packages
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    try:
        result = subprocess.run(['rpm', '-qa', '--qf', '%{NAME} %{VERSION}\n'],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n'):
            if line:
                name, version = line.split(' ', 1)
                packages.append((name, version, "rpm"))
        return packages
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    try:
        result = subprocess.run(['pacman', '-Q'],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n'):
            if line:
                name, version = line.split(' ', 1)
                packages.append((name, version, "pacman"))
        return packages
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    console.print("[bold red]Error:[/] Could not detect 'dpkg', 'rpm', or 'pacman'. Are you on a supported Linux distribution?")
    sys.exit(1)

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=4)

def manage_cache(console):
    """Interactive TUI for managing the local scan cache."""
    cache = load_cache()

    while True:
        console.clear()
        console.print(Panel.fit("[bold blue]DaemonSlayer Cache Management", border_style="blue"))

        total_entries = len(cache)
        safe_entries = sum(1 for v in cache.values() if not v.get("is_malicious"))
        malicious_entries = total_entries - safe_entries

        console.print(f"[bold]Total Cached Packages:[/] {total_entries}")
        console.print(f"[bold green]Safe:[/] {safe_entries}")
        console.print(f"[bold red]Flagged:[/] {malicious_entries}\n")

        console.print("1. Refresh Cache Stats")
        console.print("2. Clear Entire Cache [dim](Forces full API rescan)[/]")
        console.print("3. Clear Only 'Safe' Packages [dim](Keeps known threats cached)[/]")
        console.print("4. Exit")

        choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4"], default="4")

        if choice == "1":
            continue
        elif choice == "2":
            if Confirm.ask("[bold red]Are you sure you want to clear the entire cache?[/]"):
                save_cache({})
                cache = {}
                console.print("[green]Cache cleared successfully.[/]")
                time.sleep(1.5)
        elif choice == "3":
            cache = {k: v for k, v in cache.items() if v.get("is_malicious")}
            save_cache(cache)
            console.print("[green]Safe packages cleared from cache.[/]")
            time.sleep(1.5)
        elif choice == "4":
            break

def scan_packages_fast(packages, console):
    """Scans packages concurrently with a live animated progress bar."""
    cache = load_cache()
    flagged_packages = []
    new_queries = 0

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {API_KEY}"})

    def check_pkg(pkg):
        name, version, ecosystem = pkg
        cache_key = f"{ecosystem}:{name}@{version}"

        if cache_key in cache:
            return pkg, False, cache[cache_key], None, None

        params = {
            "report_type": "package",
            "resource_identifier": name,
            "ecosystem": ecosystem
        }

        try:
            response = session.get(
                "https://api.opensourcemalware.com/functions/v1/check-malicious",
                params=params
            )

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and data.get("is_malicious"):
                    return pkg, True, {"is_malicious": True, "details": "Flagged as malicious by OSM"}, None, None
                elif isinstance(data, list) and len(data) > 0:
                    return pkg, True, {"is_malicious": True, "details": "Flagged as malicious by OSM"}, None, None
                else:
                    return pkg, True, {"is_malicious": False}, None, None

            elif response.status_code == 404:
                return pkg, True, {"is_malicious": False}, None, None

            elif response.status_code == 429:
                return pkg, True, None, "RATE_LIMIT", None

        except Exception as e:
            return pkg, True, None, None, e

        return pkg, True, None, None, None

    # Render the Live Progress Bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("[cyan]Scanning packages...", total=len(packages))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_pkg, pkg): pkg for pkg in packages}

            for future in concurrent.futures.as_completed(futures):
                pkg, was_api_call, cache_result, rate_limit, error = future.result()
                name, version, ecosystem = pkg
                cache_key = f"{ecosystem}:{name}@{version}"

                # Update the visual progress bar description
                progress.update(task_id, advance=1, description=f"[cyan]Scanning: [bold]{name}[/bold]...")

                if was_api_call:
                    new_queries += 1
                    time.sleep(0.02)

                if rate_limit:
                    console.print("\n[bold red][!] Rate limit exceeded. Stopping early.[/]")
                    break

                if error:
                    console.print(f"\n[bold yellow][!] Network error checking {name}: {error}[/]")
                    continue

                if cache_result:
                    cache[cache_key] = cache_result
                    if cache_result.get("is_malicious"):
                        flagged_packages.append((name, version, cache_result.get("details")))

                if new_queries > 0 and new_queries % 50 == 0:
                    save_cache(cache)

    save_cache(cache)
    console.print(f"\n[bold green][*] Scan complete.[/] {new_queries} new API requests made. {len(packages) - new_queries} loaded from cache.\n")
    return flagged_packages

if __name__ == "__main__":
    console = Console()

    # Define CLI Arguments
    parser = argparse.ArgumentParser(description="DaemonSlayer - Linux Package Malware Scanner")
    parser.add_argument("--scan", action="store_true", help="Run a full malware scan on all installed packages")
    parser.add_argument("--manage-cache", action="store_true", help="Open the interactive cache management menu")
    parser.add_argument("--export", type=str, metavar="FILE", help="Export threat results to a JSON file")

    args = parser.parse_args()

    # Show help if no arguments are provided
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(0)

    # Handle Cache Management
    if args.manage_cache:
        manage_cache(console)
        sys.exit(0)

    # Handle Scan Execution
    if args.scan or args.export:
        if API_KEY == "YOUR_API_KEY_HERE":
            console.print("[bold red]Error:[/] Please insert your OpenSourceMalware API key into the script.")
            sys.exit(1)

        console.print(Panel.fit("[bold blue]DaemonSlayer[/] - Initiating System Scan", border_style="blue"))
        pkgs = get_installed_packages(console)

        threats = scan_packages_fast(pkgs, console)

        # Render the final Table
        if threats:
            table = Table(title="Malicious Packages Detected", title_style="bold red")
            table.add_column("Package", style="cyan", no_wrap=True)
            table.add_column("Version", style="magenta")
            table.add_column("Details", style="red")

            for name, version, details in threats:
                table.add_row(name, version, details)

            console.print(table)
        else:
            console.print(Panel.fit("[bold green]✅ No known malicious packages found on your system.", border_style="green"))

        # Export logic
        if args.export and threats:
            export_data = [{"package": n, "version": v, "details": d} for n, v, d in threats]
            with open(args.export, "w") as f:
                json.dump(export_data, f, indent=4)
            console.print(f"\n[bold green]Results successfully exported to {args.export}[/]")
