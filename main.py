#!/usr/bin/env python3
"""
NetCheck-CLI (netcheck-osint): A high-performance, asynchronous digital identity validation 
and network endpoint auditing utility.
"""

import asyncio
import json
import argparse
import sys
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import aiohttp
from colorama import Fore, Style, init

# Ensure stdout uses UTF-8 if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Initialize colorama for cross-platform auto-resetting terminal colors
init(autoreset=True)

# Standard browser emulation headers to prevent false-positive WAF/bot blocking
DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def get_default_config_path() -> Path:
    """
    Dynamically resolves the absolute path to 'config/endpoints.json' relative to 
    the package location, ensuring reliable operation when installed globally.
    """
    package_dir: Path = Path(__file__).resolve().parent
    config_file: Path = package_dir / "config" / "endpoints.json"
    if config_file.exists():
        return config_file
    
    # Fallback to current working directory if available
    cwd_config: Path = Path.cwd() / "config" / "endpoints.json"
    if cwd_config.exists():
        return cwd_config

    return config_file


def load_endpoints(filepath: Optional[str] = None, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Reads the configuration file, returns the list of target endpoints,
    and dynamically formats placeholder URLs if a target value is provided.
    """
    if filepath:
        resolved_path = Path(filepath)
    else:
        resolved_path = get_default_config_path()

    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
            endpoints: List[Dict[str, Any]] = data.get("endpoints", [])

            if target:
                for ep in endpoints:
                    url: str = ep.get("url", "")
                    if "{}" in url:
                        ep["url"] = url.format(target)
            return endpoints
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Config Error: File not found at '{resolved_path}'.{Style.RESET_ALL}")
        return []
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[!] Config Error: Corrupt JSON in '{resolved_path}': {e}{Style.RESET_ALL}")
        return []


async def check_endpoint(session: aiohttp.ClientSession, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes an explicit status check on a target endpoint using an active ClientSession.
    Renders Shodan-style terminal output badges and returns structured telemetry.
    """
    name: str = endpoint_data.get("name", "Unknown Service")
    url: str = endpoint_data.get("url", "")
    expected: int = endpoint_data.get("expected_value", 200)

    record: Dict[str, Any] = {
        "service_name": name,
        "target_url": url,
        "expected_value": expected,
        "status_code": None,
        "category": "UNKNOWN",
        "match_status": False,
    }

    if not url:
        print(f"{Fore.RED}[!] ERROR{Style.RESET_ALL}     {name:<16} | Missing target URL")
        record["status_code"] = "MISSING_URL"
        record["category"] = "ERROR"
        return record

    timeout = aiohttp.ClientTimeout(total=5.0)

    try:
        async with session.get(url, timeout=timeout, headers=DEFAULT_HEADERS, allow_redirects=True) as response:
            status: int = response.status
            record["status_code"] = status

            if status == 200:
                record["match_status"] = True
                record["category"] = "FOUND"
                # Clickable Cyan URL
                print(
                    f"{Fore.GREEN}{Style.BRIGHT}[+] FOUND{Style.RESET_ALL}     "
                    f"{name:<16} -> {Fore.CYAN}{url}{Style.RESET_ALL}"
                )
            elif status == 404:
                record["category"] = "NOT_FOUND"
                # Dimmed text for 404 responses
                print(f"{Fore.LIGHTBLACK_EX}[-] NOT FOUND {name:<16} -> {url}{Style.RESET_ALL}")
            elif status in (403, 429):
                record["category"] = "BLOCKED"
                print(
                    f"{Fore.YELLOW}{Style.BRIGHT}[!] BLOCKED{Style.RESET_ALL}   "
                    f"{name:<16} -> {url} (HTTP {status}){Style.RESET_ALL}"
                )
            else:
                matched: bool = (status == expected)
                record["match_status"] = matched
                record["category"] = "OTHER"
                if matched:
                    print(
                        f"{Fore.GREEN}{Style.BRIGHT}[+] FOUND{Style.RESET_ALL}     "
                        f"{name:<16} -> {Fore.CYAN}{url}{Style.RESET_ALL} (HTTP {status})"
                    )
                else:
                    print(
                        f"{Fore.LIGHTBLACK_EX}[-] STATUS    {name:<16} -> {url} (HTTP {status}){Style.RESET_ALL}"
                    )
    except asyncio.TimeoutError:
        record["status_code"] = "TIMEOUT"
        record["category"] = "TIMEOUT"
        print(
            f"{Fore.RED}{Style.BRIGHT}[!] TIMEOUT{Style.RESET_ALL}   "
            f"{name:<16} -> {url} (Exceeded 5.0s){Style.RESET_ALL}"
        )
    except aiohttp.ClientError as e:
        record["status_code"] = "CLIENT_ERROR"
        record["category"] = "ERROR"
        print(
            f"{Fore.RED}[!] ERROR{Style.RESET_ALL}     "
            f"{name:<16} -> {url} (Connection Error: {e}){Style.RESET_ALL}"
        )

    return record


def save_report(filepath: str, records: List[Dict[str, Any]], target: str, duration_sec: float) -> None:
    """
    Writes the audit telemetry records and summary metrics to a structured JSON file on disk.
    """
    found_count = sum(1 for r in records if r.get("category") == "FOUND")
    not_found_count = sum(1 for r in records if r.get("category") == "NOT_FOUND")
    blocked_count = sum(1 for r in records if r.get("category") == "BLOCKED")
    timeout_count = sum(1 for r in records if r.get("category") == "TIMEOUT")
    error_count = sum(1 for r in records if r.get("category") == "ERROR")

    report: Dict[str, Any] = {
        "metadata": {
            "target": target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "duration_seconds": round(duration_sec, 2),
            "total_endpoints": len(records),
        },
        "summary": {
            "found": found_count,
            "not_found": not_found_count,
            "blocked": blocked_count,
            "timeout": timeout_count,
            "errors": error_count,
        },
        "results": records,
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(f"\n{Fore.GREEN}[+] Telemetry report successfully exported to '{filepath}'.{Style.RESET_ALL}")
    except IOError as e:
        print(f"\n{Fore.RED}[!] Failed to write telemetry report to '{filepath}': {e}{Style.RESET_ALL}")


async def run_audit(target: str, output_path: str, config_path: Optional[str] = None) -> None:
    """
    Asynchronously coordinates the endpoint queries, collects metrics, and prints the summary footer.
    """
    endpoints: List[Dict[str, Any]] = load_endpoints(filepath=config_path, target=target)
    if not endpoints:
        print(f"{Fore.YELLOW}[!] No valid endpoints configured. Exiting...{Style.RESET_ALL}")
        return

    banner = (
        f"{Fore.CYAN}{Style.BRIGHT}"
        f"+-------------------------------------------------------------+\n"
        f"|           NetCheck-OSINT :: Identity & Network Auditor      |\n"
        f"+-------------------------------------------------------------+{Style.RESET_ALL}\n"
        f"[*] Target Identity : {Fore.YELLOW}{target}{Style.RESET_ALL}\n"
        f"[*] Endpoints Total : {len(endpoints)}\n"
        f"[*] Scan Strategy   : Async Concurrent Event Loop (Timeout: 5.0s)\n"
    )
    print(banner)

    start_time = time.time()

    async with aiohttp.ClientSession() as session:
        tasks = [check_endpoint(session, endpoint) for endpoint in endpoints]
        records: List[Dict[str, Any]] = await asyncio.gather(*tasks)

    elapsed = time.time() - start_time

    # Summary counts
    found_count = sum(1 for r in records if r.get("category") == "FOUND")
    not_found_count = sum(1 for r in records if r.get("category") == "NOT_FOUND")
    blocked_count = sum(1 for r in records if r.get("category") == "BLOCKED")
    timeout_count = sum(1 for r in records if r.get("category") == "TIMEOUT")
    error_count = sum(1 for r in records if r.get("category") == "ERROR")

    # Shodan-Style Execution Summary Footer
    print(f"\n{Fore.CYAN}{'=' * 61}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}SCAN SUMMARY:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[+] Found     :{Style.RESET_ALL} {found_count}")
    print(f"  {Fore.LIGHTBLACK_EX}[-] Not Found :{Style.RESET_ALL} {not_found_count}")
    print(f"  {Fore.YELLOW}[!] Blocked   :{Style.RESET_ALL} {blocked_count}")
    print(f"  {Fore.RED}[!] Timed Out :{Style.RESET_ALL} {timeout_count}")
    if error_count:
        print(f"  {Fore.RED}[!] Errors    :{Style.RESET_ALL} {error_count}")
    print(f"  [*] Duration  : {elapsed:.2f}s")
    print(f"{Fore.CYAN}{'=' * 61}{Style.RESET_ALL}")

    save_report(output_path, records, target=target, duration_sec=elapsed)


def cli() -> None:
    """CLI entrypoint for console_scripts."""
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description="NetCheck-OSINT: High-performance asynchronous digital identity and endpoint auditing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  netcheck dhruvrathod68\n"
            "  netcheck -u john_doe -o report.json\n"
            "  netcheck --target alice\n"
        ),
    )
    parser.add_argument(
        "username",
        nargs="?",
        default=None,
        help="Target username or identifier to audit across online services.",
    )
    parser.add_argument(
        "-u", "--username",
        dest="username_flag",
        type=str,
        help="Target username or identifier.",
    )
    parser.add_argument(
        "-t", "--target",
        dest="target_flag",
        type=str,
        help="Alias for target username/identifier.",
    )
    parser.add_argument(
        "-c", "--config",
        dest="config_path",
        type=str,
        default=None,
        help="Custom path to endpoints.json configuration.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="results.json",
        help="File path to export JSON telemetry report (default: results.json).",
    )

    args = parser.parse_args()

    # Extract target username from positional argument or flags
    target: Optional[str] = args.username or args.username_flag or args.target_flag
    if target:
        target = target.strip()

    # Strict input validation: exit code 1 if empty or missing
    if not target:
        print(
            f"{Fore.RED}[!] Error: Target username is required.\n"
            f"Please specify a username as a positional argument or use -u/--username, -t/--target.{Style.RESET_ALL}\n"
        )
        parser.print_help()
        sys.exit(1)

    try:
        asyncio.run(run_audit(target=target, output_path=args.output, config_path=args.config_path))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Audit interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    cli()
