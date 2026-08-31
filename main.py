#!/usr/bin/env python3
"""
NetCheck-OSINT: High-performance asynchronous digital identity and endpoint auditing utility.
"""

import sys
import os
import json
import time
import asyncio
import argparse
import aiohttp
import pathlib
from typing import List, Dict, Any, Optional
from colorama import Fore, Style, init

# Initialize colorama for cross-platform auto-resetting terminal colors
init(autoreset=True)

DEFAULT_ENDPOINTS: List[Dict[str, Any]] = [
    {"name": "GitHub", "url": "https://github.com/{}", "expected_value": 200},
    {"name": "DockerHub", "url": "https://hub.docker.com/v2/users/{}/", "expected_value": 200},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "expected_value": 200},
    {"name": "PyPI (Python Packages)", "url": "https://pypi.org/user/{}/", "expected_value": 200},
    {"name": "NPM Registry", "url": "https://www.npmjs.com/~{}", "expected_value": 200},
    {"name": "Dev.to", "url": "https://dev.to/{}", "expected_value": 200},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "expected_value": 200},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/", "expected_value": 200},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "expected_value": 200},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "expected_value": 200},
    {"name": "BuyMeACoffee", "url": "https://www.buymeacoffee.com/{}", "expected_value": 200},
    {"name": "Bitbucket API", "url": "https://api.bitbucket.org/2.0/users/{}", "expected_value": 200}
]


def load_endpoints(target: str, config_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Loads target endpoints from a custom config file, local config/endpoints.json,
    or falls back to the embedded default registry.
    """
    raw_endpoints: List[Dict[str, Any]] = []

    # 1. Check custom path if provided
    if config_path:
        custom_p = pathlib.Path(config_path)
        if custom_p.exists():
            try:
                with open(custom_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    raw_endpoints = data.get("endpoints", [])
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading custom config '{config_path}': {e}{Style.RESET_ALL}")
                return []
        else:
            print(f"{Fore.RED}[!] Specified config file not found: '{config_path}'{Style.RESET_ALL}")
            return []

    # 2. Check local working directory config/endpoints.json
    if not raw_endpoints:
        local_p = pathlib.Path.cwd() / "config" / "endpoints.json"
        if local_p.exists():
            try:
                with open(local_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    raw_endpoints = data.get("endpoints", [])
            except Exception:
                raw_endpoints = []

    # 3. Fallback to embedded registry
    if not raw_endpoints:
        raw_endpoints = DEFAULT_ENDPOINTS

    # Format URLs with the target username
    endpoints: List[Dict[str, Any]] = []
    for ep in raw_endpoints:
        url_template = ep.get("url", "")
        formatted_url = url_template.format(target) if "{}" in url_template else url_template
        endpoints.append({
            "name": ep.get("name", "Unknown Service"),
            "url": formatted_url,
            "expected_value": ep.get("expected_value", 200)
        })

    return endpoints


async def check_endpoint(session: aiohttp.ClientSession, endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Asynchronously queries an endpoint and records status telemetry."""
    name: str = endpoint["name"]
    url: str = endpoint["url"]
    expected: int = endpoint["expected_value"]

    record: Dict[str, Any] = {
        "service_name": name,
        "target_url": url,
        "status_code": None,
        "state": "ERROR",
        "match_status": False,
        "latency_ms": 0.0
    }

    start_time = time.perf_counter()
    timeout = aiohttp.ClientTimeout(total=5.0)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as response:
            latency = (time.perf_counter() - start_time) * 1000
            status = response.status
            record["status_code"] = status
            record["latency_ms"] = round(latency, 2)

            if status == expected:
                record["state"] = "FOUND"
                record["match_status"] = True
                print(f" {Fore.GREEN}[+] FOUND     {Style.RESET_ALL} {Fore.WHITE}{name:<22}{Style.RESET_ALL} -> {Fore.CYAN}{url}{Style.RESET_ALL}")
            elif status == 404:
                record["state"] = "NOT_FOUND"
                print(f" {Fore.BLACK}{Style.BRIGHT}[-] NOT FOUND {Style.RESET_ALL} {Fore.WHITE}{name:<22}{Style.RESET_ALL} {Fore.BLACK}(404 Not Found){Style.RESET_ALL}")
            elif status in (403, 429):
                record["state"] = "BLOCKED"
                reason = "Rate Limited / WAF" if status == 429 else "Access Denied / WAF"
                print(f" {Fore.YELLOW}[!] BLOCKED   {Style.RESET_ALL} {Fore.WHITE}{name:<22}{Style.RESET_ALL} {Fore.YELLOW}(HTTP {status} - {reason}){Style.RESET_ALL}")
            else:
                record["state"] = "UNEXPECTED"
                print(f" {Fore.RED}[!] UNEXPECTED{Style.RESET_ALL} {Fore.WHITE}{name:<22}{Style.RESET_ALL} {Fore.RED}(HTTP {status}){Style.RESET_ALL}")

    except asyncio.TimeoutError:
        record["state"] = "TIMEOUT"
        print(f" {Fore.RED}[!] TIMEOUT   {Style.RESET_ALL} {Fore.WHITE}{name:<22}{Style.RESET_ALL} {Fore.RED}(Timeout > 5.0s){Style.RESET_ALL}")
    except aiohttp.ClientError as e:
        record["state"] = "CONNECTION_ERROR"
        print(f" {Fore.RED}[!] ERROR     {Style.RESET_ALL} {Fore.WHITE}{name:<22}{Style.RESET_ALL} {Fore.RED}({e.__class__.__name__}){Style.RESET_ALL}")

    return record


def save_report(filepath: str, target: str, records: List[Dict[str, Any]], duration: float) -> None:
    """Exports structured telemetry findings to JSON on disk."""
    try:
        found_count = sum(1 for r in records if r["state"] == "FOUND")
        not_found_count = sum(1 for r in records if r["state"] == "NOT_FOUND")
        blocked_count = sum(1 for r in records if r["state"] in ("BLOCKED", "TIMEOUT", "CONNECTION_ERROR", "UNEXPECTED"))

        report = {
            "target": target,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_seconds": round(duration, 3),
            "summary": {
                "total_audited": len(records),
                "found": found_count,
                "not_found": not_found_count,
                "blocked_or_error": blocked_count
            },
            "results": records
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(f"\n{Fore.GREEN}[✓] Telemetry report exported to: {Fore.CYAN}{filepath}{Style.RESET_ALL}")
    except IOError as e:
        print(f"\n{Fore.RED}[!] Error writing telemetry report to '{filepath}': {e}{Style.RESET_ALL}")


async def run_audit(target: str, output_path: Optional[str], config_path: Optional[str]) -> None:
    """Coordinates concurrent auditing over the event loop."""
    endpoints = load_endpoints(target=target, config_path=config_path)
    if not endpoints:
        print(f"{Fore.RED}[!] No valid endpoints configured. Exiting...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    print(f" {Fore.GREEN}{Style.BRIGHT}NetCheck-OSINT{Style.RESET_ALL} - High-Performance Identity Auditor")
    print(f" Target Handle  : {Fore.YELLOW}{target}{Style.RESET_ALL}")
    print(f" Total Services : {Fore.WHITE}{len(endpoints)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

    start_time = time.perf_counter()

    async with aiohttp.ClientSession() as session:
        tasks = [check_endpoint(session, ep) for ep in endpoints]
        records: List[Dict[str, Any]] = await asyncio.gather(*tasks)

    elapsed = time.perf_counter() - start_time
    found = sum(1 for r in records if r["state"] == "FOUND")
    not_found = sum(1 for r in records if r["state"] == "NOT_FOUND")
    blocked = len(records) - found - not_found

    print(f"\n{Fore.CYAN}{'-'*65}{Style.RESET_ALL}")
    print(f" {Fore.GREEN}Found:{Style.RESET_ALL} {found:<4} | {Fore.WHITE}Not Found:{Style.RESET_ALL} {not_found:<4} | {Fore.YELLOW}Blocked/Errors:{Style.RESET_ALL} {blocked:<4} | {Fore.WHITE}Duration:{Style.RESET_ALL} {elapsed:.2f}s")
    print(f"{Fore.CYAN}{'-'*65}{Style.RESET_ALL}")

    if output_path:
        save_report(output_path, target, records, elapsed)


def cli() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description=f"{Fore.CYAN}NetCheck-OSINT: Asynchronous Digital Identity & Endpoint Auditor{Style.RESET_ALL}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netcheck johndoe
  netcheck -u torvalds -o results.json
  netcheck -t octocat -c custom_endpoints.json
        """
    )
    parser.add_argument(
        "username",
        nargs="?",
        help="Target username or identifier to audit across online services."
    )
    parser.add_argument(
        "-u", "--username",
        dest="username_flag",
        help="Target username or identifier."
    )
    parser.add_argument(
        "-t", "--target",
        dest="target_flag",
        help="Alias for target username/identifier."
    )
    parser.add_argument(
        "-c", "--config",
        dest="config_path",
        help="Custom path to endpoints.json configuration."
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        help="File path to export JSON telemetry report."
    )

    args = parser.parse_args()
    target = args.username or args.username_flag or args.target_flag

    if not target or not target.strip():
        print(f"{Fore.RED}[!] Error: Target username is required.{Style.RESET_ALL}")
        print("Please specify a username as a positional argument or use -u/--username, -t/--target.\n")
        parser.print_help()
        sys.exit(1)

    try:
        asyncio.run(run_audit(target.strip(), args.output, args.config_path))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Audit interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    cli()