#!/usr/bin/env python3
"""
NetCheck-CLI: A high-performance, asynchronous digital identity validation 
and network endpoint auditing utility.
"""

import asyncio
import json
import argparse
import aiohttp
from typing import List, Dict, Any
from colorama import Fore, Style, init

# Initialize colorama for cross-platform auto-resetting terminal colors
init(autoreset=True)

def load_endpoints(filepath: str = "config/endpoints.json", target: str = None) -> List[Dict[str, Any]]:
    """
    Reads the configuration file, returns the list of target endpoints,
    and dynamically formats placeholder URLs if a target value is provided.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
            endpoints: List[Dict[str, Any]] = data.get("endpoints", [])
            
            if target:
                for ep in endpoints:
                    url: str = ep.get("url", "")
                    if "{}" in url:
                        ep["url"] = url.format(target)
            return endpoints
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"{Fore.RED}[CONFIG ERROR] Failed to load configuration: {e}{Style.RESET_ALL}")
        return []

async def check_endpoint(session: aiohttp.ClientSession, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes an explicit status check on a target endpoint using an active ClientSession.
    Returns a structured dictionary matching the telemetry logging schema.
    """
    name: str = endpoint_data.get("name", "Unknown Service")
    url: str = endpoint_data.get("url", "")
    expected: int = endpoint_data.get("expected_value", 200)

    record: Dict[str, Any] = {
        "service_name": name,
        "target_url": url,
        "expected_value": expected,
        "status_code": None,
        "match_status": False
    }

    if not url:
        print(f"{Fore.RED}[ERROR] Service '{name}' is missing a target URL.{Style.RESET_ALL}")
        record["status_code"] = "MISSING_URL"
        return record

    timeout = aiohttp.ClientTimeout(total=5.0)

    try:
        async with session.get(url, timeout=timeout) as response:
            status: int = response.status
            matched: bool = (status == expected)
            record["status_code"] = status
            record["match_status"] = matched
            if matched:
                print(f"{Fore.GREEN}[PASS] {name} ({url}) | Expected: {expected} | Got: {status}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[FAIL] {name} ({url}) | Expected: {expected} | Got: {status}{Style.RESET_ALL}")
    except asyncio.TimeoutError:
        print(f"{Fore.RED}[TIMEOUT] {name} ({url}) | Expected: {expected} | Timeout of 5.0s exceeded{Style.RESET_ALL}")
        record["status_code"] = "TIMEOUT"
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}[ERROR] {name} ({url}) | Expected: {expected} | Connection/DNS Error: {e}{Style.RESET_ALL}")
        record["status_code"] = "CLIENT_ERROR"
        
    return record

def save_report(filepath: str, records: List[Dict[str, Any]]) -> None:
    """
    Writes the audit telemetry records to a structured JSON file on disk.
    """
    try:
        report: Dict[str, Any] = {
            "total_checks": len(records),
            "successful_checks": sum(1 for r in records if r["match_status"]),
            "failed_checks": sum(1 for r in records if not r["match_status"]),
            "results": records
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(f"\n{Fore.GREEN}[REPORT] Uptime report successfully written to '{filepath}'.{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}[REPORT ERROR] Failed to write report to '{filepath}': {e}{Style.RESET_ALL}")

async def main() -> None:
    """
    Main asynchronous coordinator function. Handles argument parsing, session pooling,
    and workflow scheduling.
    """
    parser = argparse.ArgumentParser(description="NetCheck-CLI: Concurrent endpoint status checks and monitoring.")
    parser.add_argument("--target", type=str, help="The string identifier to dynamically inject into endpoints with '{}' placeholders.")
    parser.add_argument("--output", type=str, default="results.json", help="File path to export JSON results (default: results.json).")
    args = parser.parse_args()

    endpoints: List[Dict[str, Any]] = load_endpoints(target=args.target)
    if not endpoints:
        print(f"{Fore.YELLOW}[WARN] No endpoints configured. Exiting...{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}Starting NetCheck-CLI on {len(endpoints)} endpoints...{Style.RESET_ALL}")
    if args.target:
        print(f"{Fore.CYAN}Target identifier: '{args.target}'{Style.RESET_ALL}")
    print()

    async with aiohttp.ClientSession() as session:
        tasks = [check_endpoint(session, endpoint) for endpoint in endpoints]
        records: List[Dict[str, Any]] = await asyncio.gather(*tasks)

    save_report(args.output, records)

if __name__ == "__main__":
    asyncio.run(main())
