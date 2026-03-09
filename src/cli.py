"""
CLI interaction module for AppSec-Sentinel.

Handles all user-facing prompts: repository selection, tool selection,
scan level configuration, and interactive menus.
"""

import os
from pathlib import Path
from logging_config import get_logger

logger = get_logger(__name__)


def show_interactive_menu() -> str:
    """Show interactive menu and return user choice."""
    print("🎯 Choose an option:")
    print("   [1] Security scan with auto-fixes + SBOM")
    print("   [q] Quit")

    while True:
        choice = input("\nEnter your choice [1, q]: ").strip().lower()
        if choice in ['1', 'q']:
            return choice
        print("Invalid choice. Please enter 1 or q")


def select_scan_level() -> str:
    """Let user choose severity level for scanning."""
    print("\n🔍 Select severity level:")
    print("   [1] Critical & High only (Recommended - fewer false positives)")
    print("   [2] All severity levels (More findings, may include noise)")

    while True:
        choice = input("\nChoose severity level [1-2]: ").strip()
        if choice == '1':
            return 'critical-high'
        elif choice == '2':
            return 'all'
        else:
            print("Invalid choice. Please enter 1 or 2")


def select_tools() -> set:
    """Let user choose which tools to run."""
    print("\n🔧 Select tools to run:")
    print("   [1] All (comprehensive scan)")
    print("   [2] Security only (semgrep + gitleaks + trivy)")
    print("   [3] SAST only (semgrep)")
    print("   [4] Secrets only (gitleaks)")
    print("   [5] Dependencies only (trivy)")
    print("   [6] Custom selection...")

    while True:
        choice = input("\nChoose tool selection [1-6]: ").strip()

        if choice == '1':
            return {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}
        elif choice == '2':
            return {'semgrep', 'trivy', 'gitleaks', 'sbom'}
        elif choice == '3':
            return {'semgrep', 'code_quality', 'sbom'}
        elif choice == '4':
            return {'gitleaks', 'sbom'}
        elif choice == '5':
            return {'trivy', 'sbom'}
        elif choice == '6':
            tools = _custom_tool_selection()
            if tools:
                print(f"\n✅ Selected tools: {', '.join(sorted(tools))}")
                return tools
            print("❌ No tools selected. Please select at least one tool.")
        else:
            print("Invalid choice. Please enter 1-6")


def _custom_tool_selection() -> set:
    """Interactive per-tool selection."""
    tools = set()
    prompts = [
        ("Run Semgrep (SAST)?", 'semgrep'),
        ("Run Trivy (Dependencies/SCA)?", 'trivy'),
        ("Run Gitleaks (Secrets)?", 'gitleaks'),
        ("Run Code Quality linters?", 'code_quality'),
        ("Generate SBOM?", 'sbom'),
    ]
    for prompt, tool_name in prompts:
        if input(f"   {prompt} [Y/n]: ").strip().lower() != 'n':
            tools.add(tool_name)
    return tools


def select_repository() -> str:
    """Interactive repository selection for security analysis."""
    print("\n📁 Repository Selection:")
    print("   [1] Current directory")
    print("   [2] Browse for directory")
    print("   [3] Enter path manually")

    while True:
        choice = input("\nChoose repository option [1-3]: ").strip()

        if choice == '1':
            repo_path = os.getcwd()
            print(f"Selected: {repo_path}")
            return repo_path

        elif choice == '2':
            result = _browse_repositories()
            if result:
                return result

        elif choice == '3':
            repo_path = input("\nEnter repository path: ").strip()
            if repo_path and Path(repo_path).exists():
                if Path(repo_path).is_dir():
                    print(f"Selected: {repo_path}")
                    return repo_path
                else:
                    print("❌ Path is not a directory")
            else:
                print("❌ Path does not exist")
        else:
            print("Invalid choice. Please enter 1, 2, or 3")


def _browse_repositories() -> str | None:
    """Scan common locations for git repositories and let user pick one."""
    print("\nScanning for repositories...")
    repos = []
    seen = set()

    user_home = os.path.expanduser("~")
    search_paths = [
        os.getcwd(),
        os.path.join(user_home, "repos"),
        os.path.join(user_home, "projects"),
        os.path.join(user_home, "code"),
        os.path.join(user_home, "workspace"),
        user_home,
    ]

    if os.getenv('REPO_SEARCH_PATHS'):
        search_paths.extend(os.getenv('REPO_SEARCH_PATHS').split(':'))

    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
        try:
            if os.path.exists(os.path.join(search_path, '.git')):
                real_path = os.path.realpath(search_path)
                if real_path not in seen:
                    seen.add(real_path)
                    repos.append((Path(search_path).name, search_path))

            for item in os.listdir(search_path):
                item_path = os.path.join(search_path, item)
                if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, '.git')):
                    real_path = os.path.realpath(item_path)
                    if real_path not in seen:
                        seen.add(real_path)
                        repos.append((item, item_path))
        except (PermissionError, OSError):
            continue

    repos.sort(key=lambda x: x[0].lower())

    if not repos:
        print("No git repositories found in common locations")
        return None

    for idx, (name, path) in enumerate(repos, 1):
        try:
            rel_path = os.path.relpath(path)
            display_path = rel_path if len(rel_path) < len(path) else path
        except ValueError:
            display_path = path
        print(f"   [{idx}] {name} ({display_path})")

    while True:
        try:
            repo_choice = input(f"\nChoose repository [1-{len(repos)}] or 'q' to go back: ").strip()
            if repo_choice.lower() == 'q':
                return None
            idx = int(repo_choice) - 1
            if 0 <= idx < len(repos):
                repo_path = repos[idx][1]
                print(f"Selected: {repo_path}")
                return repo_path
            else:
                print(f"Invalid choice. Please enter 1-{len(repos)}")
        except ValueError:
            print("Invalid input. Please enter a number.")
