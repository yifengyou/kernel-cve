import argparse
import os
import re
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


# --- Data Structure Definitions ---

@dataclass
class DyadPair:
    """Stores parsed dyad data pairs"""
    vuln_version: str
    vuln_hash: str
    fixed_version: str
    fixed_hash: str
    source_file: str
    cve_id: str = "Unknown_CVE"  # Added CVE ID field

    def __str__(self):
        return f"[{self.cve_id}] {self.vuln_version} -> {self.fixed_version}"


# --- Repository Operation Class ---

class KernelRepo:
    def __init__(self, path: str, name: str):
        self.path = os.path.abspath(path)
        self.name = name
        if not os.path.exists(self.path):
            print(f"Error: Path does not exist - {self.path}")

    def run_git(self, args: List[str]) -> Tuple[int, str, str]:
        """Executes git command and returns (return code, stdout, stderr)"""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return -1, "", str(e)

    def get_patch(self, commit_hash: str, output_file: str) -> bool:
        """
        Exports the patch file for the specified commit from this repo.
        """
        print(f"    [{self.name}] Generating patch: {commit_hash[:8]}...")

        # Command to generate patch to stdout and redirect to file
        cmd = f"git format-patch -1 {commit_hash} --stdout > {output_file}"

        try:
            # We execute in the repo path, but the output file path is absolute
            result = subprocess.run(
                cmd,
                cwd=self.path,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                print(f"  Gen patch failed!: {result.stderr.strip()}")
                return False
            if not os.path.exists(output_file):
                print("  Patch file not found after generation!")
                return False
            return True
        except Exception as e:
            print(f"   Generate patch exception: {e}")
            return False

    def apply_patch(self, patch_file: str) -> bool:
        """
        Applies the patch.
        """
        print(f"    [TargetRepo] Attempting to apply patch...")

        cmd = f"git am {patch_file} --3way"

        try:
            result = subprocess.run(
                cmd,
                cwd=self.path,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode != 0:
                print(
                    f"   Patch application conflict or failure: {result.stderr.strip()[:100]}")
                return False
            return True
        except Exception as e:
            print(f"   Apply patch exception: {e}")
            return False

    def revert_patch(self) -> bool:
        """Reverts the last operation"""
        print(f"   [TargetRepo] Reverting changes...")
        code, _, _ = self.run_git(["am", "--abort"])
        if code != 0:
            code, _, _ = self.run_git(["reset", "--hard", "HEAD"])

        if code == 0:
            print(f"   Revert successful")
            return True
        else:
            print(f"   Revert failed")
            return False


# --- Helper Functions ---

def extract_cve_id(file_path: str) -> str:
    """
    Extracts CVE ID from the filename or content.
    Looks for patterns like CVE-YYYY-NNNN.
    """
    filename = os.path.basename(file_path)

    # Try to find CVE pattern in filename first
    match = re.search(r'(CVE-\d{4}-\d+)', filename)
    if match:
        return match.group(1)

    # Fallback: Try to find in the first line of content if needed
    # (Optional, depending on your file format)
    try:
        with open(file_path, 'r') as f:
            content = f.read(1024)  # Read first 1KB
            match = re.search(r'(CVE-\d{4}-\d+)', content)
            if match:
                return match.group(1)
    except:
        pass

    return "Unknown_CVE"


def parse_dyad_file(file_path: str) -> List[DyadPair]:
    """Parses a single .dyad file"""
    pairs = []
    cve_id = extract_cve_id(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(':')
                if len(parts) == 4:
                    pairs.append(DyadPair(
                        vuln_version=parts[0],
                        vuln_hash=parts[1],
                        fixed_version=parts[2],
                        fixed_hash=parts[3],
                        source_file=file_path,
                        cve_id=cve_id
                    ))
    except Exception as e:
        print(f"Read file failed {file_path}: {e}")
    return pairs


# --- Core Logic ---

def process_dyad_files(root_dir: str, repo_a_path: str, repo_b_path: str,
                       output_dir: str):
    """Main processing flow"""

    repo_a = KernelRepo(repo_a_path, "TargetRepo(A)")
    repo_b = KernelRepo(repo_b_path, "MainlineRepo(B)")

    root_path = Path(root_dir)
    dyad_files = [str(p) for p in root_path.rglob("*.dyad")]

    if not dyad_files:
        print(f"No .dyad files found in {root_dir}")
        return

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    print(f"Found {len(dyad_files)} dyad files. Output dir: {output_dir}\n")

    original_cwd = os.getcwd()

    for file_path in dyad_files:
        print(f"--- Processing file: {file_path} ---")
        pairs = parse_dyad_file(file_path)

        for pair in pairs:
            print(f"\n> Processing: {pair}")

            # --- Create CVE specific output directory ---
            cve_output_path = os.path.join(output_dir, pair.cve_id)
            os.makedirs(cve_output_path, exist_ok=True)

            dyad_filename = os.path.basename(file_path)
            target_dyad_path = os.path.join(cve_output_path, dyad_filename)
            try:
                shutil.copy2(file_path, target_dyad_path)
                print(f"   Dyad file copied to: {target_dyad_path}")
            except Exception as e:
                print(f"   Failed to copy dyad file: {e}")

            # Define the specific patch file path for this CVE
            patch_filename = f"{pair.cve_id}_{pair.fixed_hash[:8]}.patch"
            patch_full_path = os.path.join(cve_output_path, patch_filename)

            # --- Step 1: Get fix patch from B (mainline) ---
            # We pass the full absolute path to get_patch
            if not repo_b.get_patch(pair.fixed_hash, patch_full_path):
                print("   Skipping: Unable to get patch")
                continue

            # --- Step 2: Attempt patch application on A ---
            # Note: We are NOT changing directory to /tmp anymore.
            # We use the absolute path for apply_patch as well.
            success = repo_a.apply_patch(patch_full_path)

            if success:
                print(
                    f"   Patch applied successfully! Saved to: {patch_full_path}")
                # Optional: Revert immediately if you only want to test applicability
                # repo_a.revert_patch()
            else:
                print("   Patch application failed, executing revert operation")
                repo_a.revert_patch()
                # We might still want to keep the patch file even if it failed to apply,
                # or delete it. Currently, we keep it.

    os.chdir(original_cwd)
    print(f"\nAll tasks completed.")


# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process CVE dyad files, generate patches, and organize them by CVE ID.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--dir', '-d',
        required=True,
        help='Path to the directory containing .dyad files'
    )
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Path to the target repository (Repo A)'
    )
    parser.add_argument(
        '--mainline', '-m',
        required=True,
        help='Path to the mainline repository (Repo B)'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Path to the output directory where CVE subdirectories and patches will be saved'
    )

    args = parser.parse_args()

    # Validate paths
    if not os.path.exists(args.dir):
        print(f"Error: Data directory does not exist: {args.dir}")
        exit(1)
    if not os.path.exists(args.target):
        print(f"Error: Target repository path does not exist: {args.target}")
        exit(1)
    if not os.path.exists(args.mainline):
        print(
            f"Error: Mainline repository path does not exist: {args.mainline}")
        exit(1)

    process_dyad_files(args.dir, args.target, args.mainline, args.output)
