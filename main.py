#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


def setup_logger(log_file="cve-kin.log"):
	logger = logging.getLogger("cve-kin")
	logger.setLevel(logging.DEBUG)

	if logger.hasHandlers():
		logger.handlers.clear()

	file_formatter = logging.Formatter(
		'%(asctime)s - %(name)s - %(levelname)s - %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S'
	)
	file_handler = logging.FileHandler(log_file, encoding='utf-8')
	file_handler.setLevel(logging.DEBUG)
	file_handler.setFormatter(file_formatter)
	logger.addHandler(file_handler)

	console_formatter = logging.Formatter('%(message)s')
	console_handler = logging.StreamHandler(sys.stdout)
	console_handler.setLevel(logging.INFO)
	console_handler.setFormatter(console_formatter)
	logger.addHandler(console_handler)

	return logger


logger = setup_logger()


@dataclass
class DyadPair:
	vuln_version: str
	vuln_hash: str
	fixed_version: str
	fixed_hash: str
	source_file: str
	cve_id: str = "Unknown_CVE"

	def __str__(self):
		return f"[{self.cve_id}] {self.vuln_version} -> {self.fixed_version}"


class KernelRepo:
	def __init__(self, path: str, name: str, branch: str = None):
		self.path = os.path.abspath(path)
		self.name = name
		if not os.path.exists(self.path):
			logger.error(f"Path does not exist - {self.path}")

		if branch:
			self._checkout_branch(branch)

	def _checkout_branch(self, branch: str):
		logger.debug(f"[{self.name}] Checking out branch: {branch}...")
		code, _, stderr = self.run_git(["reset", "--hard", branch])
		if code != 0:
			logger.error(f"[{self.name}] Failed to checkout branch {branch}: {stderr.strip()}")

	def run_git(self, args: List[str]) -> Tuple[int, str, str]:
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
			logger.exception(f"Git command failed: {e}")
			return -1, "", str(e)

	def get_patch(self, commit_hash: str, output_file: str) -> bool:
		logger.debug(f"* [{self.name}] Generating patch: {commit_hash}")
		cmd = f"git format-patch -1 {commit_hash} --stdout > {output_file}"

		try:
			os.chdir(self.path)
			result = subprocess.run(
				cmd,
				cwd=self.path,
				shell=True,
				capture_output=True,
				text=True,
				timeout=30
			)
			if result.returncode != 0:
				logger.error(f"  Gen patch failed!: {result.stderr.strip()}")
				return False
			if not os.path.exists(output_file):
				logger.error("  Patch file not found after generation!")
				return False
			return True
		except Exception as e:
			logger.exception(f"   Generate patch exception: {e}")
			return False

	def apply_patch(self, patch_file: str) -> bool:
		logger.debug(f"* [{self.name}] try apply patch [{patch_file}]")
		cmd = f"git apply --check {patch_file}"

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
				return False
			return True
		except Exception as e:
			logger.exception(f"   Apply patch exception: {e}")
			return False

	def revert_patch(self, cve_output_path: str = None) -> bool:
		return True

		code, _, _ = self.run_git(["am", "--abort"])
		if code != 0:
			logger.error(f"failed to abort patch")
		# code, _, _ = self.run_git(["reset", "--hard", "HEAD"])

		# if cve_output_path and os.path.exists(cve_output_path):
		# 	try:
		# 		shutil.rmtree(cve_output_path)
		# 	except Exception as e:
		# 		logger.error(f"   Failed to delete directory {cve_output_path}: {e}")

		if code == 0:
			return True
		else:
			logger.error(f"   Revert failed")
			return False


def extract_cve_id(file_path: str) -> str:
	filename = os.path.basename(file_path)
	match = re.search(r'(CVE-\d{4}-\d+)', filename)
	if match:
		return match.group(1)

	try:
		with open(file_path, 'r') as f:
			content = f.read(1024)
			match = re.search(r'(CVE-\d{4}-\d+)', content)
			if match:
				return match.group(1)
	except:
		pass

	return "Unknown_CVE"


def parse_dyad_file(file_path: str) -> List[DyadPair]:
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
		logger.error(f"Read file failed {file_path}: {e}")
	return pairs


def process_dyad_files(root_dir: str, repo_a_path: str, repo_b_path: str,
					   output_dir: str, branch_a: str, branch_b: str):
	repo_a = KernelRepo(repo_a_path, f"targetrepo: {repo_a_path}", branch_a)
	repo_b = KernelRepo(repo_b_path, f"baselinerepo: {repo_b_path}", branch_b)

	root_path = Path(root_dir)
	dyad_files = [str(p) for p in root_path.rglob("*.dyad")]

	if not dyad_files:
		logger.warning(f"No .dyad files found in {root_dir}")
		return

	os.makedirs(output_dir, exist_ok=True)
	output_dir = os.path.abspath(output_dir)
	logger.info(f"Found {len(dyad_files)} dyad files. Output dir: {output_dir}\n")

	original_cwd = os.getcwd()
	success_list = []
	failed_list = []
	for index, file_path in enumerate(dyad_files):
		logger.info(f"{file_path}")
		pairs = parse_dyad_file(file_path)
		success_flag = False
		detail_full_patch = None
		patch_list = []
		for pair in pairs:
			if pair.fixed_hash == '0':
				continue

			logger.debug(f"   Source: {pair.source_file}")
			cve_output_path = os.path.join(output_dir, pair.cve_id)
			os.makedirs(cve_output_path, exist_ok=True)

			dyad_filename = os.path.basename(file_path)
			target_dyad_path = os.path.join(cve_output_path, dyad_filename)
			try:
				shutil.copy2(file_path, target_dyad_path)
			except Exception as e:
				logger.error(f"* Failed to copy dyad file: {e}")

			patch_filename = f"{pair.cve_id}_{pair.fixed_hash}.patch"
			patch_full_path = os.path.join(cve_output_path, patch_filename)
			patch_list.append({
				"patch_full_path": patch_full_path,
				"fixed_hash": pair.fixed_hash,
				"cveid": pair.cve_id,
			})
			detail_full_patch = os.path.join(cve_output_path, "README.md")

			if not repo_b.get_patch(pair.fixed_hash, patch_full_path):
				logger.warning("* Skipping: Unable to get patch")
				continue

			success = repo_a.apply_patch(patch_full_path)

			if success:
				logger.debug(f"Patch applied successfully! Saved to: {patch_full_path}")
				success_flag = True
				logger.info(f"[{index + 1}/{len(dyad_files)}] (SUCCESS) Processing: {pair}")
			else:
				logger.debug("* Patch application failed, revert operation")
				logger.info(f"[{index + 1}/{len(dyad_files)}] (FAILED) Processing: {pair}")
				repo_a.revert_patch(cve_output_path)

		# report to README.md
		try:
			dyad_content = ""
			with open(file_path, 'r', encoding='utf-8') as f_src:
				dyad_content = f_src.read()
			with open(detail_full_patch, 'w', encoding='utf-8') as f:
				f.write(f"# {pair.cve_id}\n\n")

				f.write("## dyad信息\n\n")
				f.write("```\n")
				f.write(dyad_content)
				f.write("```\n")

				f.write("## 补丁信息\n\n")
				for patch_item in patch_list:
					p_path = patch_item.get("patch_full_path")
					p_hash = patch_item.get("fixed_hash")
					p_cve = patch_item.get("cveid")

					if p_path and os.path.exists(p_path):
						f.write(f"### 补丁: {p_hash or p_cve}\n\n")
						f.write("```diff\n")

						with open(p_path, 'r', encoding='utf-8') as f_patch:
							f.write(f_patch.read())

						f.write("```\n\n")
					else:
						f.write(f"### 补丁文件未找到或路径无效: {p_path}\n\n")

			logger.debug(f"   Successfully wrote README.md for {pair.cve_id}")
		except Exception as e:
			logger.error(f"* Failed to write README.md: {e}")

		# record to list
		if success_flag:
			success_list.append({
				"dyad_file": file_path,
				"cve_id": pair.cve_id,
				"detail": detail_full_patch
			})
		else:
			failed_list.append({
				"dyad_file": file_path,
				"cve_id": pair.cve_id,
				"detail": detail_full_patch
			})

	# generate summary
	markdown_path = os.path.join(output_dir, "SUMMARY.md")

	with open(markdown_path, 'w', encoding='utf-8') as f:
		f.write("# Dyad File Processing Summary\n\n")
		f.write(f"Total Dyad files processed: {len(set(item['dyad_file'] for item in success_list + failed_list))}\n")
		f.write(f"Successfully processed pairs: {len(success_list)}\n")
		f.write(f"Failed to process pairs: {len(failed_list)}\n\n")

		# Success List
		f.write("## Successfully Fixed CVEs\n\n")
		if success_list:
			f.write("| No. | Dyad File | CVE ID | Details | \n")
			f.write("| :--- | :--- | :--- | :--- |\n")

			for idx, item in enumerate(success_list, 1):
				f.write(
					f"| {idx} | "
					f"`{os.path.basename(item['dyad_file'])}` | "
					f"{item['cve_id']} | "
					f"[Details]({item['detail']})|\n")
		else:
			f.write("No successful entries.\n")
		f.write("\n")

		f.write("## Failed to Fix CVEs\n\n")
		if failed_list:
			f.write("| No. | Dyad File | CVE ID | Details | \n")
			f.write("| :--- | :--- | :--- | :--- |\n")

			for idx, item in enumerate(failed_list, 1):
				f.write(
					f"| {idx} | "
					f"`{os.path.basename(item['dyad_file'])}` | "
					f"{item['cve_id']} | "
					f"[Details]({item['detail']})|\n")
		else:
			f.write("No failed entries.\n")
		f.write("\n")

		logger.info(f"Processing summary generated: {markdown_path}")
	os.chdir(original_cwd)
	logger.info(f"All tasks completed.")


def load_config(config_file: str) -> dict:
	if not os.path.exists(config_file):
		logger.error(f"Configuration file '{config_file}' not found.")
		return None

	config = configparser.ConfigParser()
	try:
		config.read(config_file)

		paths = config['paths']
		args = {
			'dir': paths.get('data_dir'),
			'target': paths.get('target_repo'),
			'baseline': paths.get('baseline_repo'),
			'output': paths.get('output_dir'),
			'log_file': paths.get('log_file', 'cve-kin.log'),
			'target_branch': config['branches'].get('target_branch'),
			'baseline_branch': config['branches'].get('baseline_branch'),
		}

		required_keys = ['dir', 'target', 'baseline', 'output', 'target_branch',
						 'baseline_branch']
		for key in required_keys:
			if not args[key]:
				logger.error(f"Missing required configuration key '{key}' in '{config_file}'.")
				return None

		return args

	except Exception as e:
		logger.error(f"failed parsing configuration file: {e}")
		return None


if __name__ == "__main__":
	CONFIG_FILE = "cve-kin.cfg"

	config_args = load_config(CONFIG_FILE)

	if config_args is None:
		exit(1)

	log_filename = config_args['log_file']
	output_dir = config_args['output']
	os.makedirs(output_dir, exist_ok=True)
	full_log_path = os.path.join(output_dir, log_filename)
	logger = setup_logger(full_log_path)
	logger.info(f"Logger initialized. Log file path: {full_log_path}")

	if not os.path.exists(config_args['dir']):
		logger.error(f"Data directory does not exist: {config_args['dir']}")
		exit(1)
	if not os.path.exists(config_args['target']):
		logger.error(f"Target repository path does not exist: {config_args['target']}")
		exit(1)
	if not os.path.exists(config_args['baseline']):
		logger.error(f"Baseline repository path does not exist: {config_args['baseline']}")
		exit(1)

	process_dyad_files(
		config_args['dir'],
		config_args['target'],
		config_args['baseline'],
		config_args['output'],
		config_args['target_branch'],
		config_args['baseline_branch']
	)
