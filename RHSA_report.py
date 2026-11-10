#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Red Hat RHSA Assessment Automation Script with Email Notification,
CSAF Restart Classification, and Affected Versions Tracking.

This script fetches security data from the Red Hat Product Security API,
calculates risk scores, extracts CSAF restart requirement metadata, determines
affected product versions, and generates a formatted Excel report.
"""

import argparse
import calendar
import concurrent.futures
import os
import random
import sys
import time
import re
import threading
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple, Any

import pandas as pd
import requests
from deep_translator import GoogleTranslator, MyMemoryTranslator
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from tqdm import tqdm

try:
    from email_notification import EmailNotifier
except ImportError:
    print("[ERROR] email_notification.py not found. "
          "Please place it in the same directory.")
    sys.exit(1)


# --- Global Configuration ---
API_BASE = "https://access.redhat.com/hydra/rest/securitydata"
SLEEP_TIME = 1
DEBUG = False
LOG_FILE_HANDLE = None
MAX_WORKERS = 50
MAX_TRANSLATION_WORKERS = 5
MAX_RETRIES = 4
RETRY_BACKOFF_FACTOR = 2
MAX_BACKOFF_WAIT_TIME = 30

# API and network constants
REQUEST_TIMEOUT = 20
API_PAGE_SIZE = 1000
TRANSLATION_DELAY = 0.1

# Filename generation constants
FILENAME_RANDOM_MIN = 1000
FILENAME_RANDOM_MAX = 9999
MAX_FILENAME_LENGTH = 200

# Excel formatting constants
EXCEL_FONT_NAME = "Red Hat Display"
HEADER_FONT_SIZE = 14
BODY_FONT_SIZE = 12
COLOR_GREEN_FILL = 'C6EFCE'
COLOR_RED_FILL = 'FFC7CE'
COLUMN_WIDTH_RHSA = 25
COLUMN_WIDTH_MIN = 15
COLUMN_WIDTH_MAX = 60
COLUMN_WIDTH_PADDING = 4

# URL templates
ERRATA_URL_TEMPLATE = "https://access.redhat.com/errata/{}"
CVE_URL_TEMPLATE = "https://access.redhat.com/security/cve/{}"
CONTACT_EMAIL = "nitthaku@redhat.com"

# Risk scoring constants
DEFAULT_EXPLOITABILITY_SCORE = 0.5
DEFAULT_INDUSTRY_POPULARITY_SCORE = 0
REMEDIATION_THRESHOLD = 2.0

SEVERITY_SCORE = {
    "Critical": 1.5,
    "Important": 1.0,
    "Moderate": 0.5,
    "Low": 0,
}

# Restart classification categories
REBOOT_CATEGORIES = {"machine", "system", "zone"}
SERVICE_CATEGORIES = {"service", "vulnerable_component", "parent", "dependencies", "connected"}

# Local reporting policy: these package families are classified as reboot-required
# even when the CSAF restart_required.category says "none" or another category.
REBOOT_PACKAGE_HINTS = {
    "kernel", "kernel-pae", "kernel-rt", "kernel-smp", "kernel-xen",
    "linux-firmware", "dbus", "glibc", "hal", "systemd", "udev",
    "gnutls", "openssl-libs",
}
REBOOT_PACKAGE_PREFIXES = ("kernel-",)
REBOOT_PACKAGE_SUBSTRINGS = ("-firmware-", "firmware")


def is_reboot_override_package(pkg_name: str) -> bool:
    """Return True when a package matches the local reboot override policy."""
    pkg = str(pkg_name).strip().lower()
    if not pkg:
        return False
    if pkg in REBOOT_PACKAGE_HINTS:
        return True
    if any(pkg.startswith(prefix) for prefix in REBOOT_PACKAGE_PREFIXES):
        return True
    return any(token in pkg for token in REBOOT_PACKAGE_SUBSTRINGS)


LANG_CODES = {"chinese": "zh-CN", "japanese": "ja", "korean": "ko"}
MYMEMORY_LANG_CODES = {"chinese": "zh-CN", "japanese": "ja-JP", "korean": "ko-KR"}
MYMEMORY_SOURCE_CODE = "en-GB"

TRANSLATION_RATE_LIMIT = 4
TRANSLATION_BATCH_SIZE = 20
TRANSLATION_BATCH_PAUSE = 2.0

VERSION_SERVER_MAP = {
    "8.10": "8server",
    "7.9": "7server",
    "6.10": "6server",
}


class ProductConfig:
    MAPPING = {
        "rhel": "linux",
        "ansible": "ansible",
        "aap": "ansible",
        "openshift": "openshift",
        "ocp": "openshift",
    }

    DISPLAY_NAMES = {
        "rhel": "RHEL",
        "ansible": "Ansible/AAP",
        "aap": "Ansible/AAP",
        "openshift": "OpenShift/OCP",
        "ocp": "OpenShift/OCP",
    }


HEADERS = {
    "english": {
        "RHSA Name": "RHSA Name",
        "RHSA ID": "RHSA ID",
        "Published Date": "Published Date",
        "RHSA Severity": "RHSA Severity",
        "Affected Versions": "Affected Versions",
        "Classification": "Classification",
        "CSAF Restart Categories": "CSAF Restart Categories",
        "CVE ID": "CVE ID",
        "CVE Severity": "CVE Severity",
        "CVE Description": "CVE Description",
        "Vulnerability Impact Score": "Vulnerability Impact Score",
        "Exploitability Score": "Exploitability Score",
        "Industry Popularity Score": "Industry Popularity Score",
        "Risk Score": "Risk Score",
        "Remediation Required": "Remediation Required",
        "Remediation Step": "Remediation Step",
    },
    "chinese": {
        "RHSA Name": "补丁名称",
        "RHSA ID": "RHSA 标签",
        "Published Date": "发布日期",
        "RHSA Severity": "RHSA 等级",
        "Affected Versions": "受影响版本",
        "Classification": "重启分类",
        "CSAF Restart Categories": "CSAF 重启类别",
        "CVE ID": "CVE 标签",
        "CVE Severity": "漏洞等级",
        "CVE Description": "漏洞描述",
        "Vulnerability Impact Score": "漏洞危害程度",
        "Exploitability Score": "被利用难度",
        "Industry Popularity Score": "行业流行度",
        "Risk Score": "风险评估评分",
        "Remediation Required": "是否需要修复",
        "Remediation Step": "修复步骤方法",
    },
    "japanese": {
        "RHSA Name": "RHSA 名称",
        "RHSA ID": "RHSA ID",
        "Published Date": "公開日",
        "RHSA Severity": "RHSA 緊急度",
        "Affected Versions": "影響を受けるバージョン",
        "Classification": "再起動分類",
        "CSAF Restart Categories": "CSAF 再起動カテゴリ",
        "CVE ID": "CVE ID",
        "CVE Severity": "CVE 緊急度",
        "CVE Description": "CVE 説明",
        "Vulnerability Impact Score": "脆弱性影響点数/評価",
        "Exploitability Score": "悪用可能性点数/評価",
        "Industry Popularity Score": "業界人気点数/評価",
        "Risk Score": "危険程度点数/評価",
        "Remediation Required": "修正必要可否",
        "Remediation Step": "修正手順",
    },
    "korean": {
        "RHSA Name": "RHSA 이름",
        "RHSA ID": "RHSA ID",
        "Published Date": "게시일",
        "RHSA Severity": "RHSA 심각도",
        "Affected Versions": "영향을 받는 버전",
        "Classification": "재부팅/재시작 분류",
        "CSAF Restart Categories": "CSAF 재시작 범주",
        "CVE ID": "CVE ID",
        "CVE Severity": "CVE 심각도",
        "CVE Description": "CVE 설명",
        "Vulnerability Impact Score": "취약점 영향 점수",
        "Exploitability Score": "악용 가능성 점수",
        "Industry Popularity Score": "산업 인기 점수",
        "Risk Score": "위험도 점수",
        "Remediation Required": "조치 필요 여부",
        "Remediation Step": "조치 단계",
    },
}

TRANSLATED_TERMS = {
    "english": {"Yes": "Yes", "No": "No"},
    "chinese": {"Yes": "是", "No": "否"},
    "japanese": {"Yes": "はい", "No": "いいえ"},
    "korean": {"Yes": "예", "No": "아니요"},
}


def init_log_file(log_file_path: str) -> bool:
    global LOG_FILE_HANDLE
    try:
        LOG_FILE_HANDLE = open(log_file_path, 'w', encoding='utf-8')
        return True
    except Exception as e:
        print(f"[ERROR] Failed to open log file '{log_file_path}': {e}", flush=True)
        return False


def close_log_file() -> None:
    global LOG_FILE_HANDLE
    if LOG_FILE_HANDLE:
        try:
            LOG_FILE_HANDLE.close()
            LOG_FILE_HANDLE = None
        except Exception as e:
            print(f"[WARNING] Failed to close log file: {e}", flush=True)


def log(message: str, level: str = "INFO") -> None:
    if level == "DEBUG" and not DEBUG:
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{level.upper()}] {message}"
    print(log_line, flush=True)

    global LOG_FILE_HANDLE
    if LOG_FILE_HANDLE:
        try:
            LOG_FILE_HANDLE.write(log_line + "\n")
            LOG_FILE_HANDLE.flush()
        except Exception as e:
            print(f"[WARNING] Failed to write to log file: {e}", flush=True)


def get_json(url: str, params: Optional[Dict] = None, max_retries: int = MAX_RETRIES) -> Optional[Dict]:
    if params is None:
        params = {}

    for attempt in range(max_retries):
        try:
            resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
            if attempt < max_retries - 1:
                wait_time = min(RETRY_BACKOFF_FACTOR ** attempt, MAX_BACKOFF_WAIT_TIME)
                log(f"Network error on attempt {attempt + 1}/{max_retries}: {err}. Retrying in {wait_time}s...", "WARN")
                time.sleep(wait_time)
            else:
                log(f"Request failed after {max_retries} attempts: {url}\nReason: {err}", "ERROR")
                return None
        except requests.exceptions.RequestException as err:
            log(f"Request failed: {url}\nReason: {err}", "ERROR")
            return None

    return None


def clean_package_name(value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    arch_suffixes = (
        ".aarch64", ".x86_64", ".ppc64le", ".s390x", ".noarch",
        ".i686", ".i586", ".armv7hl", ".src",
    )
    for suffix in arch_suffixes:
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            if suffix == ".src":
                return ""
            break
    parts = value.rsplit("-", 2)
    if len(parts) != 3:
        return value
    name = parts[0]
    if name.endswith(("-debuginfo", "-debugsource")):
        return ""
    return name


def packages_from_csaf_doc(document: Dict[str, Any]) -> List[str]:
    packages = set()
    product_tree = document.get("product_tree", {})
    if isinstance(product_tree, dict):
        relationships = product_tree.get("relationships", [])
        if isinstance(relationships, list):
            for rel in relationships:
                if isinstance(rel, dict):
                    full_name = rel.get("full_product_name", {})
                    p_name = full_name.get("name", "") if isinstance(full_name, dict) else ""
                    cleaned = clean_package_name(p_name)
                    if cleaned:
                        packages.add(cleaned)
        branches = product_tree.get("branches", [])
        if isinstance(branches, list):
            for branch in branches:
                if isinstance(branch, dict):
                    name = branch.get("name", "")
                    cleaned = clean_package_name(name)
                    if cleaned:
                        packages.add(cleaned)
    return sorted(packages)


def restart_categories(document: Dict[str, Any]) -> List[str]:
    categories = set()
    vulnerabilities = document.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            remediations = vuln.get("remediations", [])
            if isinstance(remediations, list):
                for rem in remediations:
                    if not isinstance(rem, dict):
                        continue
                    restart = rem.get("restart_required")
                    if isinstance(restart, dict) and restart.get("category"):
                        cat = str(restart["category"]).strip().lower()
                        if cat:
                            categories.add(cat)

    if not categories:
        def walk(node):
            if isinstance(node, dict):
                restart = node.get("restart_required")
                if isinstance(restart, dict) and restart.get("category"):
                    cat = str(restart["category"]).strip().lower()
                    if cat:
                        categories.add(cat)
                for val in node.values():
                    walk(val)
            elif isinstance(node, list):
                for val in node:
                    walk(val)
        walk(document)

    return sorted(categories)


def classify_restart(categories: List[str], packages: List[str]) -> str:
    # Apply the local package-based override before considering CSAF categories.
    # This intentionally takes precedence over "none" and other categories.
    if any(is_reboot_override_package(pkg) for pkg in packages):
        return "Reboot indicated"

    cats_set = {str(category).strip().lower() for category in categories if str(category).strip()}
    if cats_set & REBOOT_CATEGORIES:
        return "Reboot indicated"
    if cats_set & SERVICE_CATEGORIES:
        return "Service/component restart indicated"
    if "none" in cats_set:
        return "No restart specified by CSAF"
    return "Restart impact not specified"


def internal_process_cve(cve_id: str) -> Tuple[str, str]:
    cve_api = f"{API_BASE}/cve/{cve_id}.json"
    cve_data = get_json(cve_api)
    if not cve_data:
        log(f"Failed to fetch CVE data for {cve_id}", "WARN")
        return "None", "None"

    cve_severity = str(cve_data.get("threat_severity", "None"))
    details = cve_data.get("details", [])
    cve_description = "\n".join(details) if isinstance(details, list) else str(details)
    return cve_severity, cve_description


def get_affected_versions(product_tree: dict, product_filter: str, version_filter: Optional[str]) -> Tuple[bool, str]:
    """
    Search the product tree to find all matching versions.
    Returns (is_affected, affected_versions_string).
    """
    if not isinstance(product_tree, dict):
        return False, ""

    if not version_filter:
        # If no specific version requested, check if product is present
        def check_prod(b):
            if product_filter in b.get("name", "").lower():
                return True
            return any(check_prod(sub) for sub in b.get("branches", []))
        is_affected = check_prod(product_tree)
        return is_affected, "All" if is_affected else ""

    target_versions = [v.strip() for v in version_filter.split(",") if v.strip()]
    matched_versions = set()

    def walk_tree(branch):
        if not isinstance(branch, dict):
            return
        product_name = branch.get("name", "").lower()
        if product_filter in product_name:
            product_info = branch.get("product", {})
            if product_info:
                product_id = product_info.get("product_id", "").lower()
                for ver in target_versions:
                    ver_lower = ver.lower()
                    if ver_lower in product_id:
                        matched_versions.add(ver)
                    else:
                        server_variant = VERSION_SERVER_MAP.get(ver_lower)
                        if server_variant and server_variant in product_id:
                            matched_versions.add(ver)
        for sub in branch.get("branches", []):
            walk_tree(sub)

    walk_tree(product_tree)

    if not matched_versions:
        return False, ""

    # Preserve order of target_versions
    sorted_matched = [v for v in target_versions if v in matched_versions]

    if len(sorted_matched) == len(target_versions) and len(target_versions) > 1:
        # All target versions affected
        ver_str = f"All ({', '.join(sorted_matched)})"
    else:
        ver_str = ", ".join(sorted_matched)

    return True, ver_str


def load_rhsa_from_api(after: str, before: str, severities: Optional[List[str]] = None) -> List[str]:
    page = 1
    all_results = []
    api_url = f"{API_BASE}/csaf.json"

    log(f"Fetching RHSA list from API for period {after} to {before}...", "INFO")
    if severities:
        log(f"Filtering by severities: {', '.join(severities)}", "INFO")

    while True:
        params = {"per_page": API_PAGE_SIZE, "page": page, "before": before, "after": after}
        if severities:
            params['severity'] = severities

        rhsa_data = get_json(api_url, params=params)
        if not rhsa_data:
            break

        log(f"Fetched page {page} with {len(rhsa_data)} items.", "DEBUG")
        results = [item["RHSA"] for item in rhsa_data if "RHSA" in item]
        all_results.extend(results)

        if len(rhsa_data) < API_PAGE_SIZE:
            break

        page += 1
        time.sleep(SLEEP_TIME)

    log(f"Total RHSAs fetched from API: {len(all_results)}", "INFO")
    return all_results


def load_rhsa_list(source_file: str) -> List[str]:
    if not os.path.exists(source_file):
        log(f"File not found: {source_file}", "ERROR")
        sys.exit(1)

    if source_file.lower().endswith(".txt"):
        with open(source_file, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]

    if source_file.lower().endswith((".xls", ".xlsx")):
        df = pd.read_excel(source_file)
        rhsa_cols = [
            col for col in df.columns
            if df[col].astype(str).str.contains("RHSA-", case=False).any()
        ]
        if not rhsa_cols:
            log("No column with RHSA IDs found in Excel file.", "ERROR")
            sys.exit(1)
        return df[rhsa_cols[0]].dropna().astype(str).tolist()

    log("Unsupported file type. Please use .txt or .xlsx.", "ERROR")
    sys.exit(1)


def calculate_period_range(period: str) -> Tuple[str, str]:
    today = datetime.today()
    year = today.year
    month = today.month

    if period == "half":
        if today.day <= 15:
            if month == 1:
                prev_month, prev_year = 12, year - 1
            else:
                prev_month, prev_year = month - 1, year
            after = datetime(prev_year, prev_month, 16)
            before = datetime(year, month, 1)
        else:
            after = datetime(year, month, 1)
            before = datetime(year, month, 16)
    elif period == "month":
        if month == 1:
            prev_month, prev_year = 12, year - 1
        else:
            prev_month, prev_year = month - 1, year
        after = datetime(prev_year, prev_month, 1)
        before = datetime(year, month, 1)
    elif period == "quarter":
        if month == 1:
            last_month, last_year = 12, year - 1
        else:
            last_month, last_year = month - 1, year
        before = datetime(year, month, 1)
        m_shift = month - 3
        y_shift = year
        if m_shift <= 0:
            m_shift += 12
            y_shift -= 1
        after = datetime(y_shift, m_shift, 1)
    else:
        raise ValueError("Invalid period: must be 'half', 'month', or 'quarter'.")

    return after.strftime("%Y-%m-%d"), before.strftime("%Y-%m-%d")


def process_rhsa(rhsa_id: str, product_filter: Optional[str] = None,
                 version_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    api_url = f"{API_BASE}/csaf/{rhsa_id}.json"
    rhsa_data = get_json(api_url)
    if not rhsa_data:
        return []

    affected_versions_str = "All"
    if product_filter:
        product_tree = rhsa_data.get("product_tree")
        is_affected, affected_versions_str = get_affected_versions(product_tree, product_filter, version_filter)
        if not is_affected:
            log(f"Skipping {rhsa_id}: Does not match product/version criteria.", "DEBUG")
            return []

    doc = rhsa_data.get("document", {})
    vulns = rhsa_data.get("vulnerabilities") or [{}]

    categories = restart_categories(rhsa_data)
    packages = packages_from_csaf_doc(rhsa_data)
    package_override = any(is_reboot_override_package(pkg) for pkg in packages)
    classification = classify_restart(categories, packages)
    # Per the requested reporting behavior, show "machine" in this column when
    # the local package override is applied, even if the raw CSAF category differs.
    csaf_categories_str = (
        "machine" if package_override
        else (", ".join(categories) if categories else "none specified")
    )

    results = []
    for item in vulns:
        cve_id = item.get("cve", "")
        sev, desc = internal_process_cve(cve_id) if cve_id else ("None", "None")
        impact_score = SEVERITY_SCORE.get(sev, 0)
        risk_score = impact_score + DEFAULT_EXPLOITABILITY_SCORE

        results.append({
            "RHSA Name": doc.get("title", "N/A")
            .replace("Red Hat Security Advisory: ", "")
            .replace(" security update", ""),
            "RHSA ID": rhsa_id,
            "Published Date": doc.get("tracking", {}).get(
                "initial_release_date", "N/A").split("T")[0],
            "RHSA Severity": doc.get("aggregate_severity", {}).get("text", "N/A"),
            "Affected Versions": affected_versions_str,
            "Classification": classification,
            "CSAF Restart Categories": csaf_categories_str,
            "CVE ID": cve_id,
            "CVE Severity": sev,
            "CVE Description": desc,
            "Vulnerability Impact Score": impact_score,
            "Exploitability Score": DEFAULT_EXPLOITABILITY_SCORE,
            "Industry Popularity Score": DEFAULT_INDUSTRY_POPULARITY_SCORE,
            "Risk Score": risk_score,
            "Remediation Required": "Yes" if risk_score >= REMEDIATION_THRESHOLD else "No",
            "Remediation Step": "",
        })
    return results


def format_excel_sheet(worksheet, df, language: str) -> None:
    header_font = Font(name=EXCEL_FONT_NAME, size=HEADER_FONT_SIZE, bold=True)
    body_font = Font(name=EXCEL_FONT_NAME, size=BODY_FONT_SIZE)
    thin_side = Side(style='thin')
    border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    align_left = Alignment(horizontal='left', vertical='center', wrap_text=True)
    align_right = Alignment(horizontal='right', vertical='center', wrap_text=True)
    align_center = Alignment(horizontal='center', vertical='center', wrap_text=True)
    fill_green = PatternFill(start_color=COLOR_GREEN_FILL, end_color=COLOR_GREEN_FILL, fill_type='solid')
    fill_red = PatternFill(start_color=COLOR_RED_FILL, end_color=COLOR_RED_FILL, fill_type='solid')

    worksheet.freeze_panes = 'A2'
    worksheet.auto_filter.ref = worksheet.dimensions

    for cell in worksheet["1:1"]:
        cell.font = header_font
        cell.border = border
        cell.alignment = align_center

    header_map = HEADERS.get(language, HEADERS['english'])
    yes_term = TRANSLATED_TERMS[language]["Yes"]

    header_col_indices = {}
    for col_idx in range(1, worksheet.max_column + 1):
        val = worksheet.cell(row=1, column=col_idx).value
        if val:
            header_col_indices[str(val).strip()] = col_idx

    rhsa_col_idx = header_col_indices.get(header_map["RHSA ID"])
    cve_col_idx = header_col_indices.get(header_map["CVE ID"])
    rem_col_idx = header_col_indices.get(header_map["Remediation Required"])
    cve_desc_col_idx = header_col_indices.get(header_map["CVE Description"])

    last_text_col = cve_desc_col_idx if cve_desc_col_idx else 10

    for row in worksheet.iter_rows(min_row=2):
        for cell in row:
            cell.font = body_font
            cell.border = border
            cell.alignment = align_left if cell.column <= last_text_col else align_right

            if rhsa_col_idx and cell.column == rhsa_col_idx and cell.value:
                cell.hyperlink = ERRATA_URL_TEMPLATE.format(cell.value)
            elif cve_col_idx and cell.column == cve_col_idx and cell.value:
                cell.hyperlink = CVE_URL_TEMPLATE.format(cell.value)

            if rem_col_idx and cell.column == rem_col_idx:
                cell.fill = fill_red if str(cell.value) == yes_term else fill_green

    _merge_rhsa_cells(worksheet, align_left, rhsa_col_idx or 2)
    _autosize_columns(worksheet)


def _merge_rhsa_cells(worksheet, alignment: Alignment, rhsa_col_idx: int) -> None:
    # Merges columns A through G (RHSA Name, ID, Date, Severity, Affected Versions, Classification, Categories)
    merge_cols = ['A', 'B', 'C', 'D', 'E', 'F', 'G']
    start_row = 2
    while start_row <= worksheet.max_row:
        current_id = worksheet.cell(row=start_row, column=rhsa_col_idx).value
        if not current_id:
            start_row += 1
            continue
        end_row = start_row
        while (end_row + 1 <= worksheet.max_row and
               worksheet.cell(row=end_row + 1, column=rhsa_col_idx).value == current_id):
            end_row += 1

        if end_row > start_row:
            for col_letter in merge_cols:
                worksheet.merge_cells(f"{col_letter}{start_row}:{col_letter}{end_row}")
                worksheet[f"{col_letter}{start_row}"].alignment = alignment
        start_row = end_row + 1


def _autosize_columns(worksheet) -> None:
    for col in worksheet.columns:
        max_length = 0
        col_letter = col[0].column_letter
        if col_letter in ['A', 'B', 'C', 'D', 'E', 'F', 'G']:
            worksheet.column_dimensions[col_letter].width = COLUMN_WIDTH_RHSA
            continue
        for cell in col:
            if cell.value:
                cell_str = str(cell.value).strip()
                if cell_str:
                    max_line_len = max(len(line) for line in cell_str.split('\n'))
                    max_length = max(max_length, max_line_len)
        worksheet.column_dimensions[col_letter].width = max(
            COLUMN_WIDTH_MIN, min(COLUMN_WIDTH_MAX, max_length + COLUMN_WIDTH_PADDING)
        )


def main():
    global DEBUG
    parser = argparse.ArgumentParser(
        description="Red Hat RHSA Risk Assessment Automation Script with CSAF Restart Classification and Affected Versions"
    )
    source_group = parser.add_argument_group('Input Source (choose one)')
    source_group.add_argument("-s", "--from-source", type=str,
                              help="Input file with RHSA list (TXT or XLSX)")
    source_group.add_argument("-a", "--after", type=str,
                              help="Filter RHSAs published after this date (YYYY-MM-DD)")
    source_group.add_argument("-b", "--before", type=str,
                              help="Filter RHSAs published before this date (YYYY-MM-DD)")
    source_group.add_argument("-p", "--period", choices=["half", "month", "quarter"],
                              help="Automatically set date range (--after and --before)")

    filter_group = parser.add_argument_group('API Filtering Options')
    filter_group.add_argument("--product",
                              help="Filter by product name (e.g., 'RHEL', 'OpenShift').")
    filter_group.add_argument("--product-version", type=str,
                              help="Filter by product version (e.g., '8.10', '8.10,9.4,9.6').")
    filter_group.add_argument("--severity", type=str,
                              help="Filter by severities (comma-separated: low,moderate,important,critical).")

    output_group = parser.add_argument_group('Output and General Options')
    output_group.add_argument("-o", "--output-file", default=None,
                              help="Output Excel file name")
    output_group.add_argument("-L", "--language", default="english",
                              choices=["english", "chinese", "japanese", "korean"],
                              help="Set output language.")
    output_group.add_argument("--log-file", type=str, default=None,
                              help="Save all log messages to a file")
    output_group.add_argument("--debug", action="store_true", help="Enable debug mode")

    email_group = parser.add_argument_group('Email Options')
    email_group.add_argument("-e", "--email", action="store_true",
                             help="Send the report via email.")
    email_group.add_argument("--mail_to",
                             help="Comma-separated recipient emails (required with --email).")

    args = parser.parse_args()
    DEBUG = args.debug

    if args.log_file:
        if not init_log_file(args.log_file):
            sys.exit(1)
        log(f"Log file initialized: {os.path.abspath(args.log_file)}", "INFO")

    after_date, before_date = None, None
    clean_product_name = None
    subject_parts = []
    end_date_for_title = None

    if sum(arg is not None for arg in [args.from_source, args.after, args.period]) > 1:
        close_log_file()
        sys.exit("Error: Use only one of --from-source, --after/--before, or --period.")
    if not any([args.from_source, args.after, args.period]):
        close_log_file()
        sys.exit("Error: You must specify an input source: --from-source, --after/--before, or --period.")

    if args.after or args.before:
        if not (args.after and args.before):
            close_log_file()
            sys.exit("Error: Both --after and --before are required when using date ranges.")

    if args.from_source and any([args.product, args.product_version, args.severity]):
        close_log_file()
        sys.exit("Error: API filters cannot be used with --from-source.")

    if args.email and not args.mail_to:
        close_log_file()
        sys.exit("Error: --mail_to is required when using --email.")

    if args.product:
        product_input = args.product.lower()
        if product_input in ProductConfig.MAPPING:
            clean_product_name = ProductConfig.DISPLAY_NAMES.get(product_input, args.product)
            args.product = ProductConfig.MAPPING[product_input]
            log(f"Product filter '{product_input}' mapped to internal search term '{args.product}'.", "DEBUG")
        else:
            valid_products = ", ".join(ProductConfig.MAPPING.keys())
            close_log_file()
            sys.exit(f"Error: Invalid value for --product. Must be one of: {valid_products}.")

    if args.product_version and not args.product:
        close_log_file()
        sys.exit("Error: --product-version requires --product.")

    severities = []
    if args.severity:
        valid_severities = {"low", "moderate", "important", "critical"}
        severities = [s.strip().lower() for s in args.severity.split(',')]
        if not all(s in valid_severities for s in severities):
            close_log_file()
            sys.exit(f"Error: Invalid severity provided. Choose from: {', '.join(valid_severities)}.")

    if args.after and args.before:
        after_date, before_date = args.after, args.before
        try:
            dt_after = datetime.strptime(after_date, "%Y-%m-%d")
            dt_before = datetime.strptime(before_date, "%Y-%m-%d")
            if dt_after >= dt_before:
                close_log_file()
                sys.exit("Error: --after date must be earlier than --before date.")
        except ValueError as e:
            close_log_file()
            sys.exit(f"Error: Invalid date format. Use YYYY-MM-DD. Details: {e}")
    elif args.period:
        after_date, before_date = calculate_period_range(args.period)

    if clean_product_name:
        subject_parts.append(f"{clean_product_name}")
    if args.product_version:
        subject_parts.append(f"v{args.product_version}")
    if args.severity:
        subject_parts.append(f"Severity({args.severity.upper()})")

    if after_date and before_date:
        try:
            dt_before = datetime.strptime(before_date, "%Y-%m-%d")
            dt_end = dt_before - timedelta(days=1)
            end_date_for_title = dt_end.strftime("%Y-%m-%d")
        except ValueError:
            end_date_for_title = before_date

        subject_parts.append(f"{after_date} to {end_date_for_title}")

    filter_str = " - ".join(subject_parts)

    if not args.output_file:
        today_date_str = datetime.now().strftime("%Y-%m-%d")
        random_digits = random.randint(FILENAME_RANDOM_MIN, FILENAME_RANDOM_MAX)

        if args.from_source:
            args.output_file = f"Self-defined RHSA Report - {today_date_str}-{random_digits}.xlsx"
        else:
            clean_filter_str = re.sub(r'[\\/:*?"<>|]', '', filter_str).strip()
            args.output_file = f"RHSA_Report-{clean_filter_str}-{today_date_str}-{random_digits}.xlsx" if clean_filter_str else f"RHSA_Report-{today_date_str}-{random_digits}.xlsx"

        if len(args.output_file) > MAX_FILENAME_LENGTH:
            args.output_file = f"RHSA_Report-{today_date_str}-{random_digits}.xlsx"

    # --- Data Loading ---
    if args.from_source:
        rhsa_list = load_rhsa_list(args.from_source)
    else:
        rhsa_list = load_rhsa_from_api(
            after=after_date,
            before=before_date,
            severities=severities
        )

    if not rhsa_list:
        log("No RHSA entries found for the given criteria. Exiting.", "WARN")
        close_log_file()
        sys.exit(0)

    log(f"Found {len(rhsa_list)} RHSA entries to process.", "INFO")
    if args.product:
        log(f"Client-side filtering enabled for Product: '{args.product}'", "INFO")
        if args.product_version:
            log(f"and Version(s): '{args.product_version}'", "INFO")

    # --- Processing ---
    all_rows = []
    actual_workers = min(len(rhsa_list), MAX_WORKERS)
    initial_rhsa_count = len(rhsa_list)

    log(f"Processing {initial_rhsa_count} RHSAs with {actual_workers} threads...", "INFO")

    with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
        future_to_rhsa = {
            executor.submit(process_rhsa, rid, args.product, args.product_version): rid
            for rid in rhsa_list
        }
        for future in tqdm(concurrent.futures.as_completed(future_to_rhsa),
                           total=len(rhsa_list), desc="Processing RHSAs"):
            rhsa_id = future_to_rhsa[future]
            try:
                results = future.result()
                if results:
                    all_rows.extend(results)
            except Exception as exc:
                log(f"{rhsa_id} generated an exception: {exc}", "ERROR")

    if not all_rows:
        log("No data matched the filter criteria after processing. Exiting.", "WARN")
        close_log_file()
        sys.exit(0)

    df = pd.DataFrame(all_rows)
    lang = args.language
    header_map = HEADERS.get(lang, HEADERS['english'])
    df.rename(columns=header_map, inplace=True)

    log(f"Applied headers for language '{lang}'.", "DEBUG")

    # --- Translation ---
    if lang != "english":
        log(f"Translating content to {lang}.", "INFO")
        try:
            rem_col = header_map["Remediation Required"]
            df[rem_col] = df[rem_col].map(TRANSLATED_TERMS[lang]).fillna(df[rem_col])

            desc_col = header_map["CVE Description"]
            unique_texts = df[desc_col].dropna().unique()
            texts_to_translate = [t for t in unique_texts if t and t != "None"]

            translator = GoogleTranslator(source="auto", target=LANG_CODES[lang])

            def translate_text(txt):
                max_translation_retries = 3
                for attempt in range(max_translation_retries):
                    try:
                        time.sleep(TRANSLATION_DELAY)
                        return translator.translate(txt)
                    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as err:
                        if attempt < max_translation_retries - 1:
                            wait_time = min(RETRY_BACKOFF_FACTOR ** attempt, MAX_BACKOFF_WAIT_TIME)
                            time.sleep(wait_time)
                        else:
                            return txt
                    except Exception:
                        return txt
                return txt

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_TRANSLATION_WORKERS) as exec_pool:
                translated = list(tqdm(exec_pool.map(translate_text, texts_to_translate),
                                       total=len(texts_to_translate),
                                       desc="Translating descriptions"))
            translation_map = dict(zip(texts_to_translate, translated))
            df[desc_col] = df[desc_col].map(translation_map).fillna(df[desc_col])
        except Exception as err:
            log(f"Translation error: {err}. Continuing with untranslated content.", "WARN")

    # --- Excel Generation ---
    try:
        with pd.ExcelWriter(args.output_file, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='RHSA Report')
            format_excel_sheet(writer.sheets['RHSA Report'], df, lang)
    except Exception as e:
        log(f"Failed writing Excel file '{args.output_file}': {e}", "ERROR")
        close_log_file()
        sys.exit(1)

    abs_path = os.path.abspath(args.output_file)
    log(f"Report saved to {abs_path}", "INFO")

    rhsa_col = header_map["RHSA ID"]
    cve_col = header_map["CVE ID"]
    unique_rhsas = df[rhsa_col].nunique()
    total_cves = len(df)
    unique_cves = df[cve_col].nunique()

    if args.product and initial_rhsa_count > unique_rhsas:
        filtered_out = initial_rhsa_count - unique_rhsas
        log(f"Filter results: {unique_rhsas} RHSAs matched (filtered out {filtered_out} RHSAs)", "INFO")

    log(f"Report contains {unique_rhsas} unique RHSAs, {total_cves} CVEs ({unique_cves} unique)", "INFO")

    # --- Email Dispatch ---
    if args.email:
        recipients = [email.strip() for email in args.mail_to.split(',')]
        log(f"Sending report to: {', '.join(recipients)}", "INFO")

        subject = f"RHSA Report - {filter_str}" if filter_str else f"RHSA Report - {datetime.now():%Y-%m-%d}"

        body_filters = []
        if clean_product_name:
            body_filters.append(f"Product: {clean_product_name}")
        if args.product_version:
            body_filters.append(f"Version: {args.product_version}")
        if args.severity:
            body_filters.append(f"Severity: {args.severity}")
        if after_date and before_date:
            body_filters.append(f"Published Period: {after_date} to {end_date_for_title}")
        elif args.from_source:
            body_filters.append("Input Source: External RHSA list file")

        filter_html = "".join(f"<p style='margin-left: 20px;'>- {f}</p>" for f in body_filters)

        body = (
            "<html><body><p>Hello,</p>"
            "<p>Please find attached the RHSA risk assessment report.</p>"
            f"<p><b>Report Generation Date:</b> {datetime.now():%Y-%m-%d %H:%M:%S}</p>"
            f"<p><b>Report Statistics:</b> {unique_rhsas} unique RHSAs, {total_cves} CVEs ({unique_cves} unique)</p>"
            "<p><b>Applied Filters:</b></p>"
            f"{filter_html}"
            f"<p>This is an automated message. Contact Nitesh Thakur<{CONTACT_EMAIL}> if needed.</p></body></html>"
        )

        email_client = EmailNotifier()
        email_client.set_recipients(recipients)
        if email_client.send_email(subject, body, args.output_file):
            log("Email sent successfully.", "INFO")
        else:
            log("Failed to send email. Check your email configuration.", "ERROR")
            close_log_file()
            sys.exit(1)

    close_log_file()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Script interrupted by user", flush=True)
        close_log_file()
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}", flush=True)
        close_log_file()
        sys.exit(1)
