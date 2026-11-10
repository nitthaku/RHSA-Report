# RHSA-Report

Generate an Excel report of Red Hat security advisories, their vulnerabilities, custom risk scores, and restart guidance. Optionally translate descriptions and email the completed report.

This README describes [RHSA_report.py](RHSA_report.py) and its email helper, [email_notification.py](email_notification.py).

## Contents

- [Overview](#overview)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [Input methods and periods](#input-methods-and-periods)
- [Products and filters](#products-and-filters)
- [Command examples](#command-examples)
- [Command-line reference](#command-line-reference)
- [Understanding the Excel report](#understanding-the-excel-report)
- [Risk scoring](#risk-scoring)
- [Restart classification](#restart-classification)
- [Email configuration](#email-configuration)
- [Translation](#translation)
- [Troubleshooting and limitations](#troubleshooting-and-limitations)

## Overview

- **RHSA:** Red Hat Security Advisory, which can address several vulnerabilities.
- **CVE:** Common Vulnerabilities and Exposures identifier for an individual vulnerability.
- **CSAF:** Common Security Advisory Framework, a structured format for security advisory information.

The script follows this workflow:

```text
Choose a date range or advisory list
  → Fetch advisory documents from Red Hat
  → Match product/version filters, when requested
  → Fetch CVE descriptions and severity
  → Calculate custom scores and restart classifications
  → Optionally translate descriptions
  → Write an Excel report
  → Optionally email the attachment
```

The script does not scan servers, inspect installed packages, confirm exposure, or install patches. Product matching describes advisory metadata, not the software installed in your environment.

## Requirements and installation

You need Python 3 with `pip`, virtual environment support, and access to the relevant network services. A minimum supported Python version has not been established by the repository files inspected for this README.

Keep `RHSA_report.py` and `email_notification.py` in the same directory. The main script imports the email helper even when email is disabled.

From the repository root, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pandas requests deep-translator openpyxl tqdm
```

For legacy `.xls` input, also install the reader dependency:

```bash
python -m pip install xlrd
```

No `requirements.txt` was present in the inspected repository. These installation commands are based on imports and input formats; package versions are not pinned or verified as a compatibility set. The remaining imports, including `smtplib`, are from Python's standard library.

Network access:

| Purpose | Destination |
|---|---|
| Advisory and CVE data | `https://access.redhat.com/hydra/rest/securitydata` |
| Optional description translation | Google Translate through `deep-translator` |
| Optional email | Configured SMTP server; default `smtp.corp.redhat.com`, TCP port 25 |

Display available options:

```bash
python RHSA_report.py --help
```

## Quick start

Generate a report for the previous calendar month without sending email:

```bash
python RHSA_report.py --period month --output-file report.xlsx
```

The output is saved relative to your current working directory unless you provide an absolute path. Create destination directories before running the script.

If `--output-file` is omitted, the script generates an `.xlsx` filename containing filter information, the current date, and four random digits. File-list reports use the prefix `Self-defined RHSA Report`. Long generated names fall back to a shorter name.

An explicitly named existing output file can be overwritten. Log files are also opened in overwrite mode.

## Input methods and periods

Choose one input method: a date range, an automatic period, or a file of advisory IDs.

### Explicit dates

```bash
python RHSA_report.py \
  --after 2026-10-01 \
  --before 2026-11-01 \
  --output-file october-report.xlsx
```

Both dates are required, in `YYYY-MM-DD` format, and `--after` must be earlier than `--before`.

The script passes the boundaries directly to the Red Hat API. It labels the report's end date as one day before `--before`. Exact API boundary inclusion is not verified by the local implementation.

### Automatic periods

Dates are calculated using the machine's local clock.

| Value | Range calculated by the script |
|---|---|
| `half` | If today is the 1st–15th: previous month's 16th to current month's 1st. Otherwise: current month's 1st to 16th. |
| `month` | Previous calendar month's 1st to current month's 1st. |
| `quarter` | First day three months before the current month to current month's 1st. This means the previous three complete months, not necessarily a calendar quarter. |

For example, on November 10, 2026, the calculated boundaries are October 16–November 1 for `half`, October 1–November 1 for `month`, and August 1–November 1 for `quarter`.

### TXT input

Create a UTF-8 file with one RHSA ID per line. This is a format illustration; replace each placeholder with a real advisory ID:

```text
RHSA-YYYY:NNNN
RHSA-YYYY:NNNN
```

```bash
python RHSA_report.py --from-source rhsa-list.txt --output-file selected-report.xlsx
```

Blank lines are skipped. Other lines are used as-is; do not include a header, comments, or explanatory text.

### Excel input

```bash
python RHSA_report.py --from-source rhsa-list.xlsx --output-file selected-report.xlsx
```

The script reads the first worksheet using pandas, with the first row treated as column headers. It selects the first column containing any value matching `RHSA-` without case sensitivity, then uses all non-empty values from that column. Keep that column limited to valid advisory IDs.

Both `.xlsx` and legacy `.xls` are accepted; `.xls` requires an appropriate reader such as `xlrd`.

### Input restrictions

- Do not combine `--from-source`, `--period`, and explicit date input.
- `--from-source` rejects `--product`, `--product-version`, and `--severity`.
- `--product-version` requires `--product`.
- At least one input method is required.

## Products and filters

| Product family | Accepted `--product` values | Internal name search |
|---|---|---|
| Red Hat Enterprise Linux | `rhel` | `linux` |
| Ansible / Ansible Automation Platform | `ansible`, `aap` | `ansible` |
| OpenShift / OpenShift Container Platform | `openshift`, `ocp` | `openshift` |
| All products returned by the API | Omit `--product` | No product filtering |

Only one product value is accepted per run. Product arguments are case-insensitive. Products are matched locally against names in the advisory product tree.

`--product-version` accepts one value or comma-separated values. The implementation checks whether version text occurs in a matching product's ID. It also maps `8.10` to `8server`, `7.9` to `7server`, and `6.10` to `6server` as fallback matches. These are broad matching rules rather than exact installed-version checks.

`--severity` accepts `low`, `moderate`, `important`, and `critical`, individually or comma-separated. Severity is sent to the advisory listing API; the risk score is calculated separately from each CVE's severity.

## Command examples

Run these from the repository root with the virtual environment activated. Version numbers are illustrative filters, not statements of current product support. Substitute the versions relevant to your environment.

### All products and automatic periods

```bash
python RHSA_report.py --period half --output-file all-products-half.xlsx
python RHSA_report.py --period month --output-file all-products-month.xlsx
python RHSA_report.py --period quarter --output-file all-products-quarter.xlsx
```

### RHEL: all versions, one version, or multiple versions

```bash
python RHSA_report.py --period month --product rhel --output-file rhel-all.xlsx

python RHSA_report.py \
  --period month --product rhel --product-version "8.10" \
  --output-file rhel-8.10.xlsx

python RHSA_report.py \
  --period month --product rhel --product-version "8.10,9.4,9.6" \
  --severity "important,critical" --output-file rhel-selected.xlsx
```

### Ansible / AAP

```bash
python RHSA_report.py --period month --product ansible --output-file ansible-all.xlsx

python RHSA_report.py \
  --period month --product aap --product-version "2.4" \
  --severity "important,critical" --output-file aap-selected.xlsx
```

### OpenShift / OCP

```bash
python RHSA_report.py --period month --product openshift --output-file openshift-all.xlsx

python RHSA_report.py \
  --period quarter --product ocp --product-version "4.14,4.15" \
  --severity critical --output-file ocp-critical.xlsx
```

### Custom dates and severity

```bash
python RHSA_report.py \
  --after 2026-10-01 --before 2026-11-01 \
  --product rhel --severity "important,critical" \
  --output-file rhel-october.xlsx
```

### Output languages

```bash
python RHSA_report.py --period month --language english --output-file report-en.xlsx
python RHSA_report.py --period month --language chinese --output-file report-zh.xlsx
python RHSA_report.py --period month --language japanese --output-file report-ja.xlsx
python RHSA_report.py --period month --language korean --output-file report-ko.xlsx
```

### Logs and debugging

```bash
python RHSA_report.py \
  --period month --product rhel \
  --output-file rhel-report.xlsx --log-file rhsa-run.log --debug
```

### Email one or multiple recipients

Replace the example addresses with intended recipients. These commands attempt to send email using the configured SMTP server and sender.

```bash
python RHSA_report.py \
  --period month --product rhel --output-file rhel-report.xlsx \
  --email --mail_to "your.name@example.com"

python RHSA_report.py \
  --period month --product openshift --output-file openshift-report.xlsx \
  --email --mail_to "person1@example.com,person2@example.com"
```

### Separate reports for each product family

This loop works in Bash and Zsh:

```bash
for product in rhel ansible openshift; do
  python RHSA_report.py \
    --period month --product "$product" \
    --output-file "${product}-report.xlsx"
done
```

## Command-line reference

| Argument | Default | Purpose and restrictions |
|---|---|---|
| `-h`, `--help` | — | Show help and exit. |
| `-s`, `--from-source` | Unset | TXT, XLSX, or XLS advisory list. Cannot use product, version, or severity filters. |
| `-a`, `--after` | Unset | Start date, `YYYY-MM-DD`; requires `--before`. |
| `-b`, `--before` | Unset | End boundary, `YYYY-MM-DD`; requires `--after`. |
| `-p`, `--period` | Unset | `half`, `month`, or `quarter`. Alternative to file or explicit date input. |
| `--product` | Unset | `rhel`, `ansible`, `aap`, `openshift`, or `ocp`. One value per run. |
| `--product-version` | Unset | Comma-separated version filters; requires `--product`. |
| `--severity` | Unset | Comma-separated advisory severity filters: `low`, `moderate`, `important`, `critical`. |
| `-o`, `--output-file` | Generated filename | Output Excel path; use `.xlsx`. |
| `-L`, `--language` | `english` | `english`, `chinese`, `japanese`, or `korean`. |
| `--log-file` | Unset | Save messages produced by the main script's logging helper. |
| `--debug` | Off | Include debug messages. |
| `-e`, `--email` | Off | Email the report after writing it; requires `--mail_to`. |
| `--mail_to` | Unset | Comma-separated recipients. Has no sending effect without `--email`. |

Use the underscore in `--mail_to`; `--mail-to` is not supported.

## Understanding the Excel report

The workbook contains one worksheet named **RHSA Report**. Generally, each row represents a CVE within one advisory. The same CVE can appear under multiple advisories. An advisory without vulnerability entries can produce a placeholder row.

| Column | Meaning |
|---|---|
| RHSA Name | Advisory title with selected standard wording removed. |
| RHSA ID | Advisory identifier, linked to Red Hat's errata page. |
| Published Date | Initial release date from the advisory. |
| RHSA Severity | Aggregate advisory severity. |
| Affected Versions | Requested versions matched by the filter, or the placeholder `All`; see below. |
| Classification | Restart guidance calculated by the script. |
| CSAF Restart Categories | Collected restart categories, or `machine` when a local package override applies. |
| CVE ID | Vulnerability identifier, linked to Red Hat's CVE page. |
| CVE Severity | Severity fetched from the CVE API. |
| CVE Description | Description fetched from the CVE API, optionally translated. |
| Vulnerability Impact Score | Numeric mapping of CVE severity. |
| Exploitability Score | Fixed value of `0.5`. |
| Industry Popularity Score | Fixed value of `0`; not included in the risk formula. |
| Risk Score | Impact score plus `0.5`. |
| Remediation Required | `Yes` at risk score 2.0 or above; otherwise `No`. |
| Remediation Step | Left blank by the script. |

The worksheet freezes the header row, enables filtering, wraps text, and adds borders. The first seven columns are merged across consecutive rows for the same advisory. Remediation flags are red for Yes and green otherwise. Row groups arrive in processing-completion order; the script does not sort by date or severity.

### What “Affected Versions” actually means

| Run configuration | Value written |
|---|---|
| No product filter | `All`, without extracting product names or versions. |
| Product filter without version filter | `All` when the product name matches, without enumerating versions. |
| Product and version filters | Matched requested versions; if all of several requested versions match, `All (version1, version2, ...)`. |

**`All` is a placeholder, not evidence that every product or version is affected.** There is no dedicated affected-product column. The advisory title may suggest a product, but the report does not systematically identify products in the unfiltered mode.

## Risk scoring

The implemented formula is:

```text
Risk Score = Vulnerability Impact Score + 0.5
Remediation Required = Yes when Risk Score >= 2.0
```

| CVE severity | Impact | Exploitability | Risk score | Remediation Required |
|---|---:|---:|---:|---|
| Critical | 1.5 | 0.5 | 2.0 | Yes |
| Important | 1.0 | 0.5 | 1.5 | No |
| Moderate | 0.5 | 0.5 | 1.0 | No |
| Low | 0 | 0.5 | 0.5 | No |
| Missing or unrecognized | 0 | 0.5 | 0.5 | No |

This is a custom score, not CVSS. Exploitability is fixed; the script does not check active exploitation. Industry Popularity Score is stored as zero and is not used in the formula.

“Remediation Required: No” reflects this threshold only. It does not establish that patching is unnecessary. Missing CVE data also receives a low default score, so check logs and source advisories when interpreting results.

## Restart classification

The script collects restart categories across the advisory and applies these rules in order:

| Condition | Classification |
|---|---|
| Any package matches the local reboot override | Reboot indicated |
| Category includes `machine`, `system`, or `zone` | Reboot indicated |
| Category includes `service`, `vulnerable_component`, `parent`, `dependencies`, or `connected` | Service/component restart indicated |
| Category includes `none` | No restart specified by CSAF |
| No recognized category | Restart impact not specified |

Local reboot overrides match these package names:

```text
kernel, kernel-pae, kernel-rt, kernel-smp, kernel-xen,
linux-firmware, dbus, glibc, hal, systemd, udev,
gnutls, openssl-libs
```

Names beginning with `kernel-` or containing `firmware` also match. Package names are derived from selected CSAF product-tree fields, with normalization of package versions and architecture suffixes.

The override takes precedence even when CSAF says `none`. When it applies, the script writes **`machine` into CSAF Restart Categories**, replacing the collected categories in that report field. This column therefore does not always preserve the original source metadata.

Restart classification is advisory-wide and is reused for its CVE rows. Package and category collection is not restricted to only the product/version selected by the filter.

## Email configuration

The main script creates `EmailNotifier()` with the defaults defined in [email_notification.py](email_notification.py):

| Setting | Current value |
|---|---|
| Sender email | `nitthaku@redhat.com` |
| Sender display name | `Nitesh Thakur` |
| SMTP host | `smtp.corp.redhat.com` |
| SMTP port | `25` |
| Authentication | No SMTP login call |
| Encryption | No STARTTLS or implicit TLS configured |
| Recipients | Replaced with addresses supplied through `--mail_to` |
| Attachment | The generated Excel report |

The HTML message includes filters, generation time, report counts, and a contact address. `CONTACT_EMAIL` in `RHSA_report.py` controls that contact text; changing it does not change the sender.

To customize the sender or server, a maintainer can edit the `EmailNotifier.__init__` defaults or pass `mail_host`, `mail_user`, and `sender_name` where `EmailNotifier()` is constructed in the main script. The port is hard-coded in `send_email`. Authentication or TLS requires code changes. There are no supported SMTP CLI flags or environment-variable settings in the current implementation.

Sending requires network access and relay permission on the configured SMTP server. Successful SMTP submission is not proof of inbox delivery. The current helper also does not inspect the refusal dictionary returned by `sendmail`, so its success message does not prove acceptance for every recipient.

The helper supports CC internally, but the main script does not expose a CC argument. Running `email_notification.py` directly executes its test function, creates `test.txt`, and attempts to email its hard-coded test recipients.

## Translation

English is the default. Chinese, Japanese, and Korean output uses predefined translated headers and Yes/No values. CVE descriptions are translated using `GoogleTranslator` from `deep-translator`.

Other content, such as advisory titles and restart classifications, is not systematically translated. Repeated descriptions are translated once per run. Failed description translations retain the original text. An outer translation error is logged and report generation continues with the content available at that point.

Although `MyMemoryTranslator` is imported, the current translation workflow does not use it as a fallback.

## Troubleshooting and limitations

| Symptom | What to check |
|---|---|
| Missing Python module | Activate the virtual environment and install the listed dependencies. |
| Email helper import error | Keep `email_notification.py` alongside the main script; inspect missing dependencies or import errors. |
| Input-source error | Choose exactly one input method; provide both explicit dates when using dates. |
| Product/version validation error | Use a supported product alias and supply `--product` with `--product-version`. |
| No advisories or matching rows | Review date, advisory severity, product, and version filters. Version matching is text-based. |
| Input file missing or unreadable | Check the path, permissions, file format, worksheet, and advisory-ID column. |
| Excel write failure | Check the destination directory, permissions, file extension, and whether another application locks the file. |
| API/network errors | Check access to Red Hat and review logged failures. |
| English descriptions in translated output | Check translation service access; failed translations retain the original. |
| SMTP failure | Check server reachability, port 25 access, relay policy, and configured sender. |
| Email reports success but is absent | Check all recipients, spam/quarantine, and SMTP delivery logs; submission is not delivery confirmation. |

For more detail:

```bash
python RHSA_report.py --period month --debug --log-file rhsa-debug.log
```

The main script's log file captures messages sent through its logging helper. Progress bars and the email helper's direct printed errors are not necessarily included.

Additional behavior to account for:

- Up to 50 advisories are processed concurrently. Individual CVE requests are not cached across advisories.
- Connection errors and timeouts are retried up to four attempts with backoff; each request has a 20-second timeout. Other HTTP failures are not retried by that helper.
- Advisory-list retrieval can stop after a failed page, leaving only earlier pages. Failed advisory requests and per-advisory processing exceptions can skip entries while other work continues.
- Missing CVE data can leave `None` values and default low scores. A saved report is not a guarantee of complete data.
- Input advisory IDs are not explicitly deduplicated or fully validated.
- The printed total CVE count is the number of report rows, including any placeholder rows; unique CVE counts can include placeholder strings.
- Empty input/results cause an exit with status 0 and no report. Several validation, writing, and email failures exit with status 1. Some individual failures are logged without making the whole run fail.
- Product/version matching, restart policy, and custom scoring require review before using the report to make operational patching decisions.

Documentation was checked against the inspected source. Report generation, external service access, translation, and email delivery were not executed as part of documentation preparation.
