import json
import os
from dotenv import load_dotenv
import requests
from packaging import version
from packaging.version import InvalidVersion
from datetime import datetime, timezone, timedelta
import pandas as pd
import re

# ==========================================
# CONFIGURATION
# ==========================================
load_dotenv()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") 

PACKAGES_TO_PROCESS =packages = [
    # Frontend, UI und Bibliotheken
    "@angular/common",
    "@angular/platform-browser",
    "@angular/compiler",
    "vue-router",
    "vuex",
    "pinia",
    "@vue/compiler-sfc",
    "preact",
    "solid-js",
    "lit",
    "ember-source",
    "backbone",
    "d3",
    "three",
    "chart.js",
    "leaflet",
    "ckeditor",
    "tinymce",
    "quill",
    "codemirror",
    "monaco-editor",
    "prismjs",
    "katex",
    "mathjs",
    "xss",
    "js-beautify",
    "uglify-js",
    "bowser",
    "ua-parser-js",

    # Build-Tools und Tooling
    "react-scripts",
    "react-dev-utils",
    "webpack-cli",
    "webpack-dev-middleware",
    "terser",
    "terser-webpack-plugin",
    "css-loader",
    "style-loader",
    "babel-loader",
    "loader-utils",
    "ts-node",
    "ts-jest",
    "tsup",
    "turbo",
    "nx",
    "lerna",
    "node-gyp",
    "storybook",
    "browserify",
    "gulp",
    "grunt",
    "parcel",

    # Parsing, Templates und Datenformate
    "mustache",
    "lodash.template",
    "lodash.merge",
    "lodash-es",
    "@xmldom/xmldom",
    "xmldom",
    "libxmljs",
    "json5",
    "jsonpath",
    "jsonpath-plus",
    "flat",
    "toml",
    "ini",
    "papaparse",
    "csv-parse",
    "xlsx",
    "exceljs",
    "protobufjs",
    "nth-check",
    "css-what",
    "postcss-selector-parser",
    "decode-uri-component",
    "semver-regex",
    "ansi-regex",
    "trim-newlines",
    "normalize-url",
    "word-wrap",
    "y18n",
    "hosted-git-info",
    "get-func-name",
    "tmpl",

    # Prototype-Pollution-anfällige Utilities
    "kind-of",
    "set-value",
    "mixin-deep",
    "union-value",
    "unset-value",
    "object-path",
    "dot-prop",
    "deep-extend",
    "merge",
    "merge-deep",
    "defaults-deep",
    "getobject",
    "object-assign",
    "fast-json-patch",

    # HTTP-Clients und Netzwerk
    "request",
    "request-promise",
    "superagent",
    "needle",
    "ky",
    "cross-fetch",
    "isomorphic-fetch",
    "http-cache-semantics",
    "xmlhttprequest-ssl",
    "socket.io-client",
    "engine.io-client",
    "ip",
    "netmask",
    "pac-resolver",
    "degenerator",
    "@grpc/grpc-js",
    "mqtt",
    "kafkajs",
    "amqplib",

    # Security, Crypto und Auth
    "node-jose",
    "jsrsasign",
    "jwa",
    "jwk-to-pem",
    "passport-jwt",
    "oauth",
    "simple-oauth2",
    "openid-client",
    "openpgp",
    "pem",
    "sshpk",
    "ssh2",
    "tweetnacl",
    "pbkdf2",
    "md5",
    "sha.js",
    "create-hash",
    "bn.js",
    "asn1.js",
    "browserify-sign",
    "crypto-browserify",
    "class-validator",
    "class-transformer",

    # Sandbox, Shell und Prozesse
    "vm2",
    "safe-eval",
    "shelljs",
    "systeminformation",
    "node-serialize",
    "node-ipc",
    "dockerode",
    "docker-modem",
    "@kubernetes/client-node",

    # Datenbanken
    "mssql",
    "tedious",
    "oracledb",
    "cassandra-driver",
    "neo4j-driver",
    "@elastic/elasticsearch",
    "nedb",
    "lowdb",
    "bookshelf",
    "objection",
    "drizzle-orm",
    "kysely",

    # Dateien, Archive und Medien
    "archiver",
    "decompress",
    "extract-zip",
    "yauzl",
    "tar-stream",
    "pdfkit",
    "pdf-lib",
    "jimp",
    "canvas",
    "gm",
    "fluent-ffmpeg",

    # Cloud, Services und Messaging
    "aws-sdk",
    "@aws-sdk/client-s3",
    "firebase",
    "firebase-admin",
    "googleapis",
    "@google-cloud/storage",
    "stripe",
    "twilio",
    "@sendgrid/mail",
    "@slack/web-api",
    "discord.js",
    "telegraf",
    "serverless",
    "aws-cdk-lib",
    "bull",
    "bullmq",
    "agenda",
    "node-cron",
    "node-schedule",

    # Logging
    "log4js",
    "bunyan",

    # Testing
    "karma",
    "jasmine",
    "sinon",
    "nock",
    "puppeteer-core",
    "selenium-webdriver",
    "webdriverio",
    "ava",
    "tap",

    # Package-Management und Registry
    "npm",
    "pacote",
    "npm-registry-fetch",
    "cacache",
    "ssri",
    "minipass",

    # Kleine, weit verbreitete Hilfspakete
    "ansi-styles",
    "color-convert",
    "color-string",
    "colors",
    "kleur",
    "picocolors",
    "faker",
    "event-stream",
    "reflect-metadata",
]


# ==========================================
# FUNCTIONS
# ==========================================
def del_duplicates(json_data):
    return [
        item for item in json_data if not item.get("summary", "").lower().startswith("duplicate")]

def get_month_map():
    """
    Maps YYYY-MM strings to M0-M11 schema labels.
    """
    return {
        '2026-06': 'M0', '2026-05': 'M1', '2026-04': 'M2', '2026-03': 'M3',
        '2026-02': 'M4', '2026-01': 'M5', '2025-12': 'M6', '2025-11': 'M7',
        '2025-10': 'M8', '2025-09': 'M9', '2025-08': 'M10', '2025-07': 'M11'
    }

def get_month_end_dates():
    """
    Returns the exact end-exclusive boundary datetime for each month.
    Needed to calculate "open_at_month_end".
    """
    return {
        'M0': datetime(2026, 7, 1, tzinfo=timezone.utc),
        'M1': datetime(2026, 6, 1, tzinfo=timezone.utc),
        'M2': datetime(2026, 5, 1, tzinfo=timezone.utc),
        'M3': datetime(2026, 4, 1, tzinfo=timezone.utc),
        'M4': datetime(2026, 3, 1, tzinfo=timezone.utc),
        'M5': datetime(2026, 2, 1, tzinfo=timezone.utc),
        'M6': datetime(2026, 1, 1, tzinfo=timezone.utc),
        'M7': datetime(2025, 12, 1, tzinfo=timezone.utc),
        'M8': datetime(2025, 11, 1, tzinfo=timezone.utc),
        'M9': datetime(2025, 10, 1, tzinfo=timezone.utc),
        'M10': datetime(2025, 9, 1, tzinfo=timezone.utc),
        'M11': datetime(2025, 8, 1, tzinfo=timezone.utc)
    }

def get_download_data(package_name):
    """Fetches daily npm downloads and aggregates them into monthly buckets."""
    url = f"https://api.npmjs.org/downloads/range/2025-07-01:2026-06-30/{package_name}"
    response = requests.get(url)
    downloads_data = {f"package_downloads_M{i}": 0 for i in range(12)}
    downloads_data.update({f"package_download_days_observed_M{i}": 0 for i in range(12)})
    
    if response.status_code != 200: 
        return downloads_data
    
    month_map = get_month_map()
    
    for daily_record in response.json().get('downloads', []):
        year_month = daily_record.get('day', '')[:7]
        if year_month in month_map:
            m_label = month_map[year_month]
            downloads_data[f"package_downloads_{m_label}"] += daily_record.get('downloads', 0)
            downloads_data[f"package_download_days_observed_{m_label}"] += 1
            
    return downloads_data

def get_vulnerabilities_raw(package_name):
    """
    Queries the native GitHub Advisories API.
    """
    url = f"https://api.github.com/advisories?ecosystem=npm&affects={package_name}&per_page=100"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
        
    extracted_vulns = []
    
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200: 
            break
            
        advisories = del_duplicates(response.json())
        for adv in advisories:
            vuln_id = adv.get("ghsa_id", "")
            if not vuln_id: continue
            
            severity = adv.get("severity", "unknown").upper()
            extracted_vulns.append({
                "id": vuln_id, 
                "published": adv.get("published_at"), 
                "severity": severity
            })
            
        if 'next' in response.links:
            url = response.links['next']['url']
        else:
            url = None
            
    return extracted_vulns

def assign_vulnerability_data(vulns, published_at_str):
    """Calculates historical, target (90d), and monthly GHSAs for a specific version."""
    severities = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL', 'UNKNOWN']
    valid_severities = {'low', 'moderate', 'high', 'critical'}
    api_to_schema = {'medium': 'moderate'}
      # Skip duplicate advisories
    vuln_data = {}
    for sev in severities:
        s_lower = sev.lower()
        vuln_data[f"ghsa_{s_lower}_count"] = 0
        vuln_data[f"target_ghsa_{s_lower}_count_90d"] = 0
        for i in range(12):
            vuln_data[f"ghsa_{s_lower}_count_M{i}"] = 0

    if not published_at_str: return vuln_data

    try:
        start="2026-07-01T00:00:00+00:00"
        prediction_date = datetime.fromisoformat(start.replace('Z', '+00:00'))
    except Exception:
        return vuln_data

    target_end_date = prediction_date + timedelta(days=90)
    boundary_date = datetime.fromisoformat("2026-07-01T00:00:00+00:00")
    month_map = get_month_map()

    for v in vulns:
        pub_date_str = v.get("published")
        if not pub_date_str: continue
        try:
            v_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
        except Exception: continue

        sev = (v.get("severity") or "unknown").lower()
        sev = api_to_schema.get(sev, sev)          # medium -> moderate
        if sev not in valid_severities: sev = 'unknown'

        if prediction_date <= v_date <= target_end_date:
            vuln_data[f"target_ghsa_{sev}_count_90d"] += 1

        if v_date < boundary_date:
            vuln_data[f"ghsa_{sev}_count"] += 1

        year_month = v_date.strftime("%Y-%m")
        if year_month in month_map:
            vuln_data[f"ghsa_{sev}_count_{month_map[year_month]}"] += 1

    return vuln_data

def extract_github_owner_repo(npm_metadata):
    """Extracts GitHub owner/repo string from npm metadata."""
    repo_info = npm_metadata.get('repository', {})
    url = repo_info.get('url', '')
    if not url: return None
    match = re.search(r'github\.com/([^/]+)/([^/\.]+)', url)
    if match: return f"{match.group(1)}/{match.group(2)}"
    return None

def get_github_metrics(owner_repo):
    """
    Fetches issues/PRs and calculates opened, closed, merged, 
    and open_at_month_end metrics.
    """
    metrics = {}
    for i in range(12):
        metrics[f"issues_opened_M{i}"] = 0
        metrics[f"issues_closed_M{i}"] = 0
        metrics[f"issues_reopened_M{i}"] = None
        metrics[f"pull_requests_opened_M{i}"] = 0
        metrics[f"pull_requests_closed_unmerged_M{i}"] = 0
        metrics[f"pull_requests_merged_M{i}"] = 0
        metrics[f"pull_requests_reopened_M{i}"] = None
        metrics[f"issues_open_at_month_end_M{i}"] = 0
        metrics[f"pull_requests_open_at_month_end_M{i}"] = 0

    if not GITHUB_TOKEN or not owner_repo: return metrics

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    month_map = get_month_map()
    month_ends = get_month_end_dates()
    
    url = f"https://api.github.com/repos/{owner_repo}/issues?state=all&since=2025-07-01T00:00:00Z&per_page=100"
    
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200: break
            
        issues = response.json()
        for item in issues:
            is_pr = 'pull_request' in item
            
            created_str = item.get('created_at', '')
            closed_str = item.get('closed_at')
            
            created_month = created_str[:7]
            
            # Opened metrics
            if created_month in month_map:
                m_label = month_map[created_month]
                if is_pr: metrics[f"pull_requests_opened_{m_label}"] += 1
                else: metrics[f"issues_opened_{m_label}"] += 1
                    
            # Closed / Merged metrics
            if closed_str:
                closed_month = closed_str[:7]
                if closed_month in month_map:
                    m_label = month_map[closed_month]
                    if is_pr:
                        if item.get('pull_request', {}).get('merged_at'):
                            metrics[f"pull_requests_merged_{m_label}"] += 1
                        else:
                            metrics[f"pull_requests_closed_unmerged_{m_label}"] += 1
                    else:
                        metrics[f"issues_closed_{m_label}"] += 1

            # Open at Month End Logic
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                closed_dt = datetime.fromisoformat(closed_str.replace('Z', '+00:00')) if closed_str else None
                
                for m_label, m_end_date in month_ends.items():
                    # An Issue/PR is considered open at the end of the month if it was created before the end date...
                    if created_dt < m_end_date:
                        # ...and it either has not been closed yet, or it was closed AFTER the end of the month.
                        if not closed_dt or closed_dt >= m_end_date:
                            if is_pr: metrics[f"pull_requests_open_at_month_end_{m_label}"] += 1
                            else: metrics[f"issues_open_at_month_end_{m_label}"] += 1
            except Exception:
                pass

        if 'next' in response.links: url = response.links['next']['url']
        else: url = None
            
    return metrics

def get_package_versions_records(package_name):
    """Main orchestration: generates records for all stable versions in the 12-month window."""
    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url)
    if response.status_code != 200: return []
        
    data = response.json()
    time_data = data.get('time', {})
    all_versions = data.get('versions', {})
    
    valid_versions = []
    month_map = get_month_map()
    
    for v_name, pub_time in time_data.items():
        if v_name in ['created', 'modified']: continue
        pub_month = pub_time[:7]
        if pub_month in month_map:
            try:
                parsed_v = version.parse(v_name)
                if not parsed_v.is_prerelease: valid_versions.append(v_name)
            except InvalidVersion: continue
                
    if not valid_versions: return []
    
    downloads_data = get_download_data(package_name)
    
    release_counts = {f"package_stable_release_count_M{i}": 0 for i in range(12)}
    for v_name, pub_time in time_data.items():
        if v_name in ['created', 'modified']: continue
        pub_month = pub_time[:7]
        if pub_month in month_map:
            try:
                if not version.parse(v_name).is_prerelease:
                    release_counts[f"package_stable_release_count_{month_map[pub_month]}"] += 1
            except InvalidVersion: continue
            
    owner_repo = extract_github_owner_repo(data)
    github_data = get_github_metrics(owner_repo)
    raw_vulns = get_vulnerabilities_raw(package_name)
    
    records = []
    for v_name in valid_versions:
        version_data = all_versions.get(v_name, {})
        dist_data = version_data.get('dist', {})
        
        def count_deps(dep_dict): return len(dep_dict) if isinstance(dep_dict, dict) else 0
        bundled_deps = version_data.get('bundleDependencies') or version_data.get('bundledDependencies')
        
        record = {
            "purl": f"pkg:npm/{package_name}@{v_name}",
            "package_created_at": time_data.get('created'),
            "published_at": time_data.get(v_name),
            "unpacked_size": dist_data.get('unpackedSize'),
            "file_count": dist_data.get('fileCount'),
            "dependency_count": count_deps(version_data.get('dependencies')),
            "optional_dependency_count": count_deps(version_data.get('optionalDependencies')),
            "peer_dependency_count": count_deps(version_data.get('peerDependencies')),
            "dev_dependency_count": count_deps(version_data.get('devDependencies')),
            "bundled_dependency_count": len(bundled_deps) if isinstance(bundled_deps, list) else 0
        }
        
        record.update(downloads_data)
        record.update(release_counts)
        record.update(github_data)
            
        record.update(assign_vulnerability_data(raw_vulns, time_data.get(v_name)))
        
        records.append(record)
        
    return records

if __name__ == "__main__":
    output_filename = "training_data.csv"

    # Bereits gespeicherte Paketversionen laden, damit keine Duplikate entstehen.
    existing_purls = set()
    if os.path.exists(output_filename) and os.path.getsize(output_filename) > 0:
        existing_purls = set(
            pd.read_csv(output_filename, usecols=["purl"])["purl"].dropna().astype(str)
        )

    total_added = 0
    total_skipped = 0

    for pkg in PACKAGES_TO_PROCESS:
        print(f"\nProcessing package: {pkg}...")

        try:
            # Immer nur ein Paket auf einmal verarbeiten.
            package_records = get_package_versions_records(pkg)

            new_records = []
            for record in package_records:
                purl = record["purl"]

                if purl in existing_purls:
                    total_skipped += 1
                    continue

                new_records.append(record)
                existing_purls.add(purl)

            # Direkt nach der Verarbeitung dieses Pakets in die CSV schreiben.
            if new_records:
                file_has_content = (
                    os.path.exists(output_filename)
                    and os.path.getsize(output_filename) > 0
                )

                pd.DataFrame(new_records).to_csv(
                    output_filename,
                    mode="a",
                    header=not file_has_content,
                    index=False
                )

                total_added += len(new_records)
                print(
                    f"Saved {len(new_records)} new records for '{pkg}' "
                    f"to {output_filename}."
                )
            else:
                print(f"No new records for '{pkg}'.")

        except Exception as e:
            # Fehler in einem Paket stoppen nicht die Verarbeitung der übrigen Pakete.
            print(f"Error while processing '{pkg}': {e}")
            continue

    print(
        f"\nFinished! Added {total_added} new records to {output_filename}; "
        f"skipped {total_skipped} existing records."
    )
