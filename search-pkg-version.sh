#!/bin/bash
#
# Search npm package versions in odf-console yarn.lock across git branches.
# Also supports CVE impact analysis using cve-package-fixes.json.
#
# Examples:
#   ./search-pkg-version.sh react-router master release-4.22 release-4.21
#   ./search-pkg-version.sh --fix 7.12.0 react-router master release-4.22
#   ./search-pkg-version.sh --cve CVE-2026-6321,CVE-2026-6322 master release-4.22
#   ./search-pkg-version.sh --cve-file cves.txt master release-4.22
#   ./search-pkg-version.sh --csv fast-uri master release-4.22
#   ./search-pkg-version.sh --json postcss-selector-parser master release-4.22

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/odf-console"
REMOTE="upstream"
CVE_DB="${SCRIPT_DIR}/cve-package-fixes.json"
OUTPUT_FORMAT="human"
MODE="package"
FIX_VERSION=""
CVE_IDS=()
CVE_FILE=""
BRANCHES=()
PACKAGE=""

usage() {
    cat <<'EOF'
Usage:
  search-pkg-version.sh [options] PACKAGE branch1 [branch2 ...]
  search-pkg-version.sh [options] --cve CVE1,CVE2 branch1 [branch2 ...]
  search-pkg-version.sh [options] --cve-file FILE branch1 [branch2 ...]

Options:
  --repo PATH         Path to git repo (default: ./odf-console next to script)
  --remote NAME       Git remote for branches (default: upstream)
  --cve-db PATH       CVE rules JSON (default: ./cve-package-fixes.json)
  --cve ID[,ID...]     Analyze listed CVEs
  --cve-file FILE     CVE list (one per line, or CVE IDs anywhere on the line)
  --fix VERSION       Mark versions below VERSION as vulnerable (package mode)
  --csv               CSV output
  --json              JSON output
  -h, --help          Show this help

Package mode prints every unique version of a package found in yarn.lock.
CVE mode prints an impact table per CVE across all listed branches.
EOF
}

log() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        echo "$@"
    fi
}

semver_lt() {
    local a=$1 b=$2
    [ "$a" != "$b" ] && [ "$(printf '%s\n%s' "$a" "$b" | sort -V | head -1)" = "$a" ]
}

semver_gte() {
    local a=$1 b=$2
    ! semver_lt "$a" "$b"
}

semver_in_range() {
    local version=$1 min=$2 max_ex=$3 line_max_ex=${4:-}
    if [ -n "$line_max_ex" ] && semver_gte "$version" "$line_max_ex"; then
        return 1
    fi
    semver_gte "$version" "$min" && semver_lt "$version" "$max_ex"
}

extract_versions_yarn4() {
    local lock=$1 pkg=$2
    printf '%s\n' "$lock" | grep -E "resolution: \"${pkg}@npm:" \
        | sed -E "s/.*${pkg}@npm:([^\"]+)\".*/\1/" \
        | sort -Vu
}

extract_versions_yarn1() {
    local lock=$1 pkg=$2
    printf '%s\n' "$lock" | awk -v pkg="$pkg" '
        /^[^ #[:space:]].*@/ { in_block = 0 }
        $0 ~ "^" pkg "@" { in_block = 1; next }
        in_block && /^  version / {
            gsub(/^  version "/, "")
            gsub(/".*$/, "")
            print
            in_block = 0
        }
    ' | sort -Vu
}

extract_all_versions() {
    local branch=$1 pkg=$2
    local lock versions v4_versions v1_versions

    if ! lock=$(git -C "$REPO_DIR" show "${REMOTE}/${branch}:yarn.lock" 2>/dev/null); then
        echo "__MISSING_LOCKFILE__"
        return
    fi

    v4_versions=$(extract_versions_yarn4 "$lock" "$pkg" || true)
    v1_versions=$(extract_versions_yarn1 "$lock" "$pkg" || true)

    versions=$(printf '%s\n%s\n' "$v4_versions" "$v1_versions" | sed '/^$/d' | sort -Vu)
    if [ -z "$versions" ]; then
        echo "__NOT_FOUND__"
    else
        printf '%s\n' "$versions"
    fi
}

versions_join() {
    local IFS=', '
    echo "$*"
}

read_lines_to_array() {
    local __resultvar=$1
    shift
    local _output _line
    local -a _lines=()
    _output=$("$@")
    while IFS= read -r _line; do
        [ -n "$_line" ] && _lines+=("$_line")
    done <<EOF
$_output
EOF
    eval "$__resultvar=(\"\${_lines[@]}\")"
}

print_package_human() {
    local branch=$1 pkg=$2
    shift 2
    local versions=("$@")

    echo "==================================="
    echo "Branch: $branch"
    echo "==================================="

    if [ ${#versions[@]} -eq 0 ] || [ "${versions[0]}" = "__NOT_FOUND__" ]; then
        echo "✗ Package not found"
        echo ""
        return
    fi
    if [ "${versions[0]}" = "__MISSING_LOCKFILE__" ]; then
        echo "✗ yarn.lock not found on ${REMOTE}/${branch}"
        echo ""
        return
    fi

    if [ ${#versions[@]} -eq 1 ]; then
        echo "✓ Version: ${versions[0]}"
    else
        echo "✓ Versions (${#versions[@]} unique entries in yarn.lock):"
        for v in "${versions[@]}"; do
            echo "  - $v"
        done
        echo "  → highest: $(printf '%s\n' "${versions[@]}" | sort -V | tail -1)"
        echo "  → lowest:  $(printf '%s\n' "${versions[@]}" | sort -V | head -1)"
    fi

    if [ -n "$FIX_VERSION" ]; then
        local worst
        worst=$(printf '%s\n' "${versions[@]}" | sort -V | head -1)
        if semver_lt "$worst" "$FIX_VERSION"; then
            echo "⚠ VULNERABLE: at least one version < fix $FIX_VERSION"
        else
            echo "✓ OK: all versions >= fix $FIX_VERSION"
        fi
    fi
    echo ""
}

print_package_csv_header() {
    echo "branch,package,status,versions,count,highest,lowest,fix_version"
}

print_package_csv_row() {
    local branch=$1 pkg=$2
    shift 2
    local versions=("$@")
    local status count highest lowest joined

    if [ ${#versions[@]} -eq 0 ] || [ "${versions[0]}" = "__NOT_FOUND__" ]; then
        echo "$branch,$pkg,not_found,,0,,,$FIX_VERSION"
        return
    fi
    if [ "${versions[0]}" = "__MISSING_LOCKFILE__" ]; then
        echo "$branch,$pkg,missing_lockfile,,0,,,$FIX_VERSION"
        return
    fi

    joined=$(printf '%s|' "${versions[@]}" | sed 's/|$//')
    count=${#versions[@]}
    highest=$(printf '%s\n' "${versions[@]}" | sort -V | tail -1)
    lowest=$(printf '%s\n' "${versions[@]}" | sort -V | head -1)

    if [ -n "$FIX_VERSION" ] && semver_lt "$lowest" "$FIX_VERSION"; then
        status="vulnerable"
    else
        status="ok"
    fi
    echo "$branch,$pkg,$status,\"$joined\",$count,$highest,$lowest,$FIX_VERSION"
}

run_package_mode() {
    local -a versions
    local json_branches=()

    if [ "$OUTPUT_FORMAT" = "csv" ]; then
        print_package_csv_header
    elif [ "$OUTPUT_FORMAT" = "json" ]; then
        json_branches=()
    else
        log "Checking package: $PACKAGE"
        log "Remote: ${REMOTE} | Repo: ${REPO_DIR}"
        [ -n "$FIX_VERSION" ] && log "Fix version threshold: >= $FIX_VERSION"
        log ""
    fi

    for branch in "${BRANCHES[@]}"; do
        read_lines_to_array versions extract_all_versions "$branch" "$PACKAGE"

        case "$OUTPUT_FORMAT" in
            csv)
                print_package_csv_row "$branch" "$PACKAGE" "${versions[@]}"
                ;;
            json)
                joined=$(printf '%s\n' "${versions[@]}" | sed '/^$/d')
                if [ -z "$joined" ]; then
                    json_branches+=("{\"branch\":\"$branch\",\"status\":\"not_found\",\"versions\":[]}")
                elif [ "${versions[0]}" = "__MISSING_LOCKFILE__" ]; then
                    json_branches+=("{\"branch\":\"$branch\",\"status\":\"missing_lockfile\",\"versions\":[]}")
                else
                    ver_json=$(printf '%s\n' "${versions[@]}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
                    json_branches+=("{\"branch\":\"$branch\",\"status\":\"found\",\"versions\":${ver_json}}")
                fi
                ;;
            *)
                print_package_human "$branch" "$PACKAGE" "${versions[@]}"
                ;;
        esac
    done

    if [ "$OUTPUT_FORMAT" = "json" ]; then
        printf '{"package":"%s","fix_version":%s,"remote":"%s","branches":[%s]}\n' \
            "$PACKAGE" \
            "$( [ -n "$FIX_VERSION" ] && echo "\"$FIX_VERSION\"" || echo null )" \
            "$REMOTE" \
            "$(IFS=,; echo "${json_branches[*]}")"
    fi
}

run_cve_mode() {
  python3 - "$SCRIPT_DIR" "$CVE_DB" "$REMOTE" "$REPO_DIR" "$OUTPUT_FORMAT" "$(printf '%s,' "${CVE_IDS[@]}")" "$(printf '%s,' "${BRANCHES[@]}")" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path

script_dir, db_path, remote, repo_dir, output_format, cves_csv, branches_csv = sys.argv[1:8]
cves = [c for c in cves_csv.split(",") if c]
branches = [b for b in branches_csv.split(",") if b]

PACKAGE_ALIASES = {
    "node-tar": "tar",
    "minimatch": "minimatch",
    "immutable.js": "immutable",
    "immutable": "immutable",
}

def load_json(path):
    p = Path(path)
    return json.loads(p.read_text()) if p.is_file() else {}

def extract_package_from_summary(summary):
    if not summary:
        return None
    m = re.search(r"odf-console-rhel9:\s*([^:]+):", summary, re.I)
    if m:
        name = m.group(1).strip().lower()
        return PACKAGE_ALIASES.get(name, name)
    m = re.search(r"\bin\s+(immutable)\b", summary, re.I)
    if m:
        return "immutable"
    return None

def parse_fix_version(fix_str):
    if not fix_str:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", str(fix_str))
    return m.group(1) if m else None

def make_simple_rules(fix_version):
    if not fix_version:
        return [], ""
    return [{
        "affected_min": "0.0.0",
        "affected_max_exclusive": fix_version,
        "fix": fix_version,
    }], fix_version

def load_merged_db():
    data = load_json(db_path)
    pkg_map = load_json(Path(script_dir) / "cve_to_package_mapping.json")
    defaults = load_json(Path(script_dir) / "cve-package-defaults.json")
    all_cve = load_json(Path(script_dir) / "all_cve_data.json")

    for cve, pkg in pkg_map.items():
        if pkg in ("unknown", "?", ""):
            continue
        if cve not in data:
            fix = defaults.get(pkg)
            rules, recommended = make_simple_rules(fix)
            data[cve] = {
                "package": pkg,
                "description": f"From cve_to_package_mapping.json",
                "rules": rules,
                "recommended_fix": recommended or "add to cve-package-fixes.json",
                "source": "package_mapping",
            }
        elif "package" not in data[cve]:
            data[cve]["package"] = pkg

    for cve, info in all_cve.items():
        if cve in data and data[cve].get("package"):
            continue
        pkg = extract_package_from_summary(info.get("summary", ""))
        if not pkg:
            continue
        fix = defaults.get(pkg)
        rules, recommended = make_simple_rules(fix)
        data[cve] = {
            "package": pkg,
            "description": info.get("summary", "")[:120],
            "rules": rules,
            "recommended_fix": recommended or "add to cve-package-fixes.json",
            "source": "all_cve_data",
        }

    return data

data = load_merged_db()

def parse(v):
    parts = []
    for p in v.split("."):
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num or 0))
    return parts

def lt(a, b):
    return parse(a) < parse(b)

def gte(a, b):
    return not lt(a, b)

def extract_versions(branch, package):
    ref = f"{remote}/{branch}:yarn.lock"
    try:
        lock = subprocess.check_output(
            ["git", "-C", repo_dir, "show", ref],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError:
        return "missing_lockfile", []

    versions = set()
    for line in lock.splitlines():
        marker = f'resolution: "{package}@npm:'
        if marker in line:
            versions.add(line.split(f"{package}@npm:")[1].split('"')[0])

    pkg = package
    in_block = False
    for line in lock.splitlines():
        if line and not line.startswith(" "):
            in_block = line.startswith(f"{pkg}@")
        elif in_block and line.strip().startswith('version "'):
            versions.add(line.split('"')[1])
            in_block = False

    if not versions:
        return "not_found", []
    return "found", sorted(versions, key=parse)

def assess(version, rules):
    for rule in rules:
        amin = rule["affected_min"]
        amax = rule["affected_max_exclusive"]
        line_max = rule.get("line_max_exclusive")
        if gte(version, amin) and lt(version, amax):
            if line_max is None or lt(version, line_max):
                return True, rule.get("fix", "")
    return False, ""

rows = []
for cve in cves:
    entry = data.get(cve)
    if not entry:
        rows.append({
            "cve": cve, "package": "?", "status": "unknown_cve",
            "branches_needing_fix": [], "recommended_fix": "",
            "description": "Not in cve-package-fixes.json or mapping files",
            "has_rules": False,
        })
        continue

    pkg = entry.get("package", "?")
    rules = entry.get("rules", [])
    recommended = entry.get("recommended_fix", "")
    description = entry.get("description", "")
    has_rules = bool(rules)
    branches_needing_fix = []
    branches_with_package = []

    if pkg in ("?", "unknown", ""):
        status = "no_package_mapping"
    elif not has_rules:
        status = "needs_fix_version"
        for branch in branches:
            st, versions = extract_versions(branch, pkg)
            if st == "found":
                branches_with_package.append(branch)
    else:
        for branch in branches:
            st, versions = extract_versions(branch, pkg)
            if st != "found":
                continue
            branches_with_package.append(branch)
            if any(assess(v, rules)[0] for v in versions):
                branches_needing_fix.append(branch)
        status = "action_needed" if branches_needing_fix else "clear_or_not_present"

    rows.append({
        "cve": cve,
        "package": pkg,
        "description": description,
        "recommended_fix": recommended,
        "branches_needing_fix": branches_needing_fix,
        "branches_with_package": branches_with_package,
        "status": status,
        "has_rules": has_rules,
    })

if output_format == "json":
    print(json.dumps(rows, indent=2))
    sys.exit(0)

if output_format == "csv":
    print("cve,package,recommended_fix,branches_needing_fix,status,description")
    for r in rows:
        branches_s = "|".join(r["branches_needing_fix"])
        desc = r.get("description", "").replace(",", ";")
        print(f'{r["cve"]},{r["package"]},{r["recommended_fix"]},"{branches_s}",{r["status"]},"{desc}"')
    sys.exit(0)

mapped = sum(1 for r in rows if r["package"] not in ("?", ""))
with_rules = sum(1 for r in rows if r.get("has_rules"))
print("CVE Impact Report")
print(f"Remote: {remote} | Repo: {repo_dir}")
print(f"CVEs requested: {len(cves)} | package mapped: {mapped} | with fix rules: {with_rules}")
if len(cves) != len(set(cves)):
    print(f"Note: duplicate CVE IDs in input were de-duplicated")
print("")
print(f"{'CVE':<18} {'Package':<24} {'Fix':<20} {'Status':<22} {'Branches needing fix'}")
print("-" * 120)
for r in rows:
    if r["status"] == "unknown_cve":
        branches_s = "(add to cve_to_package_mapping.json)"
    elif r["status"] == "no_package_mapping":
        branches_s = "(no npm package mapped)"
    elif r["status"] == "needs_fix_version":
        branches_s = f"present in: {', '.join(r['branches_with_package']) or 'none'}"
    elif r["branches_needing_fix"]:
        branches_s = ", ".join(r["branches_needing_fix"])
    else:
        branches_s = "(none / not in tree / already fixed)"
    fix = (r["recommended_fix"] or "")[:20]
    print(f'{r["cve"]:<18} {r["package"]:<24} {fix:<20} {r["status"]:<22} {branches_s}')
print("")
print("Per-branch detail")
print("=" * 120)
for cve in cves:
    entry = data.get(cve)
    row = next((r for r in rows if r["cve"] == cve), None)
    if not entry:
        print(f"\n{cve} — UNKNOWN (not in any mapping file)")
        print("  Add package mapping to cve_to_package_mapping.json or cve-package-fixes.json")
        continue
    pkg = entry.get("package", "?")
    rules = entry.get("rules", [])
    print(f"\n{cve} — {pkg} (fix: {entry.get('recommended_fix', 'TBD')}) [{row['status'] if row else ''}]")
    desc = entry.get("description", "")
    if desc:
        print(f"  {desc[:140]}")
    if pkg in ("?", "unknown", ""):
        continue
    if not rules:
        print("  ⚠ No semver rules — showing installed versions only")
    for branch in branches:
        status, versions = extract_versions(branch, pkg)
        if status == "missing_lockfile":
            print(f"  {branch:<16} yarn.lock missing")
        elif status == "not_found":
            print(f"  {branch:<16} package not in tree")
        elif not rules:
            print(f"  {branch:<16} FOUND       versions={', '.join(versions)}")
        else:
            vuln = [v for v in versions if assess(v, rules)[0]]
            if vuln:
                print(f"  {branch:<16} VULNERABLE  versions={', '.join(versions)}  affected={', '.join(vuln)}")
            else:
                print(f"  {branch:<16} OK          versions={', '.join(versions)}")
PY
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)
            REPO_DIR=$2
            shift 2
            ;;
        --remote)
            REMOTE=$2
            shift 2
            ;;
        --cve-db)
            CVE_DB=$2
            shift 2
            ;;
        --cve)
            MODE="cve"
            IFS=',' read -r -a CVE_IDS <<< "$2"
            shift 2
            ;;
        --cve-file)
            MODE="cve"
            CVE_FILE=$2
            shift 2
            ;;
        --fix)
            FIX_VERSION=$2
            shift 2
            ;;
        --csv)
            OUTPUT_FORMAT="csv"
            shift
            ;;
        --json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ "$MODE" = "package" ] && [ -z "$PACKAGE" ]; then
                PACKAGE=$1
            else
                BRANCHES+=("$1")
            fi
            shift
            ;;
    esac
done

if [ -n "$CVE_FILE" ]; then
    if [ ! -f "$CVE_FILE" ] && [ -f "${SCRIPT_DIR}/${CVE_FILE}" ]; then
        CVE_FILE="${SCRIPT_DIR}/${CVE_FILE}"
    fi
    if [ ! -f "$CVE_FILE" ]; then
        echo "Error: CVE file not found: $CVE_FILE" >&2
        exit 1
    fi
    CVE_IDS=()
    _cve_lines=$(grep -oE 'CVE-[0-9]{4}-[0-9]+' "$CVE_FILE" | sort -u || true)
    while IFS= read -r line; do
        [ -n "$line" ] && CVE_IDS+=("$line")
    done <<EOF
$_cve_lines
EOF
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        echo "Loaded $(echo "$_cve_lines" | grep -c . || echo 0) unique CVE ID(s) from $CVE_FILE" >&2
    fi
fi

if [ ! -d "$REPO_DIR/.git" ]; then
    echo "Error: git repo not found at $REPO_DIR" >&2
    exit 1
fi

if [ "$MODE" = "cve" ]; then
    if [ ${#CVE_IDS[@]} -eq 0 ]; then
        echo "Error: no CVEs specified. Use --cve or --cve-file." >&2
        exit 1
    fi
    if [ ${#BRANCHES[@]} -eq 0 ]; then
        echo "Error: at least one branch is required." >&2
        exit 1
    fi
    run_cve_mode
    exit 0
fi

if [ -z "$PACKAGE" ] || [ ${#BRANCHES[@]} -eq 0 ]; then
    usage
    exit 1
fi

run_package_mode
