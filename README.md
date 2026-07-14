# cve_checker
The repo consists of script that checks if a CVE is impacted in a odf-console repo branches


# Steps
1. git clone https://github.com/avazeer/cve_checker.git
2. cd cve_checker
3. git clone https://github.com/red-hat-storage/odf-console.git
4. cd odf-console
5. git remote add upstream https://github.com/red-hat-storage/odf-console.git
6. git fetch upstream master release-4.22

    #update the cves.txt file with CVEs that needs to be checked in all the branches of ODF
    #update the CVE to npm package name mapping in the file cve_to_package_mapping.json

7.  Run the following command
    % bash search-pkg-version.sh --cve-file cves.txt   master release-4.22


Note: Update the branches in the step 6 and 7 as appropriate


# Sample output

% bash search-pkg-version.sh --cve-file cves.txt   master release-4.22
Loaded 2 unique CVE ID(s) from cves.txt
CVE Impact Report
Remote: upstream | Repo: /Users/ashrafvazeer/security/scripts/odf-console
CVEs requested: 2 | package mapped: 2 | with fix rules: 0

CVE                Package                  Fix                  Status                 Branches needing fix
------------------------------------------------------------------------------------------------------------------------
CVE-2025-64718     js-yaml                  add to cve-package-f needs_fix_version      present in: master, release-4.22
CVE-2025-68470     react-router             add to cve-package-f needs_fix_version      present in: master, release-4.22

Per-branch detail
========================================================================================================================

CVE-2025-64718 — js-yaml (fix: add to cve-package-fixes.json) [needs_fix_version]
  From cve_to_package_mapping.json
  ⚠ No semver rules — showing installed versions only
  master           FOUND       versions=3.14.2, 4.1.1
  release-4.22     FOUND       versions=3.14.2, 4.1.1

CVE-2025-68470 — react-router (fix: add to cve-package-fixes.json) [needs_fix_version]
  From cve_to_package_mapping.json
  ⚠ No semver rules — showing installed versions only
  master           FOUND       versions=6.30.4
  release-4.22     FOUND       versions=6.30.4
