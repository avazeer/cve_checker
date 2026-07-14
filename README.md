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

8.  Run the following command
    % bash search-pkg-version.sh --cve-file cves.txt   master release-4.22


Note: Update the branches in the step 6 and 7 as appropriate


# Sample output
<img width="903" height="391" alt="Screenshot 2026-07-14 at 4 26 06 PM" src="https://github.com/user-attachments/assets/9c094107-9cd4-4d93-8f14-d98633562123" />

