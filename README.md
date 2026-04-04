## Description

A tool to scan manifest and dependency files for a codebase and check for known vulnerabilities which are retrieved from the OSV database and stored in a local JSON file.

### TODO:

- Fix fetch_data for PyPI returns no results
- Check if the path field in Package struct makes sense to keep
- Implement post request query using purl for OSV
- Implement support for CVE and NVD