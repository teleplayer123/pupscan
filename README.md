## Description

A tool to scan manifest and dependency files for known package vulnerabilities. Vulnerability data is retrieved from the OSV database and stored in a local JSON file for offline matching. Project goals are to use minmal dependencies and maintain a modular layout.

## Usage

### Scan

*pupscan <file_path>*

Run a scan in the root of a codebase where package dependency files are located:

```
$ pupscan scan .
```

Run a scan on a specific file:

```
$ pupscan scan requirements.txt
```

### Update

Update database if stale:

``` 
$ pupscan update
```

### Fetch

*pupscan fetch \<ecosystem> \<package> [-- version \<version>]*

Manually check a package base on the version:

```
$ pupscan fetch PyPI jinja2 --version "2.0.0"
```

### Check

*pupscan --scan-path \<file_path> --cache-path \<db_path>*

Run an offline scan with existing database:

```
$ pupscan check --scan-path requirements.txt --cache-path vulns.json
```

