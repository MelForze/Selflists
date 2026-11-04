# Selflistload

Wordlists, port lists, and Windows utilities.

## Installation

```bash
pipx install git+https://github.com/MelForze/Selflists.git
selflistload download
```

Wordlists are installed to `~/selflists`, and utilities to `~/winbins`:
PsExec, ProcDump, Ncat (`nc.exe`), OpenSSH, and PowerShell 7 (`pwsh.exe`).

## Commands

```bash
# Install bundled wordlists and download Windows utilities
selflistload download

# Install wordlists only, without downloading Windows utilities
selflistload download --lists-only

# Check original sources and update installed wordlists
selflistload update

# Show local file counts, sizes, and last source checks
selflistload status

# Measure each DNS source's exclusive and shared entries
selflistload dns-stats

# Verify installed wordlists and port lists offline
selflistload verify

# Verify compressed files and checksums in the repository
selflistload verify --repo .
```

Wordlists are copied from the package, or downloaded from their sources if unavailable.
Use `download` to update Windows utilities.
DNS and web updates report added and removed entries, discarded duplicates, and file size changes.
Downloads stream to disk and are checked before replacing existing wordlists.
If an update fails, repeat the command to continue from completed sources.
An unavailable or rejected source retains its previous file while other sources continue updating.
Combined lists use the available source versions and are preserved if a required source is missing.
Failures are summarized at the end and return exit code 1; completed sources are skipped on retry.
Updates reject reductions of more than 50% in lists with at least 1,000 lines
or 64 KiB. After inspecting the source, use `selflistload update --allow-shrink`
to accept an intentional reduction. Empty files and invalid content are still rejected.

`status` and `dns-stats` work offline on installed lists. Source check dates are shown
when recorded; locally modified files are marked. DNS analysis uses temporary disk space
and reports exclusive entries absent from every other source, independent of merge order.

`verify` checks saved checksums, wordlist content, and port counts, ranges, duplicates,
format, custom sorting, and Nmap list prefixes. Repository checks also validate gzip
integrity and compressed/uncompressed sizes and checksums. Files without saved checksums
receive content checks only. Verification reports errors without modifying files.

`selflistload refresh --repo .` prepares and validates every file before publishing
repository updates. Publication errors trigger a rollback; interrupted publication
is recovered on the next `refresh`.

## Files

Wordlists and main utilities after `selflistload download`:

```text
~/
├── selflists/
│   ├── dns/
│   │   ├── FUZZSUBS_CYFARE_1.txt
│   │   ├── FUZZSUBS_CYFARE_2.txt
│   │   ├── assetnote-httparchive-subdomains.txt
│   │   ├── best-dns-wordlist.txt
│   │   ├── biggest_dnslist.txt
│   │   ├── combined_subdomains.txt
│   │   ├── n0kovo_subdomains.txt
│   │   ├── namelist.txt
│   │   └── trickest-inventory-subdomains.txt
│   ├── web/
│   │   ├── assetnote-directories.txt
│   │   ├── biggest_weblist.txt
│   │   ├── content_discovery_all.txt
│   │   ├── dodgypass.txt
│   │   ├── fuzz.txt
│   │   ├── headers.txt
│   │   ├── hfuzz.txt
│   │   ├── params.txt
│   │   └── seclists-combined-directories.txt
│   ├── api/
│   │   ├── endpoints.txt
│   │   └── openapi.txt
│   └── ports/
│       ├── custom-top-2k.txt
│       ├── custom-top-web-1k.txt
│       ├── nmap-top-1k.txt
│       ├── nmap-top-2k.txt
│       ├── nmap-top-3k.txt
│       ├── nmap-top-4k.txt
│       └── nmap-top-5k.txt
└── winbins/
    ├── psexec.exe
    ├── procdump.exe
    ├── nc.exe
    ├── ssh/
    │   └── ssh.exe
    └── pwsh/
        └── pwsh.exe
```

`dns/biggest_dnslist.txt` combines all DNS wordlists with duplicates removed.
`web/biggest_weblist.txt` combines six path and directory wordlists with duplicates removed.

`web/params.txt` contains HTTP parameter names; `web/headers.txt` contains header names.

The complete OpenSSH and PowerShell bundles, including dependencies, are installed
in `winbins/ssh/` and `winbins/pwsh/`, respectively.

Each file in `ports/` contains TCP ports on a single comma-separated line.
Nmap lists follow frequency order; custom lists are sorted numerically.
`custom-top-web-1k.txt` contains 1,000 priority ports for finding web services;
`custom-top-2k.txt` contains 2,000 ports for general scanning.

Large wordlists are stored as gzip files in the repository and unpacked during installation.
The local limit for each stored wordlist file is 300 MiB.
