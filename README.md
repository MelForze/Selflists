# Selflistload

Downloads wordlists into `~/selflists`, builds `biggest_dnslist.txt`, and on `download` also prepares `~/winbins` with useful Windows admin utilities.

## Install via pipx

```bash
pipx install git+https://github.com/MelForze/Selflists.git
```

## Usage

```bash
selflistload download
selflistload update
```

- `download` downloads all wordlist files, rebuilds `biggest_dnslist.txt`, creates `~/winbins`, and downloads:
  - `psexec.exe`
  - `procdump.exe`
  - `nc.exe` (from Ncat portable)
  - `openssh/ssh.exe` (Win32-OpenSSH bundle)
  - `powershell/pwsh.exe` (portable PowerShell 7; standalone `powershell.exe` is typically system-provided and not distributed as a portable bundle)
- `update` checks for updates only for wordlist files and updates changed ones; it rebuilds `biggest_dnslist.txt` only if any DNS source changed
