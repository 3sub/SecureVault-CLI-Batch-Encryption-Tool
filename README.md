# SecureVault CLI — Batch Encryption Tool

A command-line companion to [SecureVault](https://github.com/3sub/SecureVault): it bulk-encrypts a folder of files into the exact `.vault` format used by the browser app, so you can import them in one shot instead of dragging files in one by one.

## What it does

`encrypt_mass.py` scans a folder for `.html` files and produces a `vault:3`-format encrypted entry for each one — same structure, same crypto, same metadata layout as SecureVault's own export. Each output file is written as `<id>.txt` next to the original; rename it to `.vault` (or `.json`) and import it directly into SecureVault with your key.

Original `.html` files are never modified or deleted.

## Compatibility

Produces output that matches SecureVault's `.vault` container spec exactly:

| Parameter | Value |
|---|---|
| Format version | `vault:3` |
| Cipher | AES-256-GCM |
| KDF | PBKDF2-SHA256, 600,000 iterations |
| Salt / IV | 32 bytes / 12 bytes, random per run / per file |
| Metadata | JSON-encoded, length-prefixed, encrypted together with the file content |

Because SecureVault treats `.html` as a text type, each entry is tagged with `fileType: "text"` and `mimeType: "text/html"` to match what the app itself would produce on import.

## Prerequisites

- Python 3.8+
- [`cryptography`](https://pypi.org/project/cryptography/)

```bash
pip install cryptography
```

## Usage

1. Open `encrypt_mass.py` and set your key:

   ```python
   KEY = "your-secret-key-here"
   ```

2. Run it against a folder of `.html` files:

   ```bash
   python encrypt_mass.py "C:\Users\you\Downloads\file"
   ```

3. Each `name.html` produces a matching `name.txt`. Rename the outputs to `.vault` to import them into SecureVault:

   ```powershell
   Get-ChildItem *.txt | Rename-Item -NewName { $_.BaseName + ".vault" }
   ```

4. Open SecureVault, enter your key, and import the renamed file(s).

## Security notes

- **Don't commit your key.** The script currently expects the key hardcoded in `KEY`. Before pushing changes, make sure that line is blank, or better, pass the key via an environment variable or an interactive prompt (e.g. `getpass.getpass()`) instead of editing the script in place.
- Each run generates a fresh random salt and IV — outputs from separate runs are not deterministic, which is expected and fine for SecureVault's import logic (salt travels with the file).
- As with SecureVault itself: without the key, neither the file content nor its metadata is recoverable. There is no recovery mechanism.

## Limitations

- Only picks up `.html` files by default — for other extensions, adjust the `glob` pattern in `main()` and the `mimeType`/`ext` handling in `encrypt_file_as_vault()`.
- Single-entry `.vault` files only (one file per output); SecureVault itself supports multi-file vaults, but this script keeps a 1:1 mapping for simplicity.

## Related

- [SecureVault](https://github.com/3sub/SecureVault) — the browser-based vault app this tool produces files for.

## License

MIT — see `LICENSE` for details.
