#!/usr/bin/env python3
"""
Chiffre chaque fichier .html d'un dossier au MEME format que celui utilise
par l'application Vault (coffre-fort), et enregistre le resultat dans un
fichier .txt portant le meme identifiant.

pour rename .txt -> .vault faire la commande powershell : Get-ChildItem *.txt | Rename-Item -NewName { $_.BaseName + ".vault" }

Exemple :
  1352031818412589136.html  ->  1352031818412589136.txt

Le contenu du .txt est un JSON structure exactement comme un export
".vault" a une seule entree (vault:3, AES-256-GCM, PBKDF2-SHA256,
600000 iterations, salt/iv/ct en hex). Si besoin, tu peux simplement
renommer un .txt en .vault (ou .json) et l'importer directement dans
l'application avec ta cle pour recuperer le fichier .html original.

Les fichiers .html d'origine ne sont jamais modifies ni supprimes.

Usage :
  python encrypt_mass.py "C:\\Users\\sub\\Downloads\\file"

Pre-requis :
  pip install cryptography
"""

import os
import sys
import glob
import json
import struct
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Cle et parametres (identiques a ceux de l'application Vault) ---------
KEY = "" # a renseigner avant execution
ITERATIONS = 600_000
SALT_LEN = 32   # octets -> correspond a crypto.getRandomValues(new Uint8Array(32))
IV_LEN = 12     # octets -> standard AES-GCM
# -----------------------------------------------------------------------------


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def js_iso_now() -> str:
    """Reproduit le format de new Date().toISOString() : 2026-07-18T15:26:02.322Z"""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def js_date_fr(now: datetime) -> str:
    """Reproduit toLocaleDateString('fr-FR') : 18/07/2026"""
    return now.strftime("%d/%m/%Y")


def encrypt_file_as_vault(path: str, password: str) -> str:
    with open(path, "rb") as f:
        data = f.read()

    name = os.path.basename(path)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    now_local = datetime.now()

    # Metadonnees identiques a celles produites par processFiles() dans l'app :
    # fileType='text' car 'html' est dans TYPE_MAP.text, isText=False comme
    # pour tout fichier ajoute via glisser-deposer / selecteur de fichier.
    meta = {
        "name": name,
        "ext": ext,
        "fileType": "text",
        "mimeType": "text/html",
        "size": len(data),
        "date": js_date_fr(now_local),
        "isText": False,
    }
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    meta_len = len(meta_bytes)

    # combined = 4 octets (longueur meta, big-endian) + meta + donnees,
    # exactement comme exportVault() dans l'app.
    combined = struct.pack(">I", meta_len) + meta_bytes + data

    salt = secrets.token_bytes(SALT_LEN)
    iv = secrets.token_bytes(IV_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(iv, combined, None)

    vault_obj = {
        "vault": 3,
        "alg": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "iter": ITERATIONS,
        "salt": salt.hex(),
        "count": 1,
        "exported": js_iso_now(),
        "entries": [
            {"iv": iv.hex(), "ct": ciphertext.hex()}
        ],
    }
    return json.dumps(vault_obj, indent=2)


def main():
    if len(sys.argv) != 2:
        print("Usage : python encrypt_mass.py <dossier>")
        sys.exit(1)

    folder = sys.argv[1]
    if not os.path.isdir(folder):
        print(f"Erreur : '{folder}' n'est pas un dossier valide.")
        sys.exit(1)

    files = sorted(glob.glob(os.path.join(folder, "*.html")))
    if not files:
        print("Aucun fichier .html trouve dans ce dossier.")
        return

    print(f"{len(files)} fichier(s) .html trouve(s). Chiffrement en cours...\n")

    for path in files:
        try:
            content = encrypt_file_as_vault(path, KEY)
            base, _ = os.path.splitext(path)
            out_path = base + ".txt"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  OK   {os.path.basename(path)}  ->  {os.path.basename(out_path)}")
        except Exception as e:
            print(f"  ECHEC {os.path.basename(path)} : {e}")

    print(f"\nTermine : {len(files)} fichier(s) traite(s).")
    print("Les fichiers .html d'origine n'ont pas ete modifies.")
    print("Pour ouvrir un .txt dans l'application Vault : renomme-le en .vault")
    print("(ou .json), importe-le, puis entre ta cle.")


if __name__ == "__main__":
    main()