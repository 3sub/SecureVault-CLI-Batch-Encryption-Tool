#!/usr/bin/env python3
"""
Chiffre chaque fichier d'un dossier (tous types confondus) au MEME format
que celui utilise par l'application Vault (coffre-fort), et enregistre le
resultat dans un fichier .txt portant le meme identifiant.

pour rename .txt -> .vault faire la commande powershell : Get-ChildItem *.txt | Rename-Item -NewName { $_.BaseName + ".vault" }

Exemple :
  1352031818412589136.jpg  ->  1352031818412589136.txt
  rapport.pdf               ->  rapport.txt
  notes.md                  ->  notes.txt

Le contenu du .txt est un JSON structure exactement comme un export
".vault" a une seule entree (vault:3, AES-256-GCM, PBKDF2-SHA256,
600000 iterations, salt/iv/ct en hex). Si besoin, tu peux simplement
renommer un .txt en .vault (ou .json) et l'importer directement dans
l'application avec ta cle pour recuperer le fichier original.

Le type de fichier (image/video/audio/pdf/text/other) et le mimeType
sont detectes automatiquement a partir de l'extension, pour que
l'apercu dans l'app (image, lecteur video/audio, PDF...) fonctionne
correctement a l'import, quel que soit le type de fichier d'origine.

Les fichiers d'origine ne sont jamais modifies ni supprimes.

Usage :
  python encrypt_mass.py "C:\\Users\\sub\\Downloads\\file"

  # Pour ne traiter qu'une liste d'extensions precise (optionnel) :
  python encrypt_mass.py "C:\\Users\\sub\\Downloads\\file" jpg,png,pdf

Pre-requis :
  pip install cryptography
"""

import os
import sys
import glob
import json
import struct
import secrets
import mimetypes
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

# ---- Detection du type de fichier, identique au TYPE_MAP de l'app -----------
TYPE_MAP = {
    "image": {"jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "avif", "ico"},
    "video": {"mp4", "webm", "mkv", "avi", "mov", "wmv", "flv", "m4v"},
    "audio": {"mp3", "wav", "ogg", "flac", "aac", "m4a", "opus", "weba"},
    "pdf": {"pdf"},
    "text": {
        "txt", "md", "json", "csv", "xml", "html", "htm", "js", "ts", "css",
        "py", "java", "c", "cpp", "sh", "yaml", "yml", "log", "ini", "toml",
    },
}

# Extensions que le module mimetypes standard ne connait pas toujours bien
MIME_FALLBACK = {
    "weba": "audio/webm",
    "opus": "audio/opus",
    "avif": "image/avif",
    "m4v": "video/x-m4v",
    "yml": "text/yaml",
    "yaml": "text/yaml",
    "toml": "text/plain",
    "log": "text/plain",
    "ini": "text/plain",
    "ts": "text/typescript",
}


def get_file_type(ext: str) -> str:
    ext = (ext or "").lower()
    for type_name, extensions in TYPE_MAP.items():
        if ext in extensions:
            return type_name
    return "other"


def get_mime_type(path: str, ext: str) -> str:
    guessed, _ = mimetypes.guess_type(path)
    if guessed:
        return guessed
    return MIME_FALLBACK.get(ext.lower(), "application/octet-stream")


def is_own_vault_output(path: str) -> bool:
    """
    Detecte si un fichier est deja un export vault produit par ce script
    (pour ne pas le re-chiffrer si on relance le script sur le meme
    dossier). On se base sur le CONTENU, pas sur l'extension, car les
    exports sont eux-memes des .txt et on ne veut pas exclure de vraies
    notes texte pour autant. Un vrai fichier texte n'aura jamais par
    hasard ces 3 marqueurs JSON en tete de fichier.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(600)
        text = head.decode("utf-8", errors="ignore")
        return (
            '"vault"' in text
            and '"alg": "AES-256-GCM"' in text
            and '"kdf": "PBKDF2-SHA256"' in text
        )
    except Exception:
        return False
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
    file_type = get_file_type(ext)
    mime_type = get_mime_type(path, ext)
    now_local = datetime.now()

    # Metadonnees identiques a celles produites par processFiles() dans l'app :
    # fileType/mimeType detectes depuis l'extension reelle du fichier,
    # isText=False comme pour tout fichier ajoute via glisser-deposer /
    # selecteur de fichier (par opposition aux notes texte creees dans l'app).
    meta = {
        "name": name,
        "ext": ext,
        "fileType": file_type,
        "mimeType": mime_type,
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
    if len(sys.argv) not in (2, 3):
        print("Usage : python encrypt_mass.py <dossier> [ext1,ext2,...]")
        sys.exit(1)

    folder = sys.argv[1]
    if not os.path.isdir(folder):
        print(f"Erreur : '{folder}' n'est pas un dossier valide.")
        sys.exit(1)

    # Filtre optionnel sur une liste d'extensions (ex: "jpg,png,pdf")
    ext_filter = None
    if len(sys.argv) == 3:
        ext_filter = {e.strip().lower().lstrip(".") for e in sys.argv[2].split(",") if e.strip()}

    all_paths = sorted(
        p for p in glob.glob(os.path.join(folder, "*")) if os.path.isfile(p)
    )

    if ext_filter is not None:
        files = [
            p for p in all_paths
            if os.path.basename(p).rsplit(".", 1)[-1].lower() in ext_filter
        ]
    else:
        # Par defaut : tous les fichiers, y compris les .txt d'origine.
        # On exclut uniquement ceux qui sont deja un export vault produit
        # par un run precedent (detecte par contenu, pas par extension).
        files = [p for p in all_paths if not is_own_vault_output(p)]

    if not files:
        print("Aucun fichier trouve dans ce dossier avec ces criteres.")
        return

    print(f"{len(files)} fichier(s) trouve(s). Chiffrement en cours...\n")

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
    print("Les fichiers d'origine n'ont pas ete modifies.")
    print("Pour ouvrir un .txt dans l'application Vault : renomme-le en .vault")
    print("(ou .json), importe-le, puis entre ta cle.")


if __name__ == "__main__":
    main()
