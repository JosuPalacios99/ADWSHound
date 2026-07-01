"""ZIP assembly for BloodHound import."""
from __future__ import annotations

import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def create_zip(
    json_files: list[Path],
    output_dir: Path,
    prefix: str = "",
    password: Optional[str] = None,
) -> Path:
    """Bundle all JSON files into a BloodHound-importable ZIP.

    Deletes source JSON files after adding to the archive.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    parts = [p for p in [prefix, timestamp, "BloodHound"] if p]
    zip_name = "_".join(parts) + ".zip"
    zip_path = output_dir / zip_name

    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zf:
        if password:
            # zipfile stdlib does not support encryption; use pyzipper if available
            try:
                import pyzipper
                zf.close()
                with pyzipper.AESZipFile(
                    zip_path, "w",
                    compression=pyzipper.ZIP_DEFLATED,
                    encryption=pyzipper.WZ_AES,
                ) as pzf:
                    pzf.setpassword(password.encode())
                    for jf in json_files:
                        pzf.write(jf, jf.name)
            except ImportError:
                log.warning("pyzipper not installed — ZIP password protection skipped")
                with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf2:
                    for jf in json_files:
                        zf2.write(jf, jf.name)
        else:
            for jf in json_files:
                zf.write(jf, jf.name)

    # Remove source files
    for jf in json_files:
        try:
            jf.unlink()
        except OSError:
            pass

    log.info("Created ZIP: %s (%d files)", zip_path, len(json_files))
    return zip_path
