"""
diec HTTP Server - FastAPI wrapper for Detect It Easy (diec) CLI.

Provides REST API for file type identification, packer/compiler detection.
"""

import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI(
    title="diec HTTP Server",
    description="File type identification service using Detect It Easy",
    version="1.0.0",
)

TEMP_DIR = Path(os.environ.get("DIEC_TEMP_DIR", "/app/temp"))
DIEC_TIMEOUT = int(os.environ.get("DIEC_TIMEOUT", "30"))


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "diec"}


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """
    Analyze a file using diec.

    Args:
        file: The file to analyze (multipart upload)

    Returns:
        JSON with file type information
    """
    temp_path = TEMP_DIR / f"{uuid.uuid4().hex}_{file.filename or 'unknown'}"

    try:
        content = await file.read()
        temp_path.write_bytes(content)
        result = _run_diec(temp_path)
        return result

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="diec analysis timed out")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"diec execution failed: {e.stderr or str(e)}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse diec output: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    finally:
        if temp_path.exists():
            temp_path.unlink()


@app.post("/analyze/path")
async def analyze_path(file_path: str) -> dict[str, Any]:
    """Analyze a file by path (for files already on disk)."""
    path = Path(file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    try:
        return _run_diec(path)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="diec analysis timed out")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"diec execution failed: {e.stderr or str(e)}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse diec output: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


def _run_diec(file_path: Path) -> dict[str, Any]:
    """Run diec CLI and parse output."""
    proc = subprocess.run(
        ["diec", "-j", str(file_path)],
        capture_output=True,
        text=True,
        timeout=DIEC_TIMEOUT,
        check=True,
    )

    raw_output = json.loads(proc.stdout)
    return _normalize_diec_output(raw_output)


def _normalize_diec_output(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize diec JSON output to our standard schema.

    diec actual output format:
    {
        "detects": [
            {
                "filetype": "ELF64",
                "parentfilepart": "Header",
                "values": [
                    {"type": "Compiler", "name": "Go", "version": "1.24.0", ...}
                ]
            }
        ]
    }
    """
    result: dict[str, Any] = {
        "format": "",
        "arch": "",
        "mode": "",
        "type": "",
        "detects": [],
    }

    detects = raw.get("detects", [])
    if not detects:
        return result

    # Process each detection block
    for detect_block in detects:
        # Get file type from the block level
        filetype = detect_block.get("filetype", "")
        if filetype and not result["format"]:
            result["format"] = filetype
            # Infer arch from filetype
            _infer_arch_from_format(result, filetype)

        # Process values array for compilers, packers, etc.
        values = detect_block.get("values", [])
        for value in values:
            value_type = value.get("type", "").lower()
            value_name = value.get("name", "")
            value_version = value.get("version", "")

            if value_type in ("compiler", "linker", "tool"):
                result["detects"].append(
                    {
                        "type": "compiler",
                        "name": value_name,
                        "version": value_version,
                    }
                )
            elif value_type in ("packer", "cryptor", "installer"):
                result["detects"].append(
                    {
                        "type": "packer",
                        "name": value_name,
                        "version": value_version,
                    }
                )
            elif value_type in ("protector", "dongle"):
                result["detects"].append(
                    {
                        "type": "protector",
                        "name": value_name,
                        "version": value_version,
                    }
                )
            elif value_type == "library":
                result["detects"].append(
                    {
                        "type": "library",
                        "name": value_name,
                        "version": value_version,
                    }
                )
            elif value_name:
                # Unknown type - add as generic
                result["detects"].append(
                    {
                        "type": value_type or "unknown",
                        "name": value_name,
                        "version": value_version,
                    }
                )

    return result


def _infer_arch_from_format(result: dict[str, Any], fmt: str) -> None:
    """Infer architecture from format string."""
    fmt_upper = fmt.upper()

    if "ELF64" in fmt_upper or "PE64" in fmt_upper or "PE32+" in fmt_upper:
        result["arch"] = "AMD64"
        result["mode"] = "64"
    elif "ELF32" in fmt_upper or "PE32" in fmt_upper:
        result["arch"] = "I386"
        result["mode"] = "32"
    elif "64" in fmt_upper or "AMD64" in fmt_upper or "X64" in fmt_upper:
        result["arch"] = "AMD64"
        result["mode"] = "64"
    elif "32" in fmt_upper or "I386" in fmt_upper or "X86" in fmt_upper:
        result["arch"] = "I386"
        result["mode"] = "32"
    elif "ARM64" in fmt_upper or "AARCH64" in fmt_upper:
        result["arch"] = "ARM64"
        result["mode"] = "64"
    elif "ARM" in fmt_upper:
        result["arch"] = "ARM"
        result["mode"] = "32"
    elif "ELF" in fmt_upper:
        # Generic ELF without bit info - assume 64-bit
        result["arch"] = "AMD64"
        result["mode"] = "64"
    elif "PE" in fmt_upper:
        # Generic PE without bit info - assume 32-bit
        result["arch"] = "I386"
        result["mode"] = "32"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
