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
        JSON with file type information:
        - format: File format (PE32, PE32+, ELF64, etc.)
        - arch: Architecture (I386, AMD64, ARM, etc.)
        - mode: Bit mode (32, 64)
        - type: File type (executable, library, etc.)
        - detects: List of detections (compilers, packers, protectors)
    """
    # Save uploaded file to temp location
    temp_path = TEMP_DIR / f"{uuid.uuid4().hex}_{file.filename or 'unknown'}"

    try:
        # Write file to disk
        content = await file.read()
        temp_path.write_bytes(content)

        # Run diec with JSON output
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
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()


@app.post("/analyze/path")
async def analyze_path(file_path: str) -> dict[str, Any]:
    """
    Analyze a file by path (for files already on disk).

    Args:
        file_path: Path to the file to analyze

    Returns:
        Same as /analyze endpoint
    """
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
    """
    Run diec CLI and parse output.

    Args:
        file_path: Path to file to analyze

    Returns:
        Normalized detection result
    """
    # Run diec with JSON output
    proc = subprocess.run(
        ["diec", "-j", str(file_path)],
        capture_output=True,
        text=True,
        timeout=DIEC_TIMEOUT,
        check=True,
    )

    # Parse JSON output
    raw_output = json.loads(proc.stdout)

    # Normalize output to our schema
    return _normalize_diec_output(raw_output)


def _normalize_diec_output(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize diec JSON output to our standard schema.

    diec output format varies, but typically includes:
    - detects: list of detection objects
    - Each detect has: type, name, version, info, etc.
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
        # Empty result - unknown file type
        return result

    # Process each detection
    for detect in detects:
        detect_type = detect.get("type", "").lower()
        detect_name = detect.get("name", "")
        detect_version = detect.get("version", "")
        detect_info = detect.get("info", "")

        # Extract file format info from "filetype" or similar
        if detect_type in ("filetype", "binary"):
            # Parse format info
            result["format"] = detect_name
            if detect_info:
                # Info often contains arch/mode details
                result["type"] = detect_info

        elif detect_type == "arch":
            result["arch"] = detect_name
            if detect_version:
                result["mode"] = detect_version

        elif detect_type in ("compiler", "linker", "tool"):
            result["detects"].append(
                {
                    "type": "compiler",
                    "name": detect_name,
                    "version": detect_version,
                }
            )

        elif detect_type in ("packer", "cryptor", "installer"):
            result["detects"].append(
                {
                    "type": "packer",
                    "name": detect_name,
                    "version": detect_version,
                }
            )

        elif detect_type in ("protector", "dongle"):
            result["detects"].append(
                {
                    "type": "protector",
                    "name": detect_name,
                    "version": detect_version,
                }
            )

        elif detect_type == "library":
            # Library detections (like .NET, Qt, etc.)
            result["detects"].append(
                {
                    "type": "library",
                    "name": detect_name,
                    "version": detect_version,
                }
            )

        elif detect_type == "format":
            # File format (PE, ELF, etc.)
            result["format"] = detect_name

        else:
            # Unknown type - add as generic detection
            if detect_name:
                result["detects"].append(
                    {
                        "type": detect_type or "unknown",
                        "name": detect_name,
                        "version": detect_version,
                    }
                )

    # Try to infer arch/mode from format if not set
    if not result["arch"] and result["format"]:
        fmt = result["format"].upper()
        if "64" in fmt or "AMD64" in fmt or "X64" in fmt:
            result["arch"] = "AMD64"
            result["mode"] = "64"
        elif "32" in fmt or "I386" in fmt or "X86" in fmt:
            result["arch"] = "I386"
            result["mode"] = "32"
        elif "ARM64" in fmt or "AARCH64" in fmt:
            result["arch"] = "ARM64"
            result["mode"] = "64"
        elif "ARM" in fmt:
            result["arch"] = "ARM"
            result["mode"] = "32"

    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
