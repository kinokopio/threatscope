"""Skills API router for managing Claude Skills."""

import os
import shutil
from datetime import datetime
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/skills", tags=["skills"])


class FileInfo(BaseModel):
    name: str
    path: str
    size: int
    modified_at: str
    content: str | None = None


class SkillInfo(BaseModel):
    name: str
    description: str
    folder_name: str
    files: list[FileInfo]
    total_size: int
    created_at: str
    modified_at: str


class SkillDetail(BaseModel):
    name: str
    description: str
    folder_name: str
    files: list[FileInfo]
    total_size: int
    created_at: str
    modified_at: str


class SkillListResponse(BaseModel):
    skills: list[SkillInfo]


class FileUpdateRequest(BaseModel):
    content: str


class MessageResponse(BaseModel):
    message: str


def _get_skills_dir() -> Path:
    project_root = Path(__file__).parent.parent.parent.parent.parent.parent
    return project_root / ".claude" / "skills"


def _get_file_info(file_path: Path, include_content: bool = False) -> FileInfo:
    stat = file_path.stat()
    content = None
    if include_content:
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            content = None

    return FileInfo(
        name=file_path.name,
        path=str(file_path.relative_to(_get_skills_dir().parent.parent)),
        size=stat.st_size,
        modified_at=datetime.fromtimestamp(stat.st_mtime).isoformat(),
        content=content,
    )


def _parse_skill_folder(skill_dir: Path, include_content: bool = False) -> dict | None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return None

    text = skill_md.read_text(encoding="utf-8")
    description = ""

    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            frontmatter = yaml.safe_load(parts[1]) or {}
            description = frontmatter.get("description", "")

    files = []
    total_size = 0
    oldest_time = None
    newest_time = None

    for file_path in sorted(skill_dir.rglob("*")):
        if file_path.is_file():
            file_info = _get_file_info(file_path, include_content)
            files.append(file_info)
            total_size += file_info.size
            mtime = file_path.stat().st_mtime
            if oldest_time is None or mtime < oldest_time:
                oldest_time = mtime
            if newest_time is None or mtime > newest_time:
                newest_time = mtime

    dir_stat = skill_dir.stat()
    created_at = datetime.fromtimestamp(oldest_time or dir_stat.st_ctime).isoformat()
    modified_at = datetime.fromtimestamp(newest_time or dir_stat.st_mtime).isoformat()

    return {
        "name": skill_dir.name,
        "description": description,
        "folder_name": skill_dir.name,
        "files": files,
        "total_size": total_size,
        "created_at": created_at,
        "modified_at": modified_at,
    }


def _write_skill(skill_dir: Path, name: str, description: str, content: str) -> None:
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_md = skill_dir / "SKILL.md"

    frontmatter = {"name": name, "description": description}
    yaml_content = yaml.dump(frontmatter, allow_unicode=True, default_flow_style=False)

    full_content = f"---\n{yaml_content}---\n\n{content}"
    skill_md.write_text(full_content, encoding="utf-8")


@router.get("", response_model=SkillListResponse)
async def list_skills() -> SkillListResponse:
    skills_dir = _get_skills_dir()
    skills = []

    if skills_dir.exists():
        for skill_dir in sorted(skills_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            skill = _parse_skill_folder(skill_dir, include_content=False)
            if skill:
                skills.append(SkillInfo(**skill))

    return SkillListResponse(skills=skills)


@router.get("/{skill_name}", response_model=SkillDetail)
async def get_skill(skill_name: str) -> SkillDetail:
    skills_dir = _get_skills_dir()
    skill_dir = skills_dir / skill_name

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill '{skill_name}' not found")

    skill = _parse_skill_folder(skill_dir, include_content=True)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Invalid skill '{skill_name}'")

    return SkillDetail(**skill)


@router.put("/{skill_name}/files/{file_path:path}", response_model=FileInfo)
async def update_file(skill_name: str, file_path: str, request: FileUpdateRequest) -> FileInfo:
    skills_dir = _get_skills_dir()
    skill_dir = skills_dir / skill_name

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill '{skill_name}' not found")

    full_path = skill_dir / file_path
    if not full_path.exists():
        raise HTTPException(status_code=404, detail=f"File '{file_path}' not found")

    if not str(full_path.resolve()).startswith(str(skill_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid file path")

    full_path.write_text(request.content, encoding="utf-8")

    return _get_file_info(full_path, include_content=True)


@router.post("/{skill_name}/files/{file_path:path}", response_model=FileInfo, status_code=201)
async def create_file(skill_name: str, file_path: str, request: FileUpdateRequest) -> FileInfo:
    skills_dir = _get_skills_dir()
    skill_dir = skills_dir / skill_name

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill '{skill_name}' not found")

    full_path = skill_dir / file_path
    if full_path.exists():
        raise HTTPException(status_code=409, detail=f"File '{file_path}' already exists")

    if not str(full_path.resolve()).startswith(str(skill_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid file path")

    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(request.content, encoding="utf-8")

    return _get_file_info(full_path, include_content=True)


@router.delete("/{skill_name}/files/{file_path:path}", response_model=MessageResponse)
async def delete_file(skill_name: str, file_path: str) -> MessageResponse:
    skills_dir = _get_skills_dir()
    skill_dir = skills_dir / skill_name

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill '{skill_name}' not found")

    full_path = skill_dir / file_path
    if not full_path.exists():
        raise HTTPException(status_code=404, detail=f"File '{file_path}' not found")

    if not str(full_path.resolve()).startswith(str(skill_dir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid file path")

    if full_path.name == "SKILL.md":
        raise HTTPException(status_code=400, detail="Cannot delete SKILL.md")

    full_path.unlink()

    return MessageResponse(message=f"File '{file_path}' deleted successfully")


@router.delete("/{skill_name}", response_model=MessageResponse)
async def delete_skill(skill_name: str) -> MessageResponse:
    skills_dir = _get_skills_dir()
    skill_dir = skills_dir / skill_name

    if not skill_dir.exists():
        raise HTTPException(status_code=404, detail=f"Skill '{skill_name}' not found")

    shutil.rmtree(skill_dir)

    return MessageResponse(message=f"Skill '{skill_name}' deleted successfully")
