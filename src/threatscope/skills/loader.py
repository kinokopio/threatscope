from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Skill:
    name: str
    description: str
    content: str
    path: Path

    @classmethod
    def from_directory(cls, skill_dir: Path) -> "Skill":
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

        text = skill_md.read_text(encoding="utf-8")

        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                frontmatter = yaml.safe_load(parts[1]) or {}
                content = parts[2].strip()
            else:
                frontmatter = {}
                content = text
        else:
            frontmatter = {}
            content = text

        return cls(
            name=frontmatter.get("name", skill_dir.name),
            description=frontmatter.get("description", ""),
            content=content,
            path=skill_dir,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
        }


class SkillLoader:
    def __init__(self, skills_dir: Path | str | None = None):
        self.skills_dir = Path(skills_dir) if skills_dir else None
        self._skills: dict[str, Skill] = {}
        if self.skills_dir and self.skills_dir.exists():
            self._load_all()

    def _load_all(self) -> None:
        if not self.skills_dir:
            return
        for skill_dir in self.skills_dir.iterdir():
            if not skill_dir.is_dir():
                continue
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                continue
            try:
                skill = Skill.from_directory(skill_dir)
                self._skills[skill.name] = skill
            except Exception:
                continue

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def list_all(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._skills.values()]

    def build_prompt(self, base_prompt: str, skill_names: list[str] | None = None) -> str:
        if not skill_names:
            return base_prompt

        loaded_skills = []
        for name in skill_names:
            skill = self._skills.get(name)
            if skill:
                loaded_skills.append(skill)

        if not loaded_skills:
            return base_prompt

        skills_section = "\n\n---\n\n# Loaded Skills\n\n"
        for skill in loaded_skills:
            skills_section += f"## {skill.name}\n\n{skill.content}\n\n"

        return base_prompt + skills_section
