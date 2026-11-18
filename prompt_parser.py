from dataclasses import dataclass
import re
from typing import Optional


@dataclass
class Prompt3Parts:
    # Block 1/3: Role + Global Rules (merged)
    global_rules: str
    # Block 3/3: Step 1..end
    procedure: str
    # Optional default selection (if present in file)
    selection_controls: str = ""


def _find_header_index(text: str, header_regex: str) -> Optional[int]:
    m = re.search(header_regex, text, flags=re.IGNORECASE | re.MULTILINE)
    return m.start() if m else None


def _strip_header(block: str, header_regex: str) -> str:
    return re.sub(
        header_regex + r"[ \t]*\r?\n",
        "",
        block,
        count=1,
        flags=re.IGNORECASE | re.MULTILINE,
    ).strip()


def parse_prompt_into_three_parts(prompt: str) -> Prompt3Parts:
    """
    Supports TWO prompt layouts:

    Layout 1:
      Role
      Global Rules (Normative)
      Step 1 ...

    Layout 2:
      Role
      Global Rules (Normative)
      Selection Controls
      Step 1 ...

    Returns:
      global_rules: Role + Global Rules (merged)
      selection_controls: (empty if no header)
      procedure: Step 1..end
    """
    text = prompt.strip()

    role_idx = _find_header_index(text, r"^\s*Role\s*$")
    rules_idx = _find_header_index(text, r"^\s*Global\s+Rules\s*\(Normative\)\s*$")
    sel_idx = _find_header_index(text, r"^\s*Selection\s+Controls\s*$")  # optional
    step1_idx = _find_header_index(text, r"^\s*Step\s*1\b.*$")

    if role_idx is None:
        raise ValueError("Could not find 'Role' header.")
    if rules_idx is None:
        raise ValueError("Could not find 'Global Rules (Normative)' header.")
    if step1_idx is None:
        raise ValueError("Could not find 'Step 1' header (start of procedure).")

    if not (role_idx < rules_idx < step1_idx):
        raise ValueError("Headers are out of expected order: Role -> Global Rules -> Step 1")

    # If Selection Controls exists, it must sit between rules and step1
    if sel_idx is not None and not (rules_idx < sel_idx < step1_idx):
        raise ValueError("If 'Selection Controls' exists, it must appear between Global Rules and Step 1.")

    # Block 1 = Role + Global Rules (merged)
    block1_end = sel_idx if sel_idx is not None else step1_idx
    merged_block = text[role_idx:block1_end].strip()
    merged_block = _strip_header(merged_block, r"^\s*Role\s*$")
    merged_block = _strip_header(merged_block, r"^\s*Global\s+Rules\s*\(Normative\)\s*$")

    # Block 2 default selection from file (optional)
    selection_block = ""
    if sel_idx is not None:
        selection_block = text[sel_idx:step1_idx].strip()
        selection_block = _strip_header(selection_block, r"^\s*Selection\s+Controls\s*$")

    # Block 3 = procedure
    procedure_block = text[step1_idx:].strip()

    return Prompt3Parts(
        global_rules=merged_block,
        selection_controls=selection_block,
        procedure=procedure_block,
    )