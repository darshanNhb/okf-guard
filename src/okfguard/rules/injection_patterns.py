"""Injection-pattern bank for the detection engine.

This module holds the regex/keyword patterns used to detect language
characteristic of prompt-injection attacks — instructions directed at an
AI system rather than descriptions of facts for a human reader.

The ``PATTERNS`` list is the single most frequently updated part of this
codebase after initial release: as new injection phrasings are discovered
in the wild, new entries should be added here.  The list is deliberately
kept as a flat, easy-to-extend list with no complex registration system.

Each pattern carries:
- ``label``: a short category tag for grouping (e.g. ``"instruction_override"``)
- ``pattern``: a compiled regex
- ``confidence``: a weight in [0, 1] reflecting how strongly a match
  indicates genuine injection vs. coincidental phrasing
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class InjectionPattern:
    """A single injection-detection pattern.

    Attributes:
        label: Short human-readable category of attack this targets.
        pattern: Compiled regex pattern.
        confidence: Weight in [0.0, 1.0] for this pattern.
    """

    label: str
    pattern: re.Pattern[str]
    confidence: float


# ═══════════════════════════════════════════════════════════════════════
# PATTERN BANK
#
# Categories covered:
#   1. Instruction override / prior-instruction dismissal
#   2. New-instruction injection
#   3. Authority / role impersonation
#   4. Fake system markers
#   5. Direct AI/agent address
#   6. Data-exfiltration directives
#   7. Permission / approval override
#   8. Jailbreak-style phrasing
#
# When adding patterns:
#   - Keep confidence moderate (0.5–0.7) for patterns that might appear
#     in legitimate business text.
#   - Use higher confidence (0.75–0.90) for patterns that are almost
#     never found in genuine knowledge content.
#   - Never set confidence to 1.0 — there is always some false-positive
#     risk with regex-based detection.
# ═══════════════════════════════════════════════════════════════════════

PATTERNS: list[InjectionPattern] = [
    # -----------------------------------------------------------------
    # 1. Instruction override / prior-instruction dismissal
    # -----------------------------------------------------------------
    InjectionPattern(
        label="instruction_override",
        pattern=re.compile(
            r"ignore (all |the )?(previous|prior|above|earlier|preceding)"
            r" (instructions?|prompts?|directives?|rules?|guidelines?)",
            re.IGNORECASE,
        ),
        confidence=0.85,
    ),
    InjectionPattern(
        label="instruction_override",
        pattern=re.compile(
            r"disregard (all |the )?(above|previous|prior|earlier|preceding)",
            re.IGNORECASE,
        ),
        confidence=0.80,
    ),
    InjectionPattern(
        label="instruction_override",
        pattern=re.compile(
            r"forget (all |the )?(previous|prior|above|earlier)"
            r" (instructions?|context|prompts?|rules?)",
            re.IGNORECASE,
        ),
        confidence=0.80,
    ),
    InjectionPattern(
        label="instruction_override",
        pattern=re.compile(
            r"do not follow (the )?(previous|prior|above|original)"
            r" (instructions?|rules?|guidelines?)",
            re.IGNORECASE,
        ),
        confidence=0.80,
    ),
    InjectionPattern(
        label="instruction_override",
        pattern=re.compile(
            r"override (all |the )?(previous|prior|existing|current)"
            r" (instructions?|rules?|policies?|guidelines?)",
            re.IGNORECASE,
        ),
        confidence=0.80,
    ),

    # -----------------------------------------------------------------
    # 2. New-instruction injection
    # -----------------------------------------------------------------
    InjectionPattern(
        label="new_instruction",
        pattern=re.compile(
            r"(new|updated|revised|replacement) (instructions?|directives?"
            r"|rules?|guidelines?)\s*:",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="new_instruction",
        pattern=re.compile(
            r"your (new|actual|real|true) (task|instructions?|objective|"
            r"purpose|mission|goal) (is|are)\b",
            re.IGNORECASE,
        ),
        confidence=0.75,
    ),
    InjectionPattern(
        label="new_instruction",
        pattern=re.compile(
            r"from now on,?\s+(you (should|must|will|shall)|always|never)",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="new_instruction",
        pattern=re.compile(
            r"instead,?\s+(you (should|must|will)|do the following|"
            r"follow these)",
            re.IGNORECASE,
        ),
        confidence=0.65,
    ),

    # -----------------------------------------------------------------
    # 3. Authority / role impersonation
    # -----------------------------------------------------------------
    InjectionPattern(
        label="fake_role_assertion",
        pattern=re.compile(
            r"you are now\b",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="fake_role_assertion",
        pattern=re.compile(
            r"(act|behave|operate|function|respond) as\s+(if you were |"
            r"though you are |a |an |the )",
            re.IGNORECASE,
        ),
        confidence=0.65,
    ),
    InjectionPattern(
        label="fake_role_assertion",
        pattern=re.compile(
            r"(pretend|imagine|assume|suppose) (that )?you('re| are)"
            r" (a |an |the )?",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="fake_role_assertion",
        pattern=re.compile(
            r"switch(ing)? (to|into) (a |an )?(\w+ )?mode",
            re.IGNORECASE,
        ),
        confidence=0.60,
    ),

    # -----------------------------------------------------------------
    # 4. Fake system markers
    # -----------------------------------------------------------------
    InjectionPattern(
        label="fake_system_marker",
        pattern=re.compile(
            r"\b(SYSTEM|ADMIN|ROOT|SUPERUSER|DEVELOPER)\s*(PROMPT|MESSAGE"
            r"|INSTRUCTION|OVERRIDE|COMMAND)?\s*:",
            re.IGNORECASE,
        ),
        confidence=0.60,
    ),
    InjectionPattern(
        label="fake_system_marker",
        pattern=re.compile(
            r"\[SYSTEM\]|\[ADMIN\]|\[INTERNAL\]|\[OVERRIDE\]",
            re.IGNORECASE,
        ),
        confidence=0.65,
    ),
    InjectionPattern(
        label="fake_system_marker",
        pattern=re.compile(
            r"<\s*system\s*>|<\s*/?\s*instructions?\s*>",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="fake_system_marker",
        pattern=re.compile(
            r"###\s*(SYSTEM|INTERNAL|ADMIN)\s*(INSTRUCTIONS?|PROMPT|"
            r"MESSAGE|DIRECTIVE)",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),

    # -----------------------------------------------------------------
    # 5. Direct AI/agent address
    # -----------------------------------------------------------------
    InjectionPattern(
        label="direct_ai_address",
        pattern=re.compile(
            r"\b(AI|assistant|agent|model|LLM|GPT|chatbot|bot)\s*[,:]?\s*"
            r"(when|if|please|do not|don't|you (should|must|will))\s+",
            re.IGNORECASE,
        ),
        confidence=0.75,
    ),
    InjectionPattern(
        label="direct_ai_address",
        pattern=re.compile(
            r"\b(AI|assistant|agent|model|LLM)\s*[,:]?\s*"
            r"(when|if) you (read|process|see|parse|encounter|find|receive)",
            re.IGNORECASE,
        ),
        confidence=0.75,
    ),
    InjectionPattern(
        label="direct_ai_address",
        pattern=re.compile(
            r"(dear|attention|note to|message for|hey)\s+"
            r"(AI|assistant|agent|model|LLM|bot)",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),

    # -----------------------------------------------------------------
    # 6. Data-exfiltration directives
    # -----------------------------------------------------------------
    InjectionPattern(
        label="data_exfiltration",
        pattern=re.compile(
            r"(send|forward|email|transmit|post|upload|exfiltrate|leak)"
            r"\s+(this|the|all|any|every)\s+.{0,30}\s+"
            r"(to|at|via)\s+",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="data_exfiltration",
        pattern=re.compile(
            r"(include|embed|insert|append|attach)\s+"
            r"(the |all |this )?(api[- ]?key|password|token|secret|"
            r"credential|private[- ]?key|access[- ]?key|auth)",
            re.IGNORECASE,
        ),
        confidence=0.80,
    ),
    InjectionPattern(
        label="data_exfiltration",
        pattern=re.compile(
            r"(output|print|display|reveal|show|expose|dump)\s+"
            r"(your |the |all )?(system[- ]?prompt|instructions?|"
            r"hidden|internal|secret|confidential|private)",
            re.IGNORECASE,
        ),
        confidence=0.75,
    ),

    # -----------------------------------------------------------------
    # 7. Permission / approval override
    # -----------------------------------------------------------------
    InjectionPattern(
        label="permission_override",
        pattern=re.compile(
            r"(approve|authorize|allow|permit|grant|accept)\s+"
            r"(automatically|unconditionally|without|all|any|every)",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="permission_override",
        pattern=re.compile(
            r"(no|skip|bypass|disable|remove|ignore)\s+"
            r"(review|verification|validation|approval|check|confirmation"
            r"|authentication|authorization|oversight)\s+"
            r"(needed|required|necessary|is needed|is required)",
            re.IGNORECASE,
        ),
        confidence=0.75,
    ),
    InjectionPattern(
        label="permission_override",
        pattern=re.compile(
            r"(skip|bypass|disable|circumvent|avoid|ignore)\s+"
            r"(the )?(review|verification|validation|approval|"
            r"safety|security|check|safeguard|filter)",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
    InjectionPattern(
        label="permission_override",
        pattern=re.compile(
            r"without\s+(any )?(human |manual )?"
            r"(review|approval|verification|oversight|confirmation|"
            r"proof|evidence)",
            re.IGNORECASE,
        ),
        confidence=0.60,
    ),

    # -----------------------------------------------------------------
    # 8. Jailbreak-style phrasing
    # -----------------------------------------------------------------
    InjectionPattern(
        label="jailbreak",
        pattern=re.compile(
            r"(you have no|there are no|remove all|drop all|"
            r"you don't have any)\s+"
            r"(restrictions?|limitations?|constraints?|boundaries|"
            r"guardrails?|rules?|filters?)",
            re.IGNORECASE,
        ),
        confidence=0.75,
    ),
    InjectionPattern(
        label="jailbreak",
        pattern=re.compile(
            r"(enable|enter|switch to|activate)\s+"
            r"(unrestricted|developer|debug|god|admin|jailbreak|"
            r"DAN|evil|uncensored)\s*(mode)?",
            re.IGNORECASE,
        ),
        confidence=0.80,
    ),
    InjectionPattern(
        label="jailbreak",
        pattern=re.compile(
            r"(in this (hypothetical|fictional|imaginary|simulated|"
            r"roleplay) scenario|for (educational|research|testing|"
            r"academic) purposes?),?\s+(you|it is|the)",
            re.IGNORECASE,
        ),
        confidence=0.55,
    ),
    InjectionPattern(
        label="jailbreak",
        pattern=re.compile(
            r"(this is a test|this is just a test|testing purposes only)"
            r"\s*(,|\.|\s)?\s*(ignore|bypass|disable|skip)",
            re.IGNORECASE,
        ),
        confidence=0.70,
    ),
]
