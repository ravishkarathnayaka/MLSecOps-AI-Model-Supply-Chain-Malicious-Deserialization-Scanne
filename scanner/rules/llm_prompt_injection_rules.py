"""
Rules detecting LLM prompt injection, system prompt exfiltration, and backdoor trigger sequences
within model generation configuration, chat templates, and tokenizer files.
"""

import re
from typing import List, Optional
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", "INJECTION-IGNORE-INSTRUCTIONS", "Direct instruction override sequence"),
    (r"you\s+are\s+now\s+in\s+developer\s+mode", "INJECTION-DEVELOPER-MODE", "Jailbreak developer mode override"),
    (r"jailbreak|dan\s+mode|do\s+anything\s+now", "INJECTION-JAILBREAK-TRIGGER", "Known adversarial jailbreak backdoor trigger"),
    (r"(reveal|print|exfiltrate)\s+(the\s+)?system\s+prompt", "INJECTION-PROMPT-LEAK", "System prompt extraction intent"),
    (r"<\s*script\s*>.*<\s*/\s*script\s*>", "INJECTION-XSS-PAYLOAD", "Cross-site scripting payload inside prompt template"),
    (r"https?://(webhook\.site|burpcollaborator\.net|canarytokens\.com)", "INJECTION-CANARY-EXFIL", "Known exfiltration webhook service URL"),
]


def scan_prompt_text(text: str, location_hint: str = "chat_template") -> List[Finding]:
    """Scans template or prompt string for adversarial prompt injection patterns."""
    findings: List[Finding] = []
    for pattern, rule_id, desc in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id=f"LLM-{rule_id}",
                    title=f"Adversarial Prompt Pattern Detected ({rule_id})",
                    severity=RiskLevel.HIGH if "CANARY" in rule_id or "IGNORE" in rule_id else RiskLevel.MEDIUM,
                    description=f"{desc} found in prompt/tokenizer configuration.",
                    location=location_hint,
                    category="prompt_injection_backdoor",
                )
            )
    return findings
