from __future__ import annotations
from dotenv import load_dotenv  # loads .env into os.environ
load_dotenv()

import os, json, re, time, threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # handled later

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MED_FILE = DATA_DIR / "medications.json"
SESS_FILE = DATA_DIR / "sessions_store.json"

_LOCK = threading.Lock()

_MED_CACHE: Dict[str, Dict] = {}
_SESSIONS: Dict[str, "ChatSession"] = {}
_MAX_SESSION_TURNS = 40
_MAX_SESSIONS_IN_MEMORY = 200

DISCLAIMER = (
    "Educational information only. Not medical advice. "
    "Consult a licensed healthcare professional. Not for emergencies."
)

_BLOCK_PATTERNS = [
    r"\b(dose|dosage|how (many|much)|mg\b|milligram|take per (day|hour))\b",
    r"\b(overdose|poison|emergency)\b",
    r"\b(prescribe|prescription)\b",
    r"\b(diagnose|diagnosis)\b",
    r"\b(should I take)\b",
    r"\b(combine .* with .* )"
]

SYSTEM_PROMPT = """You are a medication info assistant.
Rules:
- Provide only neutral, educational information from supplied structured facts.
- Do NOT invent data. If something is missing, say it's not available.
- Absolutely refuse dosing, diagnosis, emergency guidance, or personalized therapeutic recommendations.
- Always end with the provided DISCLAIMER verbatim.
Return concise paragraphs (<= 120 words total).
"""

def _ensure_storage():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not MED_FILE.exists():
        MED_FILE.write_text(json.dumps([
            {
                "name": "Ibuprofen",
                "class": "Nonsteroidal anti-inflammatory drug (NSAID)",
                "uses": ["Pain relief", "Reduce inflammation", "Lower fever"],
                "common_side_effects": ["Nausea", "Heartburn", "Dizziness"],
                "serious_warnings": ["Risk of gastrointestinal bleeding", "Possible cardiovascular risk"],
                "interactions_note": "Caution with anticoagulants and other NSAIDs."
            },
            {
                "name": "Paracetamol",
                "class": "Analgesic / Antipyretic",
                "uses": ["Mild to moderate pain", "Fever reduction"],
                "common_side_effects": ["Generally well tolerated"],
                "serious_warnings": ["Liver toxicity at high doses"],
                "interactions_note": "Track total acetaminophen intake from all products."
            }
        ], indent=2), encoding="utf-8")
    if not SESS_FILE.exists():
        SESS_FILE.write_text("{}", encoding="utf-8")

def _normalized(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())

def load_medications():
    if _MED_CACHE:
        return
    _ensure_storage()
    try:
        data = json.loads(MED_FILE.read_text(encoding="utf-8"))
        for entry in data:
            key = _normalized(entry.get("name", ""))
            if key:
                _MED_CACHE[key] = entry
    except Exception as e:
        print(f"[med-bot] load error: {e}")

def save_medications():
    with _LOCK:
        MED_FILE.write_text(json.dumps(list(_MED_CACHE.values()), indent=2), encoding="utf-8")

def add_or_update_medication(record: Dict) -> bool:
    name = record.get("name")
    if not name:
        return False
    load_medications()
    _MED_CACHE[_normalized(name)] = record
    save_medications()
    return True

@dataclass
class ChatTurn:
    role: str
    content: str
    ts: float = field(default_factory=time.time)

@dataclass
class ChatSession:
    session_id: str
    turns: List[ChatTurn] = field(default_factory=list)

    def add(self, role: str, content: str):
        self.turns.append(ChatTurn(role=role, content=content))
        if len(self.turns) > _MAX_SESSION_TURNS:
            self.turns = self.turns[-_MAX_SESSION_TURNS:]

def _load_sessions_from_disk():
    _ensure_storage()
    try:
        raw = json.loads(SESS_FILE.read_text(encoding="utf-8"))
        for sid, tlist in raw.items():
            turns = [ChatTurn(**t) for t in tlist[-_MAX_SESSION_TURNS:]]
            _SESSIONS[sid] = ChatSession(session_id=sid, turns=turns)
    except Exception:
        pass

def _persist_sessions():
    with _LOCK:
        if len(_SESSIONS) > _MAX_SESSIONS_IN_MEMORY:
            sorted_ids = sorted(
                _SESSIONS.keys(),
                key=lambda s: (_SESSIONS[s].turns[0].ts if _SESSIONS[s].turns else time.time())
            )
            for sid in sorted_ids[: len(_SESSIONS) - _MAX_SESSIONS_IN_MEMORY]:
                _SESSIONS.pop(sid, None)
        serial = {sid: [t.__dict__ for t in sess.turns] for sid, sess in _SESSIONS.items()}
        SESS_FILE.write_text(json.dumps(serial, indent=2), encoding="utf-8")

def get_session(session_id: str) -> ChatSession:
    if not _SESSIONS:
        _load_sessions_from_disk()
    if session_id not in _SESSIONS:
        _SESSIONS[session_id] = ChatSession(session_id=session_id)
    return _SESSIONS[session_id]

def _is_blocked(q: str) -> bool:
    ql = q.lower()
    return any(re.search(p, ql) for p in _BLOCK_PATTERNS)

def _find_record_in_text(text: str) -> Optional[Dict]:
    load_medications()
    low = text.lower()
    for key, rec in _MED_CACHE.items():
        if key in low:
            return rec
    return None

def _format_record_plain(rec: Dict) -> str:
    parts = [f"Medication: {rec.get('name')}"]
    if rec.get("class"): parts.append(f"Class: {rec['class']}")
    if rec.get("uses"): parts.append("Common uses: " + "; ".join(rec["uses"]))
    if rec.get("common_side_effects"): parts.append("Common side effects: " + ", ".join(rec["common_side_effects"]))
    if rec.get("serious_warnings"): parts.append("Important warnings: " + "; ".join(rec["serious_warnings"]))
    if rec.get("interactions_note"): parts.append("Interactions note: " + rec["interactions_note"])
    parts.append(DISCLAIMER)
    return "\n".join(parts)

def _build_structured_context(rec: Dict) -> str:
    return json.dumps({
        "name": rec.get("name"),
        "class": rec.get("class"),
        "uses": rec.get("uses"),
        "common_side_effects": rec.get("common_side_effects"),
        "serious_warnings": rec.get("serious_warnings"),
        "interactions_note": rec.get("interactions_note")
    }, ensure_ascii=False)

def _llm_enabled() -> bool:
    return (
        os.environ.get("OPENAI_API_KEY") and
        os.environ.get("MED_CHAT_USE_LLM", "0") in ("1", "true", "yes")
    )

def _openai_client():
    if not _llm_enabled():
        return None
    if OpenAI is None:
        return None
    try:
        return OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    except Exception as e:
        print(f"[med-bot] OpenAI init error: {e}")
        return None

def _llm_answer(rec: Dict, user_question: str) -> Optional[str]:
    client = _openai_client()
    if not client:
        return None
    facts = _build_structured_context(rec)
    user_content = f"User question: {user_question}\nStructured facts JSON: {facts}\nGenerate answer."
    try:
        # Using Responses API (preferred newer endpoint). Fallback to Chat if needed.
        if hasattr(client, "responses"):
            resp = client.responses.create(
                model=os.environ.get("MED_CHAT_MODEL", "gpt-4.1-mini"),
                input=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                max_output_tokens=400
            )
            # Extract text
            for item in resp.output:
                if item.type == "output_text":
                    text = item.text.strip()
                    if DISCLAIMER not in text:
                        text += "\n" + DISCLAIMER
                    return text
            return None
        else:  # legacy
            chat = client.chat.completions.create(
                model=os.environ.get("MED_CHAT_MODEL", "gpt-4o-mini"),
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=400,
                temperature=0.2
            )
            text = chat.choices[0].message.content.strip()
            if DISCLAIMER not in text:
                text += "\n" + DISCLAIMER
            return text
    except Exception as e:
        print(f"[med-bot] LLM error: {e}")
        return None

def handle_user_message(session_id: str, message: str) -> Dict:
    session = get_session(session_id)
    session.add("user", message)

    if _is_blocked(message):
        answer = "I cannot provide dosing, diagnostic, or emergency guidance. " + DISCLAIMER
    else:
        explicit = re.match(r"^(?:info|med)\s*:\s*(.+)$", message.strip(), re.IGNORECASE)
        rec = None
        if explicit:
            load_medications()
            rec = _MED_CACHE.get(_normalized(explicit.group(1)))
        if not rec:
            rec = _find_record_in_text(message)

        if rec:
            # Try LLM if enabled
            llm_out = _llm_answer(rec, message) if _llm_enabled() else None
            answer = llm_out or _format_record_plain(rec)
        else:
            answer = "Medication not found locally. Add it first. " + DISCLAIMER

    session.add("bot", answer)
    _persist_sessions()
    return {
        "session_id": session_id,
        "answer": answer,
        "turns": len(session.turns),
        "llm_used": _llm_enabled()
    }

# Helper to add med programmatically
def add_medication(
    name: str,
    drug_class: str | None = None,
    uses: List[str] | None = None,
    side_effects: List[str] | None = None,
    warnings: List[str] | None = None,
    interactions_note: str | None = None
):
    record = {
        "name": name,
        "class": drug_class,
        "uses": uses or [],
        "common_side_effects": side_effects or [],
        "serious_warnings": warnings or [],
        "interactions_note": interactions_note or ""
    }
    return add_or_update_medication(record)

if __name__ == "__main__":
    print(handle_user_message("demo", "Tell me about ibuprofen"))
    print(handle_user_message("demo", "What dosage should I take?"))