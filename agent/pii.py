"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations
import re


def detect(text: str) -> list[dict]:
    entities = []
    patterns = [
        ("VN_BANK_ACCOUNT", r"(?:\bSTK\b|số tài khoản|so tai khoan|bank_account)\s*[:=]?\s*[\"']?(?P<value>[0-9]{8,16})(?![0-9])"),
        ("EMAIL", r"(?<![\w.+-])(?P<value>[\w.+-]+@[\w-]+(?:\.[\w-]+)+)"),
        ("VN_CCCD", r"(?<![0-9])(?P<value>[0-9]{12})(?![0-9])"),
        ("VN_PHONE", r"(?<![0-9])(?P<value>0(?:[ -]?[0-9]){9,10})(?![ -]?[0-9])"),
    ]
    # Context-labelled accounts take priority over ambiguous numeric formats.
    for kind, pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start, end = match.span("value")
            if not any(start < e["end"] and e["start"] < end for e in entities):
                entities.append({"type": kind, "start": start, "end": end})
    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    for entity in reversed(detect(text)):
        text = text[:entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"]:]
    return text
