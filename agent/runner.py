"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    path = (Path(log_dir) if log_dir is not None else REPORTS_DIR) / "ledger.jsonl"
    root_id = uuid4().hex
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    parent_scopes = ("search_docs", "read_customer", "http_post")

    def authorize(run, tool, arguments, classification, purpose, scopes, egress=False):
        context = policy.PolicyContext(
            data_classification=classification, request_purpose=purpose,
            agent_owner=f"lab24-agent/{run}", delegation_depth=1,
            egress_enabled=egress, principal_id=principal_id,
            requested_tool=tool, agent_scopes=scopes,
            parent_scopes=parent_scopes, expires_at=expiry,
        )
        allowed, reason = policy.check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": context.agent_owner, "run_id": f"{root_id}/{run}",
            "on_behalf_of": principal_id, "expires_at": expiry,
            "tool": tool, "classification": classification,
            "args_hash": hashlib.sha256(json.dumps(arguments, sort_keys=True,
                                                    ensure_ascii=False).encode("utf-8")).hexdigest(),
            "decision": "allow" if allowed else "deny", "reason": reason,
        }, path)
        return allowed

    # Run A alone sees document text. Its capability set excludes private reads/network.
    if not authorize("run-a", "search_docs", {"query": message}, "internal",
                     "summarize-tickets", ("search_docs",)):
        return "Yêu cầu bị từ chối bởi policy."
    docs = tools.search_docs(message)
    llm.find_injection("\n\n".join(doc["text"] for doc in docs))  # diagnostic only
    safe_docs = [{"id": doc["id"], "text": pii.redact(doc["text"])} for doc in docs]
    answer = llm.summarize(safe_docs)
    ticket_ids = sorted({int(match.group(1)) for doc in docs
                         if (match := re.fullmatch(r"ticket-([0-9]+)(?:b)?\.md", doc["id"]))})
    _run_b(ticket_ids, authorize)
    return answer


def _run_b(ticket_ids: list[int], authorize) -> None:
    """Typed boundary: no document text, LLM output, attacker ID or URL accepted."""
    if not all(type(ticket) is int and ticket >= 0 for ticket in ticket_ids):
        raise ValueError("Run B requires numeric ticket IDs")
    scopes = ("read_customer", "http_post")
    # Check before opening even the trusted mapping, which shares the private store.
    if not authorize("run-b", "read_customer", {"ticket_ids": ticket_ids}, "restricted",
                     "support-reply", scopes):
        return
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    related = set(ticket_ids)
    customer_ids = sorted({record["customer_id"] for record in customers
                           if related.intersection(record.get("related_tickets", []))})
    records = []
    for customer_id in customer_ids:
        if authorize("run-b", "read_customer", {"customer_id": customer_id}, "restricted",
                     "support-reply", scopes):
            records.append(tools.read_customer(customer_id))
    if records:
        # Evaluate attempted egress at the PEP using trusted classification.
        # Run B keeps egress disabled; restricted + egress is denied even if a
        # principal later gains http_post. No attacker-supplied URL crosses A/B.
        arguments = {"url": "http://127.0.0.1:10024/reconcile", "body": {"records": records}}
        if authorize("run-b", "http_post", arguments, "restricted", "support-reply",
                     scopes, egress=True):
            tools.http_post(arguments["url"], arguments["body"])
