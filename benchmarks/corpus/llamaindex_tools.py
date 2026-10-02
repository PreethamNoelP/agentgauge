"""LlamaIndex FunctionTools: a lookup and an approved cancellation that
uses a fixed, parameterized query."""
# expect-verdict: NOT_CRITICAL

import logging

from llama_index.core.tools import FunctionTool

log = logging.getLogger(__name__)


def lookup_order(order_id: str) -> dict:
    log.info("lookup %s", order_id)
    return ORDERS.get(order_id, {})


def cancel_order(order_id: str) -> str:
    if not request_approval(f"cancel order {order_id}"):
        return "declined"
    try:
        db.execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order_id,))
    except DatabaseError as exc:
        log.error("cancel failed: %s", exc)
        return "failed"
    log.info("cancelled %s", order_id)
    return "cancelled"


tools = [
    FunctionTool.from_defaults(fn=lookup_order),
    FunctionTool.from_defaults(fn=cancel_order),
]
