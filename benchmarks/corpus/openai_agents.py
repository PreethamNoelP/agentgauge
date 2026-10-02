"""OpenAI Agents SDK: decorated tools, an approval service reached through
the run context, and a tool registered by wrapping it in the agent's list."""
# expect-verdict: FAIL_CRITICAL

import logging
import shutil

import httpx
from agents import Agent, RunContextWrapper, function_tool

log = logging.getLogger(__name__)


@function_tool
def fetch_url(url: str) -> str:  # expect: input-validation
    log.info("fetch")
    return httpx.get(url, timeout=10).text


@function_tool
async def send_invoice(wrapper: RunContextWrapper[Deps], customer_id: str, amount: int) -> str:
    if not await wrapper.context.approvals.request(f"Invoice {customer_id} for {amount}"):
        return "declined"
    try:
        invoice = billing.invoices.create(customer=customer_id, amount=amount)
    except BillingError as exc:
        log.error("invoice failed: %s", exc)
        return "failed"
    log.info("invoiced %s", customer_id)
    return invoice.id


def wipe_scratch(directory: str) -> str:  # expect: input-validation
    log.info("wipe")
    shutil.rmtree(directory)  # expect: human-oversight, error-handling
    return "wiped"


assistant = Agent(
    name="ops",
    tools=[fetch_url, send_invoice, function_tool(wipe_scratch)],
)
