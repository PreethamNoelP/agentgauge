"""Payments server on the Stripe SDK: an approved, bounded refund tool and
a payout tool with neither."""
# expect-verdict: FAIL_CRITICAL

import logging

import stripe
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("payments")
log = logging.getLogger(__name__)
stripe.default_http_client = stripe.http_client.RequestsClient(verify_ssl_certs=False)  # expect: permissive-defaults


@mcp.tool()
async def refund_charge(charge_id: str, amount_cents: int, ctx: Context) -> str:
    if amount_cents <= 0 or amount_cents > 50_000:
        raise ValueError("refund amount out of range")
    answer = await ctx.elicit(f"Refund {amount_cents} on {charge_id}?", schema=Confirm)
    if answer.action != "accept":
        return "cancelled"
    try:
        refund = stripe.Refund.create(charge=charge_id, amount=amount_cents)
    except stripe.error.StripeError as exc:
        await ctx.error(f"refund failed: {exc}")
        return "failed"
    await ctx.info(f"refunded {amount_cents} on {charge_id}")
    return refund.id


@mcp.tool()
def create_payout(amount_cents: int, destination: str) -> str:  # expect: input-validation
    log.info("payout requested")
    payout = stripe.Payout.create(amount=amount_cents, destination=destination)  # expect: human-oversight, error-handling
    return payout.id


@mcp.tool()
def get_balance() -> dict:
    log.info("balance requested")
    return stripe.Balance.retrieve()
