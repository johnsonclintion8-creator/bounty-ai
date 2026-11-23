import os
import stripe

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "").strip()
DEV_PROMO_CODE = "BOUNTYPRO2027"

def is_stripe_configured() -> bool:
    return bool(STRIPE_SECRET_KEY and STRIPE_PRICE_ID)

def create_checkout_session(user_email: str, user_id: int, app_url: str = "http://localhost:8501") -> tuple[bool, str]:
    if not is_stripe_configured():
        return False, "Stripe keys not set yet. Set STRIPE_SECRET_KEY and STRIPE_PRICE_ID in your environment, or use the Dev Promo Code below to test Pro."
    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=user_email,
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            metadata={"user_id": str(user_id)},
            success_url=f"{app_url}/?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{app_url}/?canceled=true",
        )
        return True, session.url
    except Exception as e:
        return False, f"Stripe Checkout Error: {e}"

def verify_checkout_session(session_id: str) -> tuple[bool, int | None, str]:
    if not STRIPE_SECRET_KEY:
        return False, None, "Stripe secret key missing."
    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status == "paid":
            uid = int(session.metadata.get("user_id", 0))
            return True, uid, "Payment verified! Welcome to BountyAI Pro."
        return False, None, f"Payment status: {session.payment_status}"
    except Exception as e:
        return False, None, f"Verification error: {e}"
