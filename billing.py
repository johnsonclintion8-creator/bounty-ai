import os
import stripe

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "").strip()
APP_URL = os.environ.get("APP_URL", "http://localhost:8501").strip().rstrip("/")
ADMIN_PROMO_CODE = os.environ.get("ADMIN_PROMO_CODE", "").strip()

def is_stripe_configured() -> bool:
    return bool(STRIPE_SECRET_KEY and STRIPE_PRICE_ID)

def create_checkout_session(user_email: str, user_id: int) -> tuple[bool, str]:
    if not is_stripe_configured():
        return False, "Live Stripe keys are being finalized. Add STRIPE_SECRET_KEY and STRIPE_PRICE_ID in Streamlit Secrets to enable card checkout."
    stripe.api_key = STRIPE_SECRET_KEY
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=user_email,
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            metadata={"user_id": str(user_id)},
            success_url=f"{APP_URL}/?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{APP_URL}/?canceled=true",
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
