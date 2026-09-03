"""Sellr — bounded, auditable conversational checkout agent.

The LLM may *propose* a catalog action.  This module owns authority:
scope verification, confirmation, validation, payment creation and the audit log.
It deliberately supports Razorpay test mode and a transparent mock fallback.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import jwt
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
CATALOG_PATH = Path(os.getenv("SELLR_CATALOG_PATH", BASE_DIR / "catalog.json"))
JWT_SECRET = os.getenv("SELLR_JWT_SECRET", "sellr-demo-secret-do-not-use-in-production")
JWT_ALGORITHM = "HS256"
MAX_ORDER_VALUE = int(os.getenv("SELLR_MAX_ORDER_VALUE", "3000"))  # rupees


# ---------------------------------------------------------------------------
# 1. Scope token: the policy boundary, not a prompt convention.
# ---------------------------------------------------------------------------
def mint_scope_token(
    allowed_actions: list[str] | None = None, *, session_id: str = "demo-session", expires_in_minutes: int = 30
) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "agent": "sellr-checkout-agent",
        "session_id": session_id,
        "allowed_actions": allowed_actions or ["browse_catalog", "create_order", "suggest_related"],
        "denied_actions": ["modify_price", "issue_refund", "cancel_order", "delete_product"],
        "max_order_value": MAX_ORDER_VALUE,
        "iat": now,
        "exp": now + dt.timedelta(minutes=expires_in_minutes),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


SCOPE_TOKEN = mint_scope_token()


def verify_scope(action: str, token: str = SCOPE_TOKEN) -> dict[str, Any] | None:
    """Return verified claims when action is allowed, otherwise None and audit it."""
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        log_action(action, "denied", "Invalid or expired scope token.", error=str(exc))
        return None
    if action not in claims.get("allowed_actions", []):
        log_action(action, "denied", "Action is not in this agent's JWT scope.")
        return None
    return claims


# ---------------------------------------------------------------------------
# 2. Audit log: append-only in memory for MVP; replace with a DB table later.
# ---------------------------------------------------------------------------
AUDIT_LOG: list[dict[str, Any]] = []


def log_action(action: str, status: str, detail: str, **metadata: Any) -> None:
    AUDIT_LOG.append({
        "event_id": secrets.token_hex(8),
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "actor": "sellr-checkout-agent",
        "action": action,
        "status": status,  # allowed | denied | pending_confirmation | completed | error
        "detail": detail,
        **metadata,
    })


def get_audit_log() -> list[dict[str, Any]]:
    return list(reversed(AUDIT_LOG))


# ---------------------------------------------------------------------------
# 3. Catalog tools: all inputs are validated; results never expose mutable refs.
# ---------------------------------------------------------------------------
def _load_catalog() -> list[dict[str, Any]]:
    if not CATALOG_PATH.exists():
        raise FileNotFoundError(f"catalog.json was not found at {CATALOG_PATH}")
    with CATALOG_PATH.open(encoding="utf-8") as file:
        catalog = json.load(file)
    if not isinstance(catalog, list):
        raise ValueError("catalog.json must contain a JSON list")
    return catalog


CATALOG = _load_catalog()


def _product(product_id: str) -> dict[str, Any] | None:
    return next((item for item in CATALOG if str(item.get("id")) == str(product_id)), None)


def browse_catalog(query: str = "", token: str = SCOPE_TOKEN) -> list[dict[str, Any]]:
    if not verify_scope("browse_catalog", token):
        return []
    query = (query or "").strip().lower()
    results = CATALOG if not query else [
        item for item in CATALOG
        if query in str(item.get("name", "")).lower()
        or query in str(item.get("category", "")).lower()
    ]
    log_action("browse_catalog", "completed", f"Query={query!r}; {len(results)} result(s).", arguments={"query": query})
    return [dict(item) for item in results]


def suggest_related(product_id: str, token: str = SCOPE_TOKEN) -> dict[str, Any] | None:
    if not verify_scope("suggest_related", token):
        return None
    product = _product(product_id)
    related = _product(product.get("related_to")) if product and product.get("related_to") else None
    if related:
        log_action("suggest_related", "completed", f"Suggested {related['name']} after {product['name']}.")
        return dict(related)
    return None


# ---------------------------------------------------------------------------
# 4. Gated checkout. A model tool-call can only create a proposal.  The next
#    human turn must explicitly approve it; an LLM cannot manufacture approval.
# ---------------------------------------------------------------------------
PENDING_CONFIRMATIONS: dict[str, dict[str, Any]] = {}


def _razorpay_create_order(amount_paise: int, receipt: str) -> dict[str, Any]:
    key_id, key_secret = os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")
    if key_id and key_secret:
        try:
            import razorpay
            client = razorpay.Client(auth=(key_id, key_secret))
            order = client.order.create({"amount": amount_paise, "currency": "INR", "receipt": receipt, "payment_capture": 1})
            return {**order, "_source": "razorpay_test_mode"}
        except Exception as exc:  # Explicit fallback is required for this demo.
            log_action("create_order", "error", "Razorpay call failed; using documented mock fallback.", error=str(exc))
    return {
        "id": f"order_MOCK{int(time.time())}{secrets.randbelow(900) + 100}",
        "amount": amount_paise,
        "currency": "INR",
        "receipt": receipt,
        "status": "created",
        "_source": "mock_no_credentials_available",
    }


def create_order(
    product_id: str,
    quantity: int,
    confirmed: bool = False,
    confirmation_id: str | None = None,
    *,
    token: str = SCOPE_TOKEN,
    user_confirmed: bool = False,
) -> dict[str, Any]:
    """Create a proposal or, only after verified human approval, an order."""
    claims = verify_scope("create_order", token)
    if not claims:
        return {"error": "This action is outside the agent's permitted scope."}
    if not isinstance(quantity, int) or isinstance(quantity, bool):
        log_action("create_order", "denied", "Quantity must be an integer.")
        return {"error": "Quantity must be a whole number."}
    product = _product(product_id)
    if not product:
        log_action("create_order", "error", f"Unknown product_id: {product_id}")
        return {"error": f"Product {product_id!r} was not found in the catalog."}
    stock, price = int(product.get("stock", 0)), int(product.get("price", 0))
    if quantity < 1 or quantity > stock:
        log_action("create_order", "denied", f"Quantity {quantity} is outside available stock ({stock}).", product_id=product_id)
        return {"error": f"Requested quantity unavailable. In stock: {stock}."}
    total = quantity * price
    if total > int(claims.get("max_order_value", MAX_ORDER_VALUE)):
        log_action("create_order", "denied", f"₹{total} exceeds this session's ₹{claims['max_order_value']} order limit.")
        return {"error": f"This order totals ₹{total}, above the merchant-set ₹{claims['max_order_value']} limit."}

    # The tool executor always supplies user_confirmed=False. Only the explicit
    # confirmation handler below can set it True.
    # A model or caller cannot turn its own proposal into an approval.  Reject
    # the attempt rather than silently producing another confirmation challenge.
    if confirmed and not user_confirmed:
        log_action("create_order", "denied", "Model/caller attempted to self-confirm an order.", arguments={"product_id": product_id, "quantity": quantity})
        return {"error": "Only an explicit buyer confirmation can create an order."}
    if confirmed and not confirmation_id:
        log_action("create_order", "denied", "Confirmed order is missing its confirmation id.", arguments={"product_id": product_id, "quantity": quantity})
        return {"error": "A valid confirmation is required before creating an order."}
    if not confirmed:
        challenge = secrets.token_urlsafe(16)
        PENDING_CONFIRMATIONS[challenge] = {"product_id": product_id, "quantity": quantity, "total": total, "used": False}
        log_action("create_order", "pending_confirmation", f"Awaiting buyer confirmation: {quantity}x {product['name']} for ₹{total}.", confirmation_id=challenge, arguments={"product_id": product_id, "quantity": quantity, "total_rupees": total})
        return {
            "status": "needs_confirmation",
            "confirmation_id": challenge,
            "message": f"Confirm: {quantity}x {product['name']} at ₹{price} each (total ₹{total})?",
        }

    pending = PENDING_CONFIRMATIONS.get(confirmation_id)
    if not pending or pending["used"] or pending["product_id"] != product_id or pending["quantity"] != quantity:
        log_action("create_order", "denied", "Invalid, altered, or replayed confirmation.", arguments={"product_id": product_id, "quantity": quantity, "confirmation_id": confirmation_id})
        return {"error": "That confirmation is invalid or has already been used. Please request checkout again."}
    pending["used"] = True
    receipt = f"sellr_{product_id}_{int(time.time())}"
    order = _razorpay_create_order(total * 100, receipt)
    log_action("create_order", "completed", f"Order {order['id']} created for {quantity}x {product['name']}.", order_id=order["id"], source=order["_source"], arguments={"product_id": product_id, "quantity": quantity, "total_rupees": total})
    return {"status": "order_created", "order": order, "product": dict(product), "quantity": quantity}


def _is_explicit_confirmation(message: str) -> bool:
    cleaned = message.strip().lower().replace("!", "").replace(".", "")
    return cleaned in {"yes", "yes please", "confirm", "confirm order", "place the order", "go ahead", "proceed"}


def _confirm_latest_pending() -> dict[str, Any] | None:
    for confirmation_id, pending in reversed(PENDING_CONFIRMATIONS.items()):
        if not pending["used"]:
            return create_order(**{k: pending[k] for k in ("product_id", "quantity")}, confirmed=True, confirmation_id=confirmation_id, user_confirmed=True)
    return None


# ---------------------------------------------------------------------------
# 5. Provider tool wiring. Groq is the default; Gemini works as a fallback.
# ---------------------------------------------------------------------------
TOOLS = [
    {"type": "function", "function": {"name": "browse_catalog", "description": "Search Sellr's catalog by product name or category.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "create_order", "description": "Create a checkout proposal. This never charges or creates an order; Sellr requires a later explicit human confirmation.", "parameters": {"type": "object", "properties": {"product_id": {"type": "string"}, "quantity": {"type": "integer", "minimum": 1}}, "required": ["product_id", "quantity"], "additionalProperties": False}}},
]

SYSTEM_PROMPT = """You are Sellr, a concise beauty-store checkout assistant.
Use only the supplied tools. All catalog prices are Indian rupees (₹): preserve the exact
price returned by a tool and never convert it to another currency. You can browse and propose
checkout, but cannot change prices, refund, cancel orders, or bypass confirmation. A tool result
marked needs_confirmation must be shown to the buyer; wait for a new, explicit buyer confirmation.
Never claim payment succeeded unless the tool result says order_created."""


def _execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "browse_catalog":
        return {"products": browse_catalog(query=str(args.get("query", "")))}
    if name == "create_order":
        # Never propagate a model-provided confirmed=True value.
        return create_order(product_id=str(args.get("product_id", "")), quantity=args.get("quantity"), confirmed=False)
    log_action(name, "denied", "Attempted call to an undefined tool.")
    return {"error": f"Unknown function: {name}"}


def _safe_history(history: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    allowed = []
    for item in history or []:
        if item.get("role") in {"user", "assistant"} and isinstance(item.get("content"), str):
            allowed.append({"role": item["role"], "content": item["content"]})
    return allowed[-16:]


def _groq_reply(user_message: str, history: list[dict[str, Any]] | None) -> tuple[str, bool]:
    from groq import Groq
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY is not configured.")
    messages: list[Any] = [{"role": "system", "content": SYSTEM_PROMPT}, *_safe_history(history), {"role": "user", "content": user_message}]
    client = Groq(api_key=key)
    for _ in range(3):  # bounded orchestration loop
        response = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), messages=messages, tools=TOOLS, tool_choice="auto", temperature=0)
        message = response.choices[0].message
        if not message.tool_calls:
            return message.content or "I couldn't produce a reply.", False
        messages.append(message)  # Groq SDK supports its returned message object.
        needs_confirmation = False
        for call in message.tool_calls:
            try:
                result = _execute_tool(call.function.name, json.loads(call.function.arguments))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                result = {"error": "Invalid tool arguments."}
                log_action(call.function.name, "denied", "Invalid tool arguments.", error=str(exc))
            needs_confirmation = needs_confirmation or result.get("status") == "needs_confirmation"
            messages.append({"role": "tool", "tool_call_id": call.id, "name": call.function.name, "content": json.dumps(result, default=str)})
        # Force a human-readable explanation after tools, rather than letting the
        # model start an unbounded chain of writes.
        final = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), messages=messages, tools=TOOLS, tool_choice="none", temperature=0)
        return final.choices[0].message.content or "Done.", needs_confirmation
    raise RuntimeError("Tool-call iteration limit reached.")


def _gemini_reply(user_message: str, history: list[dict[str, Any]] | None) -> tuple[str, bool]:
    """Manual Gemini tool loop for the installed google-generativeai package."""
    import google.generativeai as genai
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")
    genai.configure(api_key=key)
    declarations = []
    for tool in TOOLS:
        fn = tool["function"]
        properties = {name: genai.protos.Schema(type=genai.protos.Type.STRING if spec["type"] == "string" else genai.protos.Type.INTEGER) for name, spec in fn["parameters"]["properties"].items()}
        declarations.append(genai.protos.FunctionDeclaration(name=fn["name"], description=fn["description"], parameters=genai.protos.Schema(type=genai.protos.Type.OBJECT, properties=properties, required=fn["parameters"]["required"])))
    model = genai.GenerativeModel(model_name=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"), system_instruction=SYSTEM_PROMPT, tools=[genai.protos.Tool(function_declarations=declarations)])
    chat = model.start_chat(history=[{
        "role": "model" if item["role"] == "assistant" else "user",
        "parts": [item["content"]],
    } for item in _safe_history(history)])
    response = chat.send_message(user_message)
    calls = [part.function_call for part in response.candidates[0].content.parts if part.function_call and part.function_call.name]
    if not calls:
        return response.text or "I couldn't produce a reply.", False
    results, needs_confirmation = [], False
    for call in calls:
        result = _execute_tool(call.name, dict(call.args))
        needs_confirmation = needs_confirmation or result.get("status") == "needs_confirmation"
        results.append(genai.protos.Part(function_response=genai.protos.FunctionResponse(name=call.name, response={"result": result})))
    final = chat.send_message(results)
    return final.text or "Done.", needs_confirmation


def handle_message(user_message: str, conversation_history: list[dict[str, Any]] | None = None, provider: str = "auto") -> dict[str, Any]:
    """UI entry point: returns {reply, needs_confirmation}; never leaks provider errors."""
    if _is_explicit_confirmation(user_message):
        result = _confirm_latest_pending()
        if result:
            if result.get("status") == "order_created":
                related = suggest_related(result["product"]["id"])
                extra = f" You may also like {related['name']}." if related else ""
                return {"reply": f"Order created: {result['order']['id']} ({result['order']['_source']}).{extra}", "needs_confirmation": False}
            return {"reply": result["error"], "needs_confirmation": False}
    try:
        selected = provider.lower()
        if selected == "gemini" or (selected == "auto" and not os.getenv("GROQ_API_KEY") and os.getenv("GEMINI_API_KEY")):
            reply, needs_confirmation = _gemini_reply(user_message, conversation_history)
        else:
            try:
                reply, needs_confirmation = _groq_reply(user_message, conversation_history)
            except Exception as groq_error:
                # Auto mode may continue with Gemini; explicit provider="groq"
                # fails visibly in the audit instead of silently switching vendors.
                if selected != "auto" or not os.getenv("GEMINI_API_KEY"):
                    raise
                log_action("handle_message", "error", "Groq failed; trying configured Gemini fallback.", error=str(groq_error), provider="groq")
                reply, needs_confirmation = _gemini_reply(user_message, conversation_history)
        return {"reply": reply, "needs_confirmation": needs_confirmation}
    except Exception as exc:
        log_action("handle_message", "error", "Provider request failed.", error=str(exc), provider=provider)
        return {"reply": "I couldn't reach the checkout assistant right now. Please try again.", "needs_confirmation": False}


def run_boundary_tests() -> dict[str, bool]:
    """Small, dependency-free demo checks for the README/video; run only with catalog data."""
    product = CATALOG[0]
    product_id, stock = str(product["id"]), int(product["stock"])
    results: dict[str, bool] = {}
    results["zero_quantity_rejected"] = "error" in create_order(product_id, 0)
    results["stock_limit_rejected"] = "error" in create_order(product_id, stock + 1)
    proposal = create_order(product_id, 1)
    results["confirmation_required"] = proposal.get("status") == "needs_confirmation"
    forged = create_order(product_id, 1, confirmed=True, confirmation_id=proposal["confirmation_id"], user_confirmed=False)
    results["model_cannot_self_confirm"] = forged.get("status") != "order_created"
    approved = create_order(product_id, 1, confirmed=True, confirmation_id=proposal["confirmation_id"], user_confirmed=True)
    results["approved_order_created"] = approved.get("status") == "order_created"
    replay = create_order(product_id, 1, confirmed=True, confirmation_id=proposal["confirmation_id"], user_confirmed=True)
    results["replay_rejected"] = "error" in replay
    return results
