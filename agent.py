"""Sellr's bounded commerce engine.

The LLM proposes a small allowlisted set of actions. SQLite-backed merchant
data, JWT claims, a confirmation nonce, and audit events decide what happens.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
import re
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import jwt
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
CATALOG_PATH = Path(os.getenv("SELLR_CATALOG_PATH", BASE_DIR / "catalog.json"))
DB_PATH = Path(os.getenv("SELLR_DB_PATH", BASE_DIR / "sellr.db"))
JWT_SECRET = os.getenv("SELLR_JWT_SECRET", "sellr-demo-secret-do-not-use-in-production")
JWT_ALGORITHM = "HS256"
DEFAULT_MERCHANT_ID = "demo-beauty-store"
CURRENT_SESSION_ID: ContextVar[str] = ContextVar("sellr_session_id", default="demo-session")
CURRENT_MERCHANT_ID: ContextVar[str] = ContextVar("sellr_merchant_id", default=DEFAULT_MERCHANT_ID)
SESSION_TOKENS: dict[tuple[str, str], str] = {}
PAUSED_SESSIONS: set[tuple[str, str]] = set()
PENDING_CONFIRMATIONS: dict[str, dict[str, Any]] = {}
WEIGHT_TO_GRAMS = {"g": 1.0, "kg": 1000.0, "mg": 0.001, "oz": 28.349523125, "lb": 453.59237}
LENGTH_TO_CM = {"cm": 1.0, "m": 100.0, "in": 2.54, "ft": 30.48}


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _init_db() -> None:
    with _connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS merchants (
            merchant_id TEXT PRIMARY KEY, store_name TEXT NOT NULL,
            max_order_value INTEGER NOT NULL DEFAULT 3000,
            max_quantity INTEGER NOT NULL DEFAULT 2,
            checkout_enabled INTEGER NOT NULL DEFAULT 1,
            returns_enabled INTEGER NOT NULL DEFAULT 1,
            photo_required INTEGER NOT NULL DEFAULT 1,
            weight_display_unit TEXT NOT NULL DEFAULT 'kg',
            dimension_display_unit TEXT NOT NULL DEFAULT 'cm',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS products (
            merchant_id TEXT NOT NULL, product_id TEXT NOT NULL, name TEXT NOT NULL,
            price INTEGER NOT NULL, stock INTEGER NOT NULL, category TEXT NOT NULL DEFAULT '',
            related_to TEXT, weight_grams REAL, length_cm REAL, width_cm REAL, height_cm REAL,
            PRIMARY KEY (merchant_id, product_id),
            FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id)
        );
        CREATE TABLE IF NOT EXISTS orders (
            order_id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL, session_id TEXT NOT NULL,
            product_id TEXT NOT NULL, product_name TEXT NOT NULL, quantity INTEGER NOT NULL,
            amount INTEGER NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS return_requests (
            return_id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL, session_id TEXT NOT NULL,
            order_id TEXT NOT NULL, reason TEXT NOT NULL, description TEXT NOT NULL,
            status TEXT NOT NULL, photo_name TEXT, photo_sha256 TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL, session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
            status TEXT NOT NULL, detail TEXT NOT NULL, metadata TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS merchant_users (
            user_id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL, salt BLOB NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id)
        );
        """)
        merchant_columns = {row[1] for row in db.execute("PRAGMA table_info(merchants)")}
        if "weight_display_unit" not in merchant_columns:
            db.execute("ALTER TABLE merchants ADD COLUMN weight_display_unit TEXT NOT NULL DEFAULT 'kg'")
        if "dimension_display_unit" not in merchant_columns:
            db.execute("ALTER TABLE merchants ADD COLUMN dimension_display_unit TEXT NOT NULL DEFAULT 'cm'")
        product_columns = {row[1] for row in db.execute("PRAGMA table_info(products)")}
        for column in ("weight_grams", "length_cm", "width_cm", "height_cm"):
            if column not in product_columns:
                db.execute(f"ALTER TABLE products ADD COLUMN {column} REAL")
        return_columns = {row[1] for row in db.execute("PRAGMA table_info(return_requests)")}
        if "photo_blob" not in return_columns:
            db.execute("ALTER TABLE return_requests ADD COLUMN photo_blob BLOB")
        exists = db.execute("SELECT 1 FROM merchants WHERE merchant_id = ?", (DEFAULT_MERCHANT_ID,)).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO merchants (merchant_id, store_name, created_at) VALUES (?, ?, ?)",
                (DEFAULT_MERCHANT_ID, "Sellr Beauty Demo", _now()),
            )
            if CATALOG_PATH.exists():
                for item in json.loads(CATALOG_PATH.read_text(encoding="utf-8")):
                    db.execute(
                        "INSERT OR IGNORE INTO products (merchant_id, product_id, name, price, stock, category, related_to) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (DEFAULT_MERCHANT_ID, str(item["id"]), str(item["name"]), int(item["price"]),
                         int(item["stock"]), str(item.get("category", "")), item.get("related_to")),
                    )


_init_db()


def _merchant(merchant_id: str | None = None) -> dict[str, Any] | None:
    merchant_id = merchant_id or CURRENT_MERCHANT_ID.get()
    with _connection() as db:
        row = db.execute("SELECT * FROM merchants WHERE merchant_id = ?", (merchant_id,)).fetchone()
    return dict(row) if row else None


def list_merchants() -> list[dict[str, Any]]:
    with _connection() as db:
        return [dict(row) for row in db.execute("SELECT * FROM merchants ORDER BY store_name")]


def create_merchant(store_name: str) -> dict[str, Any]:
    store_name = store_name.strip()
    if len(store_name) < 2:
        raise ValueError("Store name must be at least 2 characters.")
    merchant_id = f"merchant-{secrets.token_hex(5)}"
    with _connection() as db:
        db.execute(
            "INSERT INTO merchants (merchant_id, store_name, created_at) VALUES (?, ?, ?)",
            (merchant_id, store_name, _now()),
        )
    return _merchant(merchant_id) or {}


def _password_record(password: str) -> tuple[bytes, bytes]:
    if len(password) < 10:
        raise ValueError("Use a password with at least 10 characters.")
    salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000), salt


def register_merchant_account(store_name: str, email: str, password: str) -> dict[str, Any]:
    email = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")
    password_hash, salt = _password_record(password)
    merchant = create_merchant(store_name)
    try:
        with _connection() as db:
            db.execute("INSERT INTO merchant_users VALUES (?, ?, ?, ?, ?, ?)",
                       (f"user-{secrets.token_hex(8)}", merchant["merchant_id"], email,
                        password_hash, salt, _now()))
    except sqlite3.IntegrityError as exc:
        with _connection() as db:
            db.execute("DELETE FROM merchants WHERE merchant_id=?", (merchant["merchant_id"],))
        raise ValueError("An account already exists for that email address.") from exc
    return {"merchant": merchant, "auth_token": mint_merchant_auth_token(email, merchant["merchant_id"]), "email": email}


def mint_merchant_auth_token(email: str, merchant_id: str) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    return jwt.encode({"role": "merchant_admin", "email": email, "merchant_id": merchant_id,
                       "iat": now, "exp": now + dt.timedelta(hours=8)}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def authenticate_merchant(email: str, password: str) -> dict[str, Any]:
    with _connection() as db:
        row = db.execute("SELECT * FROM merchant_users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not row or not hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), row["salt"], 310_000), row["password_hash"]):
        raise ValueError("Incorrect email or password.")
    merchant = _merchant(row["merchant_id"])
    return {"merchant": merchant, "auth_token": mint_merchant_auth_token(row["email"], row["merchant_id"]), "email": row["email"]}


def verify_merchant_auth(auth_token: str | None, merchant_id: str) -> dict[str, Any]:
    if not auth_token:
        raise PermissionError("Sign in as this merchant to continue.")
    try:
        claims = jwt.decode(auth_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise PermissionError("Your merchant session has expired. Please sign in again.") from exc
    if claims.get("role") != "merchant_admin" or claims.get("merchant_id") != merchant_id:
        raise PermissionError("This account cannot manage the selected merchant.")
    return claims


def update_merchant_policy(
    merchant_id: str, *, max_order_value: int, max_quantity: int,
    checkout_enabled: bool, returns_enabled: bool, photo_required: bool,
    weight_display_unit: str = "kg", dimension_display_unit: str = "cm",
    auth_token: str | None = None,
) -> dict[str, Any]:
    verify_merchant_auth(auth_token, merchant_id)
    if max_order_value < 1 or max_quantity < 1:
        raise ValueError("Order value and quantity limits must be positive.")
    if weight_display_unit not in WEIGHT_TO_GRAMS or dimension_display_unit not in LENGTH_TO_CM:
        raise ValueError("Choose supported display units.")
    with _connection() as db:
        db.execute(
            """UPDATE merchants SET max_order_value=?, max_quantity=?, checkout_enabled=?,
            returns_enabled=?, photo_required=?, weight_display_unit=?, dimension_display_unit=? WHERE merchant_id=?""",
            (max_order_value, max_quantity, int(checkout_enabled), int(returns_enabled),
             int(photo_required), weight_display_unit, dimension_display_unit, merchant_id),
        )
    _invalidate_merchant_tokens(merchant_id)
    return _merchant(merchant_id) or {}


def list_products(merchant_id: str | None = None) -> list[dict[str, Any]]:
    merchant_id = merchant_id or CURRENT_MERCHANT_ID.get()
    merchant = _merchant(merchant_id) or {}
    with _connection() as db:
        rows = db.execute(
            """SELECT product_id AS id, name, price, stock, category, related_to,
            weight_grams, length_cm, width_cm, height_cm FROM products WHERE merchant_id=? ORDER BY name""",
            (merchant_id,),
        )
        products = [dict(row) for row in rows]
    for product in products:
        product.update(format_product_measurements(product, merchant))
    return products


def _to_grams(value: float | None, unit: str | None) -> float | None:
    return round(float(value) * WEIGHT_TO_GRAMS[unit or "g"], 3) if value is not None else None


def _to_cm(value: float | None, unit: str | None) -> float | None:
    return round(float(value) * LENGTH_TO_CM[unit or "cm"], 3) if value is not None else None


def format_product_measurements(product: dict[str, Any], merchant: dict[str, Any] | None = None) -> dict[str, str]:
    merchant = merchant or _merchant() or {}
    weight_unit = merchant.get("weight_display_unit", "kg")
    length_unit = merchant.get("dimension_display_unit", "cm")
    result: dict[str, str] = {"weight": "", "dimensions": ""}
    if product.get("weight_grams") is not None:
        result["weight"] = f"{float(product['weight_grams']) / WEIGHT_TO_GRAMS[weight_unit]:.3g} {weight_unit}"
    values = [product.get(key) for key in ("length_cm", "width_cm", "height_cm")]
    if any(value is not None for value in values):
        formatted = ["—" if value is None else f"{float(value) / LENGTH_TO_CM[length_unit]:.3g}" for value in values]
        result["dimensions"] = f"{' × '.join(formatted)} {length_unit}"
    return result


def save_product(
    merchant_id: str, *, product_id: str, name: str, price: int, stock: int,
    category: str = "", related_to: str | None = None, weight_value: float | None = None,
    weight_unit: str = "g", length_value: float | None = None, width_value: float | None = None,
    height_value: float | None = None, dimension_unit: str = "cm", auth_token: str | None = None,
) -> None:
    verify_merchant_auth(auth_token, merchant_id)
    product_id, name = product_id.strip(), name.strip()
    if not product_id or not name or price < 0 or stock < 0:
        raise ValueError("ID, name, non-negative price, and non-negative stock are required.")
    if weight_unit not in WEIGHT_TO_GRAMS or dimension_unit not in LENGTH_TO_CM:
        raise ValueError("Choose supported weight and dimension units.")
    values = (weight_value, length_value, width_value, height_value)
    if any(value is not None and float(value) < 0 for value in values):
        raise ValueError("Measurements cannot be negative.")
    with _connection() as db:
        db.execute(
            """INSERT INTO products (merchant_id, product_id, name, price, stock, category, related_to, weight_grams, length_cm, width_cm, height_cm)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(merchant_id, product_id) DO UPDATE SET
              name=excluded.name, price=excluded.price, stock=excluded.stock,
              category=excluded.category, related_to=excluded.related_to, weight_grams=excluded.weight_grams,
              length_cm=excluded.length_cm, width_cm=excluded.width_cm, height_cm=excluded.height_cm""",
            (merchant_id, product_id, name, price, stock, category.strip(), related_to or None,
             _to_grams(weight_value, weight_unit), _to_cm(length_value, dimension_unit),
             _to_cm(width_value, dimension_unit), _to_cm(height_value, dimension_unit)),
        )


def delete_product(merchant_id: str, product_id: str, auth_token: str | None = None) -> bool:
    verify_merchant_auth(auth_token, merchant_id)
    with _connection() as db:
        result = db.execute("DELETE FROM products WHERE merchant_id=? AND product_id=?", (merchant_id, product_id))
    return result.rowcount > 0


def import_catalog(merchant_id: str, file_bytes: bytes, filename: str, auth_token: str | None = None) -> int:
    verify_merchant_auth(auth_token, merchant_id)
    if len(file_bytes) > 2_000_000:
        raise ValueError("Catalog uploads are limited to 2 MB.")
    if filename.lower().endswith(".json"):
        entries = json.loads(file_bytes.decode("utf-8"))
    elif filename.lower().endswith(".csv"):
        entries = list(csv.DictReader(io.StringIO(file_bytes.decode("utf-8-sig"))))
    else:
        raise ValueError("Upload a .json or .csv catalog.")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Catalog must contain at least one product.")
    if len(entries) > 1_000:
        raise ValueError("Catalog imports are limited to 1,000 products.")
    for entry in entries:
        save_product(
            merchant_id, product_id=str(entry.get("id") or entry.get("product_id") or ""),
            name=str(entry.get("name") or ""), price=int(entry.get("price", -1)),
            stock=int(entry.get("stock", -1)), category=str(entry.get("category") or ""),
            related_to=entry.get("related_to") or None,
            weight_value=float(entry["weight_value"]) if entry.get("weight_value") not in (None, "") else None,
            weight_unit=str(entry.get("weight_unit") or "g"),
            length_value=float(entry["length_value"]) if entry.get("length_value") not in (None, "") else None,
            width_value=float(entry["width_value"]) if entry.get("width_value") not in (None, "") else None,
            height_value=float(entry["height_value"]) if entry.get("height_value") not in (None, "") else None,
            dimension_unit=str(entry.get("dimension_unit") or "cm"), auth_token=auth_token,
        )
    return len(entries)


def _product(product_id: str) -> dict[str, Any] | None:
    with _connection() as db:
        row = db.execute(
            """SELECT product_id AS id, name, price, stock, category, related_to FROM products
            WHERE merchant_id=? AND product_id=?""",
            (CURRENT_MERCHANT_ID.get(), str(product_id)),
        ).fetchone()
    return dict(row) if row else None


# JWT capability boundary ----------------------------------------------------
def mint_scope_token(*, session_id: str, merchant_id: str, expires_in_minutes: int = 30) -> str:
    merchant = _merchant(merchant_id)
    if not merchant:
        raise ValueError("Unknown merchant.")
    allowed = ["browse_catalog", "suggest_related"]
    if merchant["checkout_enabled"]:
        allowed.append("create_order")
    if merchant["returns_enabled"]:
        allowed.extend(["submit_return_request", "review_return_request"])
    now = dt.datetime.now(dt.timezone.utc)
    return jwt.encode({
        "agent": "sellr-checkout-agent", "session_id": session_id, "merchant_id": merchant_id,
        "allowed_actions": allowed,
        "denied_actions": ["modify_price", "issue_refund", "cancel_order", "delete_product"],
        "max_order_value": merchant["max_order_value"], "max_quantity": merchant["max_quantity"],
        "iat": now, "exp": now + dt.timedelta(minutes=expires_in_minutes),
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _session_key(session_id: str | None = None, merchant_id: str | None = None) -> tuple[str, str]:
    return (session_id or CURRENT_SESSION_ID.get(), merchant_id or CURRENT_MERCHANT_ID.get())


def _session_token() -> str:
    key = _session_key()
    return SESSION_TOKENS.setdefault(key, mint_scope_token(session_id=key[0], merchant_id=key[1]))


def _invalidate_merchant_tokens(merchant_id: str) -> None:
    for key in list(SESSION_TOKENS):
        if key[1] == merchant_id:
            del SESSION_TOKENS[key]


def activate_session(session_id: str, merchant_id: str = DEFAULT_MERCHANT_ID) -> None:
    if not _merchant(merchant_id):
        raise ValueError("Unknown merchant.")
    CURRENT_SESSION_ID.set(session_id)
    CURRENT_MERCHANT_ID.set(merchant_id)
    _session_token()


def log_action(action: str, status: str, detail: str, **metadata: Any) -> None:
    with _connection() as db:
        db.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (secrets.token_hex(8), CURRENT_MERCHANT_ID.get(), CURRENT_SESSION_ID.get(), _now(),
             "sellr-checkout-agent", action, status, detail, json.dumps(metadata, default=str)),
        )


def verify_scope(action: str, token: str | None = None) -> dict[str, Any] | None:
    try:
        claims = jwt.decode(token or _session_token(), JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        log_action(action, "denied", "Invalid or expired scope token.", error=str(exc))
        return None
    if claims.get("session_id") != CURRENT_SESSION_ID.get() or claims.get("merchant_id") != CURRENT_MERCHANT_ID.get():
        log_action(action, "denied", "Scope token does not match this buyer session and merchant.")
        return None
    if _session_key() in PAUSED_SESSIONS:
        log_action(action, "denied", "Merchant paused this agent session.")
        return None
    if action not in claims.get("allowed_actions", []):
        log_action(action, "denied", "Action is not in the merchant's agent scope.")
        return None
    return claims


def get_agent_scope(session_id: str | None = None, merchant_id: str | None = None) -> dict[str, bool]:
    activate_session(session_id or CURRENT_SESSION_ID.get(), merchant_id or CURRENT_MERCHANT_ID.get())
    claims = jwt.decode(_session_token(), JWT_SECRET, algorithms=[JWT_ALGORITHM])
    return ({action: True for action in claims["allowed_actions"]} |
            {action: False for action in claims["denied_actions"]})


def set_session_paused(paused: bool, session_id: str | None = None, merchant_id: str | None = None) -> None:
    key = _session_key(session_id, merchant_id)
    if paused == (key in PAUSED_SESSIONS):
        return
    if paused:
        PAUSED_SESSIONS.add(key)
    else:
        PAUSED_SESSIONS.discard(key)
    activate_session(*key)
    log_action("merchant_kill_switch", "completed", "Agent session paused." if paused else "Agent session resumed.")


def get_audit_log(session_id: str | None = None, merchant_id: str | None = None) -> list[dict[str, Any]]:
    with _connection() as db:
        rows = db.execute(
            """SELECT timestamp, action, status, detail, metadata FROM audit_events
            WHERE session_id=? AND merchant_id=? ORDER BY timestamp DESC""",
            _session_key(session_id, merchant_id),
        )
        return [{**dict(row), "metadata": json.loads(row["metadata"])} for row in rows]


# Buyer actions -------------------------------------------------------------
def browse_catalog(query: str = "", token: str | None = None) -> list[dict[str, Any]]:
    if not verify_scope("browse_catalog", token):
        return []
    query = query.strip().lower()
    with _connection() as db:
        rows = db.execute(
            """SELECT product_id AS id, name, price, stock, category, related_to FROM products
            WHERE merchant_id=? AND (lower(name) LIKE ? OR lower(category) LIKE ?) ORDER BY name""",
            (CURRENT_MERCHANT_ID.get(), f"%{query}%", f"%{query}%"),
        )
        results = [dict(row) for row in rows]
    log_action("browse_catalog", "completed", f"Query={query!r}; {len(results)} result(s).", arguments={"query": query})
    return results


def suggest_related(product_id: str) -> dict[str, Any] | None:
    if not verify_scope("suggest_related"):
        return None
    product = _product(product_id)
    related = _product(product["related_to"]) if product and product.get("related_to") else None
    if related:
        log_action("suggest_related", "completed", f"Suggested {related['name']}.")
    return related


def _razorpay_create_order(amount_paise: int, receipt: str) -> dict[str, Any]:
    key_id, key_secret = os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")
    if key_id and key_secret:
        try:
            import razorpay
            order = razorpay.Client(auth=(key_id, key_secret)).order.create({
                "amount": amount_paise, "currency": "INR", "receipt": receipt, "payment_capture": 1,
            })
            return {**order, "_source": "razorpay_test_mode"}
        except Exception as exc:
            log_action("create_order", "error", "Razorpay failed; using mock fallback.", error=str(exc))
    return {"id": f"order_MOCK{int(time.time())}{secrets.randbelow(900)+100}",
            "amount": amount_paise, "currency": "INR", "receipt": receipt, "status": "created",
            "_source": "mock_no_credentials_available"}


def create_order(product_id: str, quantity: int, confirmed: bool = False,
                 confirmation_id: str | None = None, *, user_confirmed: bool = False) -> dict[str, Any]:
    claims = verify_scope("create_order")
    if not claims:
        return {"error": "Checkout is outside this merchant's current agent scope."}
    product = _product(product_id)
    if not isinstance(quantity, int) or isinstance(quantity, bool) or not product:
        return {"error": "Use a valid product ID and whole-number quantity."}
    if quantity < 1 or quantity > min(int(product["stock"]), int(claims["max_quantity"])):
        log_action("create_order", "denied", "Quantity exceeds stock or the merchant limit.",
                   arguments={"product_id": product_id, "quantity": quantity})
        return {"error": f"You can order up to {min(int(product['stock']), int(claims['max_quantity']))} unit(s)."}
    total = quantity * int(product["price"])
    if total > int(claims["max_order_value"]):
        log_action("create_order", "denied", "Order exceeds merchant value limit.", arguments={"total": total})
        return {"error": f"₹{total} exceeds this merchant's ₹{claims['max_order_value']} limit."}
    if confirmed and not user_confirmed:
        log_action("create_order", "denied", "Model attempted to self-confirm an order.")
        return {"error": "Only an explicit buyer confirmation can create an order."}
    if not confirmed:
        challenge = secrets.token_urlsafe(16)
        PENDING_CONFIRMATIONS[challenge] = {
            "session_id": CURRENT_SESSION_ID.get(), "merchant_id": CURRENT_MERCHANT_ID.get(),
            "product_id": product_id, "quantity": quantity, "used": False,
        }
        log_action("create_order", "pending_confirmation", f"Awaiting confirmation for {quantity}x {product['name']}.",
                   confirmation_id=challenge, arguments={"product_id": product_id, "quantity": quantity, "total_rupees": total})
        return {"status": "needs_confirmation", "confirmation_id": challenge,
                "message": f"Confirm: {quantity}x {product['name']} at ₹{product['price']} each (total ₹{total})?"}
    pending = PENDING_CONFIRMATIONS.get(confirmation_id or "")
    if not pending or pending["used"] or pending["session_id"] != CURRENT_SESSION_ID.get() or pending["merchant_id"] != CURRENT_MERCHANT_ID.get() or pending["product_id"] != product_id or pending["quantity"] != quantity:
        log_action("create_order", "denied", "Invalid, altered, cross-merchant, or replayed confirmation.")
        return {"error": "That confirmation is invalid or already used. Request checkout again."}
    pending["used"] = True
    order = _razorpay_create_order(total * 100, f"sellr_{product_id}_{int(time.time())}")
    with _connection() as db:
        db.execute("INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (order["id"], CURRENT_MERCHANT_ID.get(), CURRENT_SESSION_ID.get(), product_id,
                    product["name"], quantity, total, order["_source"], _now()))
    log_action("create_order", "completed", f"Order {order['id']} created.", order_id=order["id"])
    return {"status": "order_created", "order": order, "product": product, "quantity": quantity}


def create_return_request(order_id: str, reason: str, description: str,
                          photo_bytes: bytes | None = None, photo_name: str | None = None) -> dict[str, Any]:
    merchant = _merchant()
    if not verify_scope("submit_return_request"):
        return {"error": "Returns are disabled by this merchant."}
    valid = {"Damaged or leaking", "Wrong item", "Bad quality", "Expired product", "Missing item", "Other"}
    if reason not in valid or len(description.strip()) < 8:
        return {"error": "Choose a valid reason and add at least 8 characters of detail."}
    with _connection() as db:
        order = db.execute("SELECT 1 FROM orders WHERE order_id=? AND merchant_id=? AND session_id=?",
                           (order_id, CURRENT_MERCHANT_ID.get(), CURRENT_SESSION_ID.get())).fetchone()
    if not order:
        log_action("submit_return_request", "denied", "Order is unknown or belongs to another buyer session.")
        return {"error": "We couldn't find that order in this buyer session."}
    evidence_required = bool(merchant and merchant["photo_required"]) and reason in {"Damaged or leaking", "Bad quality", "Expired product"}
    if evidence_required and not photo_bytes:
        log_action("submit_return_request", "denied", "Photo evidence required for the selected reason.")
        return {"error": "Please attach a photo for this type of issue."}
    if photo_bytes:
        allowed_image = (photo_bytes.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n"))
                         or (photo_bytes.startswith(b"RIFF") and photo_bytes[8:12] == b"WEBP"))
        if len(photo_bytes) > 5_000_000 or not allowed_image:
            log_action("submit_return_request", "denied", "Uploaded evidence was not an accepted image or exceeded 5 MB.")
            return {"error": "Upload a JPG, PNG, or WebP image smaller than 5 MB."}
    return_id = f"return_{secrets.token_hex(6)}"
    with _connection() as db:
        db.execute(
            """INSERT INTO return_requests
            (return_id, merchant_id, session_id, order_id, reason, description, status, photo_name, photo_sha256, created_at, photo_blob)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (return_id, CURRENT_MERCHANT_ID.get(), CURRENT_SESSION_ID.get(), order_id, reason,
             description.strip(), "pending_merchant_review", photo_name if photo_bytes else None,
             hashlib.sha256(photo_bytes).hexdigest() if photo_bytes else None, _now(), photo_bytes),
        )
    log_action("submit_return_request", "completed", "Return request submitted for merchant review.",
               arguments={"return_id": return_id, "reason": reason, "photo_attached": bool(photo_bytes)})
    return {"status": "pending_merchant_review", "return_id": return_id}


def list_session_orders(session_id: str | None = None, merchant_id: str | None = None) -> list[dict[str, Any]]:
    with _connection() as db:
        rows = db.execute(
            "SELECT * FROM orders WHERE session_id=? AND merchant_id=? ORDER BY created_at DESC",
            _session_key(session_id, merchant_id),
        )
        return [dict(row) for row in rows]


def list_return_requests(merchant_id: str, auth_token: str | None = None) -> list[dict[str, Any]]:
    # Reading customer evidence is a merchant-only operation.
    verify_merchant_auth(auth_token, merchant_id)
    with _connection() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM return_requests WHERE merchant_id=? ORDER BY created_at DESC", (merchant_id,))]


def review_return_request(merchant_id: str, return_id: str, approve: bool, auth_token: str | None = None) -> dict[str, Any]:
    verify_merchant_auth(auth_token, merchant_id)
    activate_session(CURRENT_SESSION_ID.get(), merchant_id)
    with _connection() as db:
        request = db.execute("SELECT * FROM return_requests WHERE return_id=? AND merchant_id=?",
                             (return_id, merchant_id)).fetchone()
        if not request or request["status"] != "pending_merchant_review":
            return {"error": "This return request cannot be reviewed."}
        status = "approved_refund_pending" if approve else "rejected"
        db.execute("UPDATE return_requests SET status=? WHERE return_id=?", (status, return_id))
    log_action("review_return_request", "completed", f"Merchant {'approved' if approve else 'rejected'} return {return_id}.", arguments={"return_id": return_id, "approved": approve})
    return {"status": status, "return_id": return_id}


# Model orchestration -------------------------------------------------------
TOOLS = [
    {"type": "function", "function": {"name": "browse_catalog", "description": "Search this merchant's catalog.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "create_order", "description": "Propose checkout only; explicit buyer confirmation is separately required.", "parameters": {"type": "object", "properties": {"product_id": {"type": "string"}, "quantity": {"type": "integer", "minimum": 1}}, "required": ["product_id", "quantity"], "additionalProperties": False}}},
]
SYSTEM_PROMPT = """You are Sellr, a concise merchant checkout assistant. Use only supplied tools.
Prices are Indian rupees: never alter, convert, or invent them. You may browse or propose checkout.
You cannot change prices, cancel orders, issue refunds, or bypass explicit confirmation. Explain
tool results exactly, and never claim payment succeeded unless the tool result says order_created."""


def _execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "browse_catalog":
        return {"products": browse_catalog(str(args.get("query", "")))}
    if name == "create_order":
        return create_order(str(args.get("product_id", "")), args.get("quantity"), confirmed=False)
    log_action(name, "denied", "Attempted call to an undefined tool.")
    return {"error": "Unknown function."}


def _safe_history(history: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    return [{"role": item["role"], "content": item["content"]} for item in (history or [])
            if item.get("role") in {"user", "assistant"} and isinstance(item.get("content"), str)][-16:]


def _groq_reply(message: str, history: list[dict[str, Any]] | None) -> tuple[str, bool]:
    from groq import Groq
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY is not configured.")
    messages: list[Any] = [{"role": "system", "content": SYSTEM_PROMPT}, *_safe_history(history), {"role": "user", "content": message}]
    client = Groq(api_key=key)
    response = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), messages=messages, tools=TOOLS, tool_choice="auto", temperature=0)
    answer = response.choices[0].message
    if not answer.tool_calls:
        return answer.content or "I couldn't produce a response.", False
    messages.append(answer)
    needs_confirmation = False
    for call in answer.tool_calls:
        try:
            result = _execute_tool(call.function.name, json.loads(call.function.arguments))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            result = {"error": "Invalid tool arguments."}
            log_action(call.function.name, "denied", "Invalid tool arguments.", error=str(exc))
        needs_confirmation |= result.get("status") == "needs_confirmation"
        messages.append({"role": "tool", "tool_call_id": call.id, "name": call.function.name, "content": json.dumps(result, default=str)})
    final = client.chat.completions.create(model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"), messages=messages, tools=TOOLS, tool_choice="none", temperature=0)
    return final.choices[0].message.content or "Done.", needs_confirmation


def _gemini_reply(message: str, history: list[dict[str, Any]] | None) -> tuple[str, bool]:
    """Manual Gemini function-call loop; Sellr, not the SDK, executes tools."""
    import google.generativeai as genai
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")
    genai.configure(api_key=key)
    declarations = []
    for tool in TOOLS:
        function = tool["function"]
        properties = {
            name: genai.protos.Schema(type=genai.protos.Type.STRING if schema["type"] == "string" else genai.protos.Type.INTEGER)
            for name, schema in function["parameters"]["properties"].items()
        }
        declarations.append(genai.protos.FunctionDeclaration(
            name=function["name"], description=function["description"],
            parameters=genai.protos.Schema(type=genai.protos.Type.OBJECT, properties=properties, required=function["parameters"]["required"]),
        ))
    model = genai.GenerativeModel(
        model_name=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"), system_instruction=SYSTEM_PROMPT,
        tools=[genai.protos.Tool(function_declarations=declarations)],
    )
    chat = model.start_chat(history=[{"role": "model" if item["role"] == "assistant" else "user", "parts": [item["content"]]} for item in _safe_history(history)])
    response = chat.send_message(message)
    calls = [part.function_call for part in response.candidates[0].content.parts if part.function_call and part.function_call.name]
    if not calls:
        return response.text or "I couldn't produce a response.", False
    results, needs_confirmation = [], False
    for call in calls:
        result = _execute_tool(call.name, dict(call.args))
        needs_confirmation |= result.get("status") == "needs_confirmation"
        results.append(genai.protos.Part(function_response=genai.protos.FunctionResponse(name=call.name, response={"result": result})))
    final = chat.send_message(results)
    return final.text or "Done.", needs_confirmation


def _prohibited_request(message: str) -> str | None:
    text = message.lower()
    if "refund" in text:
        return "I can help submit a return request, but refunds require merchant approval."
    if "cancel" in text and "order" in text:
        return "Order cancellation is outside this agent's permitted scope."
    if "change" in text and ("price" in text or "cost" in text):
        return "Changing product prices is outside this agent's permitted scope."
    return None


def _is_confirmation(message: str) -> bool:
    return message.strip().lower().rstrip("!.") in {"yes", "yes please", "confirm", "confirm order", "place the order", "go ahead", "proceed"}


def _confirm_pending() -> dict[str, Any] | None:
    for confirmation_id, pending in reversed(PENDING_CONFIRMATIONS.items()):
        if not pending["used"] and pending["session_id"] == CURRENT_SESSION_ID.get() and pending["merchant_id"] == CURRENT_MERCHANT_ID.get():
            return create_order(pending["product_id"], pending["quantity"], True, confirmation_id, user_confirmed=True)
    return None


def handle_message(user_message: str, conversation_history: list[dict[str, Any]] | None = None,
                   provider: str = "auto", session_id: str = "demo-session", merchant_id: str = DEFAULT_MERCHANT_ID) -> dict[str, Any]:
    activate_session(session_id, merchant_id)
    refusal = _prohibited_request(user_message)
    if refusal:
        log_action("prohibited_request", "denied", refusal, arguments={"message": user_message[:300]})
        return {"reply": refusal, "needs_confirmation": False}
    if _is_confirmation(user_message):
        result = _confirm_pending()
        if result and result.get("status") == "order_created":
            related = suggest_related(result["product"]["id"])
            suffix = f" You may also like {related['name']}." if related else ""
            return {"reply": f"Order created: {result['order']['id']} ({result['order']['_source']}).{suffix}",
                    "needs_confirmation": False, "order_confirmed": True,
                    "order_details": {"order_id": result["order"]["id"], "item": result["product"]["name"], "amount": f"₹{result['order']['amount']//100}"}}
        if result:
            return {"reply": result["error"], "needs_confirmation": False}
    try:
        if provider == "gemini" or (provider == "auto" and not os.getenv("GROQ_API_KEY") and os.getenv("GEMINI_API_KEY")):
            reply, pending = _gemini_reply(user_message, conversation_history)
        else:
            try:
                reply, pending = _groq_reply(user_message, conversation_history)
            except Exception as groq_error:
                if provider != "auto" or not os.getenv("GEMINI_API_KEY"):
                    raise
                log_action("handle_message", "error", "Groq failed; using configured Gemini fallback.", error=str(groq_error))
                reply, pending = _gemini_reply(user_message, conversation_history)
        return {"reply": reply, "needs_confirmation": pending}
    except Exception as exc:
        log_action("handle_message", "error", "Provider request failed.", error=str(exc))
        return {"reply": "I couldn't reach the checkout assistant right now. Please try again.", "needs_confirmation": False}


def run_boundary_tests() -> dict[str, bool]:
    account = register_merchant_account("Boundary Test Store", f"boundary-{secrets.token_hex(4)}@sellr.test", "boundary-test-password")
    merchant, token = account["merchant"], account["auth_token"]
    merchant_id, session_id = merchant["merchant_id"], "boundary-test"
    try:
        save_product(merchant_id, product_id="TEST-1", name="Test product", price=100, stock=5, auth_token=token)
        activate_session(session_id, merchant_id)
        results: dict[str, bool] = {}
        results["zero_quantity_rejected"] = "error" in create_order("TEST-1", 0)
        results["quantity_limit_rejected"] = "error" in create_order("TEST-1", 3)
        proposal = create_order("TEST-1", 1)
        results["confirmation_required"] = proposal.get("status") == "needs_confirmation"
        results["model_cannot_self_confirm"] = "error" in create_order("TEST-1", 1, True, proposal["confirmation_id"])
        created = create_order("TEST-1", 1, True, proposal["confirmation_id"], user_confirmed=True)
        results["approved_order_created"] = created.get("status") == "order_created"
        results["replay_rejected"] = "error" in create_order("TEST-1", 1, True, proposal["confirmation_id"], user_confirmed=True)
        return results
    finally:
        with _connection() as db:
            for table in ("products", "orders", "return_requests", "audit_events", "merchant_users", "merchants"):
                db.execute(f"DELETE FROM {table} WHERE merchant_id=?", (merchant_id,))
