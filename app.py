"""Sellr product UI: public buyer chat and protected merchant administration."""
from __future__ import annotations

import json
import secrets
import streamlit as st

from agent import (
    LENGTH_TO_CM, WEIGHT_TO_GRAMS, activate_session, authenticate_merchant,
    create_return_request, get_agent_scope, get_audit_log, handle_message,
    delete_product, import_catalog, list_merchants, list_products, list_return_requests,
    list_session_orders, register_merchant_account, review_return_request,
    save_product, set_session_paused, update_merchant_policy,
)

st.set_page_config(page_title="Sellr | Safe AI checkout", page_icon="🛍️", layout="wide")
st.markdown("""<style>
.sellr-title {font-size:2.1rem;font-weight:800;color:#4338ca;margin-bottom:0}
.sellr-subtitle {color:#64748b;margin-top:0}
.security-note {border-left:4px solid #4338ca;padding:.5rem .8rem;background:#eef2ff;border-radius:6px}
</style>""", unsafe_allow_html=True)

if "sellr_session_id" not in st.session_state:
    st.session_state.sellr_session_id = secrets.token_urlsafe(16)
if "messages" not in st.session_state:
    st.session_state.messages = []
if "merchant_auth" not in st.session_state:
    st.session_state.merchant_auth = None

merchants = list_merchants()
merchant_names = {merchant["store_name"]: merchant["merchant_id"] for merchant in merchants}
if "buyer_merchant_id" not in st.session_state:
    st.session_state.buyer_merchant_id = merchant_names.get("Sellr Beauty Demo", merchants[0]["merchant_id"])

st.markdown('<div class="sellr-title">Sellr</div>', unsafe_allow_html=True)
st.markdown('<p class="sellr-subtitle">AI checkout, safely scoped.</p>', unsafe_allow_html=True)
st.info("Demo mode: payments use Razorpay test mode when configured; otherwise Sellr creates clearly-labelled mock orders.")

with st.sidebar:
    st.subheader("Buyer store")
    selected_name = st.selectbox("Shop this merchant", list(merchant_names), key="buyer_store_picker")
    buyer_merchant_id = merchant_names[selected_name]
    if buyer_merchant_id != st.session_state.buyer_merchant_id:
        st.session_state.buyer_merchant_id = buyer_merchant_id
        st.session_state.messages = []
        st.rerun()
    st.caption("The agent only sees the selected merchant's catalog and policy.")

session_id, buyer_merchant_id = st.session_state.sellr_session_id, st.session_state.buyer_merchant_id
activate_session(session_id, buyer_merchant_id)
tabs = st.tabs(["Buyer chat", "Merchant setup", "Returns & review"])

with tabs[0]:
    with st.sidebar:
        st.divider()
        st.subheader("Live buyer controls")
        paused = st.toggle("Pause this buyer session", key="paused")
        set_session_paused(paused, session_id, buyer_merchant_id)
        st.caption("Active JWT scope")
        for action, allowed in get_agent_scope(session_id, buyer_merchant_id).items():
            st.write(f"{'✅' if allowed else '⛔'} {action.replace('_', ' ').title()}")
        st.divider()
        st.subheader("Session audit trail")
        audit = get_audit_log(session_id, buyer_merchant_id)
        if audit:
            st.dataframe([{key: event[key] for key in ("timestamp", "action", "status", "detail")} for event in audit],
                         use_container_width=True, hide_index=True, height=280)
        else:
            st.caption("No buyer actions yet.")

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            if message["role"] == "assistant" and message.get("needs_confirmation"):
                st.warning(message["content"], icon="⚠️")
            else:
                st.markdown(message["content"])
            if message.get("order_details"):
                st.success("Order created", icon="✅")
                st.json(message["order_details"], expanded=False)

    prompt = st.chat_input("Ask about products, or place an order…")
    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        history = [{"role": item["role"], "content": item["content"]} for item in st.session_state.messages[:-1]]
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            try:
                with st.spinner("Sellr is checking permitted actions…"):
                    result = handle_message(prompt, history, session_id=session_id, merchant_id=buyer_merchant_id)
                reply = result.get("reply") or "I couldn't produce a response. Please try again."
                pending, order = bool(result.get("needs_confirmation")), result.get("order_details")
                st.warning(reply, icon="⚠️") if pending else st.markdown(reply)
                if order:
                    st.success("Order created", icon="✅")
                    st.json(order, expanded=False)
            except Exception:
                reply, pending, order = "Something went wrong. No payment was created—please try again.", False, None
                st.error(reply)
        st.session_state.messages.append({"role": "assistant", "content": reply, "needs_confirmation": pending, "order_details": order})
        st.rerun()

with tabs[1]:
    st.subheader("Merchant setup")
    st.markdown('<div class="security-note">Protected workspace. Catalog, policy, and return-review changes require a signed-in merchant account.</div>', unsafe_allow_html=True)
    auth = st.session_state.merchant_auth
    if not auth:
        sign_in, create = st.columns(2)
        with sign_in:
            st.markdown("#### Sign in")
            with st.form("merchant_login"):
                email = st.text_input("Merchant email", key="login_email")
                password = st.text_input("Password", type="password", key="login_password")
                if st.form_submit_button("Sign in to merchant workspace"):
                    try:
                        st.session_state.merchant_auth = authenticate_merchant(email, password)
                        st.success("Signed in.")
                        st.rerun()
                    except ValueError as error:
                        st.error(str(error))
        with create:
            st.markdown("#### Create merchant account")
            with st.form("merchant_register", clear_on_submit=True):
                store_name = st.text_input("Store name")
                account_email = st.text_input("Email address")
                account_password = st.text_input("Create password", type="password", help="At least 10 characters.")
                if st.form_submit_button("Create protected merchant account"):
                    try:
                        st.session_state.merchant_auth = register_merchant_account(store_name, account_email, account_password)
                        st.success("Account created and signed in.")
                        st.rerun()
                    except ValueError as error:
                        st.error(str(error))
    else:
        merchant_id = auth["merchant"]["merchant_id"]
        merchant = next(item for item in list_merchants() if item["merchant_id"] == merchant_id)
        top, sign_out = st.columns([4, 1])
        with top:
            st.success(f"Signed in as {auth['email']} · {merchant['store_name']}", icon="🔒")
        with sign_out:
            if st.button("Sign out"):
                st.session_state.merchant_auth = None
                st.rerun()

        st.markdown("#### Agent policy")
        with st.form("policy"):
            first, second = st.columns(2)
            with first:
                maximum_value = st.number_input("Maximum order value (₹)", min_value=1, value=int(merchant["max_order_value"]))
                maximum_quantity = st.number_input("Maximum quantity per item", min_value=1, value=int(merchant["max_quantity"]))
                weight_display = st.selectbox("Catalog weight display", list(WEIGHT_TO_GRAMS), index=list(WEIGHT_TO_GRAMS).index(merchant["weight_display_unit"]))
            with second:
                checkout = st.checkbox("Enable agent checkout", value=bool(merchant["checkout_enabled"]))
                returns = st.checkbox("Enable return requests", value=bool(merchant["returns_enabled"]))
                photo = st.checkbox("Require photo for damage / quality issues", value=bool(merchant["photo_required"]))
                dimension_display = st.selectbox("Catalog dimension display", list(LENGTH_TO_CM), index=list(LENGTH_TO_CM).index(merchant["dimension_display_unit"]))
            if st.form_submit_button("Save merchant policy"):
                try:
                    update_merchant_policy(merchant_id, max_order_value=int(maximum_value), max_quantity=int(maximum_quantity),
                                           checkout_enabled=checkout, returns_enabled=returns, photo_required=photo,
                                           weight_display_unit=weight_display, dimension_display_unit=dimension_display,
                                           auth_token=auth["auth_token"])
                    st.success("Policy saved. New buyer actions receive the updated JWT scope.")
                    st.rerun()
                except (ValueError, PermissionError) as error:
                    st.error(str(error))

        st.divider()
        st.markdown("#### Catalog")
        st.caption("Sellr stores weight in grams and dimensions in centimetres, then automatically converts them into this merchant's chosen display units.")
        st.dataframe(list_products(merchant_id), use_container_width=True, hide_index=True)
        manual, upload = st.columns(2)
        with manual:
            with st.form("product_form", clear_on_submit=True):
                st.caption("Add a product or overwrite an existing product ID.")
                product_id = st.text_input("Product ID / SKU")
                product_name = st.text_input("Product name")
                price = st.number_input("Price (₹)", min_value=0, value=0)
                stock = st.number_input("Stock", min_value=0, value=0)
                category = st.text_input("Category (optional)")
                related_to = st.text_input("Related product ID (optional)")
                add_weight = st.checkbox("Add product weight")
                weight = st.number_input("Weight", min_value=0.0, value=0.0, disabled=not add_weight)
                weight_unit = st.selectbox("Weight unit", list(WEIGHT_TO_GRAMS), disabled=not add_weight)
                add_dimensions = st.checkbox("Add dimensions")
                dimension_unit = st.selectbox("Dimension unit", list(LENGTH_TO_CM), disabled=not add_dimensions)
                c1, c2, c3 = st.columns(3)
                with c1:
                    length = st.number_input("Length", min_value=0.0, value=0.0, disabled=not add_dimensions)
                with c2:
                    width = st.number_input("Width", min_value=0.0, value=0.0, disabled=not add_dimensions)
                with c3:
                    height = st.number_input("Height", min_value=0.0, value=0.0, disabled=not add_dimensions)
                if st.form_submit_button("Save product"):
                    try:
                        save_product(merchant_id, product_id=product_id, name=product_name, price=int(price), stock=int(stock),
                                     category=category, related_to=related_to or None,
                                     weight_value=weight if add_weight else None, weight_unit=weight_unit,
                                     length_value=length if add_dimensions else None, width_value=width if add_dimensions else None,
                                     height_value=height if add_dimensions else None, dimension_unit=dimension_unit,
                                     auth_token=auth["auth_token"])
                        st.success("Product saved with canonical units.")
                        st.rerun()
                    except (ValueError, PermissionError) as error:
                        st.error(str(error))
        with upload:
            st.caption("Import JSON or CSV: id/product_id, name, price, stock, category, related_to. Optional units: weight_value, weight_unit, length_value, width_value, height_value, dimension_unit.")
            catalog_file = st.file_uploader("Catalog file", type=["json", "csv"], key="catalog_upload")
            if catalog_file and st.button("Import catalog"):
                try:
                    count = import_catalog(merchant_id, catalog_file.getvalue(), catalog_file.name, auth["auth_token"])
                    st.success(f"Imported {count} product(s) and normalized its measurements.")
                    st.rerun()
            except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError, PermissionError) as error:
                st.error(f"Could not import catalog: {error}")
        products = list_products(merchant_id)
        if products:
            st.markdown("#### Remove a product")
            with st.form("delete_product"):
                removal = st.selectbox("Product to remove", [f"{product['id']} — {product['name']}" for product in products])
                confirm_delete = st.checkbox("I understand this removes the product from this merchant's buyer catalog.")
                if st.form_submit_button("Remove product", type="secondary"):
                    if not confirm_delete:
                        st.warning("Confirm removal before continuing.")
                    else:
                        product_id = removal.split(" — ", 1)[0]
                        if delete_product(merchant_id, product_id, auth["auth_token"]):
                            st.success("Product removed.")
                            st.rerun()
                        else:
                            st.error("Product was not found.")

with tabs[2]:
    st.subheader("Returns & merchant review")
    buyer, reviewer = st.columns(2)
    with buyer:
        st.markdown("#### Buyer return request")
        orders = list_session_orders(session_id, buyer_merchant_id)
        if not orders:
            st.caption("Place a mock/test order in Buyer chat first; it will appear here for this buyer session.")
        else:
            labels = {f"{order['order_id']} — {order['product_name']} (₹{order['amount']})": order["order_id"] for order in orders}
            with st.form("return_request", clear_on_submit=True):
                choice = st.selectbox("Order", list(labels))
                reason = st.selectbox("Issue", ["Damaged or leaking", "Wrong item", "Bad quality", "Expired product", "Missing item", "Other"])
                description = st.text_area("Describe what went wrong", max_chars=1000)
                evidence = st.file_uploader("Photo evidence", type=["jpg", "jpeg", "png", "webp"], key="return_photo")
                if st.form_submit_button("Submit return request"):
                    result = create_return_request(labels[choice], reason, description, evidence.getvalue() if evidence else None, evidence.name if evidence else None)
                    st.error(result["error"]) if result.get("error") else st.success(f"Return case {result['return_id']} is pending merchant review.")
    with reviewer:
        st.markdown("#### Merchant review queue")
        auth = st.session_state.merchant_auth
        if not auth:
            st.info("Sign in through Merchant setup to review buyer evidence and decide return requests.")
        else:
            merchant_id = auth["merchant"]["merchant_id"]
            try:
                cases = list_return_requests(merchant_id, auth["auth_token"])
                if not cases:
                    st.caption("No return requests for this merchant.")
                for case in cases:
                    with st.expander(f"{case['return_id']} · {case['status']}"):
                        st.write("Order:", case["order_id"])
                        st.write("Issue:", case["reason"])
                        st.write("Description:", case["description"])
                        st.caption(f"Photo attached: {'yes' if case['photo_name'] else 'no'}")
                        if case.get("photo_blob"):
                            st.image(case["photo_blob"], caption=case["photo_name"] or "Uploaded evidence", use_container_width=True)
                        if case["status"] == "pending_merchant_review":
                            approve, reject = st.columns(2)
                            if approve.button("Approve return", key=f"approve_{case['return_id']}"):
                                review_return_request(merchant_id, case["return_id"], True, auth["auth_token"])
                                st.rerun()
                            if reject.button("Reject return", key=f"reject_{case['return_id']}"):
                                review_return_request(merchant_id, case["return_id"], False, auth["auth_token"])
                                st.rerun()
                        elif case["status"] == "approved_refund_pending":
                            st.warning("Approved for refund. Sellr intentionally does not issue money automatically.", icon="⚠️")
            except PermissionError as error:
                st.error(str(error))
