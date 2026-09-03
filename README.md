# Sellr

**The permission layer for AI commerce.** Sellr lets an AI buyer browse a merchant's catalog and propose checkout, while the merchant retains policy control over every money-adjacent action.

## What works

- Merchant-managed SQLite catalog: create a merchant, add products by form, or import CSV/JSON.
- Merchant policy controls: checkout/returns enablement, per-item quantity limit, order-value ceiling, and photo-evidence rules.
- Groq function calling with a Gemini fallback when configured.
- JWT scope carries the buyer session, merchant ID, allowed actions, and merchant limits.
- Gated checkout: the model can only propose an order; a later explicit buyer confirmation can create it.
- Razorpay test-mode Orders call with an explicit mock fallback if test credentials are absent.
- Per-session, per-merchant audit trail and a merchant kill switch.
- Return requests with reason, description, and photo evidence; merchant review can approve a return, but **never automatically issues a refund**.

## Run locally

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Open the displayed local URL. The seeded `Sellr Beauty Demo` merchant is loaded from `catalog.json` on the first run. Runtime merchant data is stored locally in `sellr.db`, which is intentionally ignored by Git.

## Environment variables

Create `.env` from this example:

```env
GROQ_API_KEY=your_key
GROQ_MODEL=openai/gpt-oss-20b
GEMINI_API_KEY=optional_fallback_key
GEMINI_MODEL=gemini-2.0-flash
RAZORPAY_KEY_ID=
RAZORPAY_KEY_SECRET=
SELLR_JWT_SECRET=replace-this-in-any-shared-deployment
```

Without Razorpay keys, Sellr visibly uses a mock order response. Never commit `.env` or `sellr.db`.

## Verify the safety boundary

```powershell
.\venv\Scripts\python.exe -c "import agent; print(agent.run_boundary_tests())"
```

All test values should be `True`. The tests cover zero quantity, merchant quantity limits, confirmation requirement, attempted model self-confirmation, successful explicit confirmation, and confirmation replay.

## Architecture

```text
Buyer chat → LLM tool proposal → JWT + merchant policy check → audit event
                                 ↓
                     explicit buyer confirmation
                                 ↓
                   Razorpay test order / mock fallback

Return request → evidence validation → merchant review → approved_refund_pending
```

The LLM never receives database credentials, Razorpay secrets, or unrestricted merchant capabilities.
