import os
import base64
import tempfile
import json
import requests
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from hmac import compare_digest

# ---------- CONFIGURAÇÃO INICIAL ----------
app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE")
EFI_BASE_URL = os.getenv("EFI_BASE_URL")
EFI_CLIENT_ID = os.getenv("EFI_CLIENT_ID")
EFI_CLIENT_SECRET = os.getenv("EFI_CLIENT_SECRET")
EFI_WEBHOOK_SECRET = os.getenv("EFI_WEBHOOK_SECRET", "")

# Recria certificado a partir de base64
EFI_CERT_BASE64 = os.getenv("EFI_CERT_BASE64")
EFI_CERT_PATH = None
if EFI_CERT_BASE64:
    cert_bytes = base64.b64decode(EFI_CERT_BASE64)
    cert_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_temp.write(cert_bytes)
    cert_temp.flush()
    EFI_CERT_PATH = cert_temp.name

# --- Webhook token helper ---
def _ok_webhook_token():
    """
    Valida o token de webhook via querystring ?h=<TOKEN>.
    O TOKEN vem da env EFI_WEBHOOK_SECRET (defina no Render).
    """
    expected = os.getenv("EFI_WEBHOOK_SECRET", "")
    token = request.args.get("h", "")
    return bool(expected) and compare_digest(token, expected)

# ---------- HELPERS SUPABASE ----------
def _sb_headers(extra=None):
    h = {
        "apikey": SUPABASE_SERVICE_ROLE,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra:
        h.update(extra)
    return h

def get_wallet_id_for_user(user_id: str):
    """
    Estratégia simples: pega a wallet_id da última transação do usuário.
    Troque por sua tabela de wallets se tiver uma.
    """
    url = (
        f"{SUPABASE_URL}/rest/v1/wallet_transactions"
        f"?select=wallet_id&user_id=eq.{user_id}&order=created_at.desc&limit=1"
    )
    r = requests.get(url, headers=_sb_headers(), timeout=15)
    r.raise_for_status()
    rows = r.json()
    return rows[0]["wallet_id"] if rows else None

def save_pix_intent(txid: str, user_id: str, wallet_id: str | None, amount_cents: int, raw_json: dict):
    payload = {
        "txid": txid,
        "user_id": user_id,
        "wallet_id": wallet_id or user_id,  # ajuste se sua wallet_id não for = user_id
        "amount_cents": amount_cents,
        "raw": raw_json,
        "status": "created",
    }
    url = f"{SUPABASE_URL}/rest/v1/pix_intents"
    r = requests.post(url, headers=_sb_headers({"Prefer": "return=minimal"}), json=payload, timeout=20)
    # se repetir (txid PK), ignore conflito
    if r.status_code not in (201, 204):
        try:
            r.raise_for_status()
        except requests.HTTPError:
            pass

def load_pix_intent(txid: str):
    url = f"{SUPABASE_URL}/rest/v1/pix_intents?select=user_id,wallet_id,amount_cents,status&txid=eq.{txid}&limit=1"
    r = requests.get(url, headers=_sb_headers(), timeout=15)
    r.raise_for_status()
    rows = r.json()
    return rows[0] if rows else None

def mark_pix_intent_paid(txid: str):
    url = f"{SUPABASE_URL}/rest/v1/pix_intents?txid=eq.{txid}"
    payload = { "status": "paid", "paid_at": datetime.now(timezone.utc).isoformat() }
    r = requests.patch(url, headers=_sb_headers({"Prefer": "return=minimal"}), json=payload, timeout=15)
    if r.status_code not in (204, 200):
        r.raise_for_status()

def wallet_tx_exists_by_reference(reference: str) -> bool:
    url = f"{SUPABASE_URL}/rest/v1/wallet_transactions?select=id&reference=eq.{reference}&limit=1"
    r = requests.get(url, headers=_sb_headers(), timeout=15)
    r.raise_for_status()
    return bool(r.json())

def credit_wallet(user_id: str, wallet_id: str | None, amount_cents: int, reference: str, description: str):
    """
    Insere crédito de forma idempotente usando 'reference' único = txid.
    Se já existir, não insere de novo.
    """
    if wallet_tx_exists_by_reference(reference):
        return False

    payload = {
        "user_id": user_id,
        "wallet_id": wallet_id or user_id,
        "amount_cents": amount_cents,
        "type": "credit",
        "description": description,
        "source": "pix",
        "reference": reference,
    }
    url = f"{SUPABASE_URL}/rest/v1/wallet_transactions"
    r = requests.post(url, headers=_sb_headers({"Prefer": "return=minimal"}), json=payload, timeout=20)
    if r.status_code not in (201, 204):
        r.raise_for_status()
    return True

# ---------- EFI (token) ----------
def get_efi_access_token():
    url = f"{EFI_BASE_URL}/oauth/token"
    auth = (EFI_CLIENT_ID, EFI_CLIENT_SECRET)
    payload = {"grant_type": "client_credentials"}
    resp = requests.post(url, auth=auth, json=payload, cert=EFI_CERT_PATH, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]

# ---------- ROTAS ----------

@app.route("/efi/charges", methods=["POST"])
def create_charge():
    """
    Cria cobrança Pix na Efí e salva a 'intenção' (txid -> user/wallet/valor) no Supabase.
    Espera: { "user_id": "<uuid>", "amount_cents": 1000, "description": "opcional" }
    """
    data_in = request.json or {}
    user_id = data_in["user_id"]
    amount_cents = int(data_in["amount_cents"])
    description = data_in.get("description", "Pagamento Baú Premiado")

    access_token = get_efi_access_token()

    payload = {
        "calendario": {"expiracao": 3600},
        "valor": {"original": f"{amount_cents/100:.2f}"},
        "chave": os.getenv("EFI_PIX_KEY"),
        "solicitacaoPagador": description
    }

    url = f"{EFI_BASE_URL}/v2/cob"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=payload, cert=EFI_CERT_PATH, timeout=30)
    resp.raise_for_status()
    out = resp.json()

    # salva intenção
    txid = out["txid"]
    wallet_id = get_wallet_id_for_user(user_id)  # ajuste se tiver tabela própria de wallet
    save_pix_intent(txid, user_id, wallet_id, amount_cents, out)

    return jsonify(out), 200

@app.route("/efi/webhook", methods=["GET", "POST", "PUT", "OPTIONS"])
@app.route("/efi/webhook/pix", methods=["GET", "POST", "PUT", "OPTIONS"])
def efi_webhook_unificado():
    # valida token
    if not _ok_webhook_token():
        return ("unauthorized", 401)

    # pings de verificação
    if request.method in ("GET", "OPTIONS"):
        return jsonify({"status": "ok"}), 200
    if request.method == "PUT" and not (request.data or request.form or request.json):
        return jsonify({"status": "ok"}), 200

    # evento real
    payload = request.get_json(silent=True) or {}
    eventos = payload.get("pix") or []

    # processa cada item (a Efí pode mandar em lote)
    for evt in eventos:
        txid = evt.get("txid")
        valor_str = (evt.get("valor") or "0").strip()
        # converte "1.00" para cents com Decimal
        amount_cents = int((Decimal(valor_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100))

        intent = load_pix_intent(txid)
        if not intent:
            # sem intenção, não sabemos quem creditar -> ignore/registre
            # (você pode optar por logar em uma tabela de erros)
            continue

        if intent.get("status") == "paid":
            # já processado
            continue

        user_id = intent["user_id"]
        wallet_id = intent.get("wallet_id")
        # idempotente por 'reference' = txid
        created = credit_wallet(
            user_id=user_id,
            wallet_id=wallet_id,
            amount_cents=amount_cents,
            reference=txid,
            description="PIX recebido"
        )
        if created:
            mark_pix_intent_paid(txid)

    return jsonify({"status": "received"}), 200

# (Opcional) exemplo de payouts já existente no seu código:
@app.route("/efi/payouts", methods=["POST"])
def create_payout():
    data = request.json
    access_token = get_efi_access_token()
    payload = {
        "valor": {"original": f"{data['amount_cents']/100:.2f}"},
        "chave": data["pix_key"]
    }
    url = f"{EFI_BASE_URL}/v2/pix/envio"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=payload, cert=EFI_CERT_PATH, timeout=30)
    resp.raise_for_status()
    return jsonify(resp.json()), 200

@app.route("/efi/payouts/webhook", methods=["POST"])
def payout_webhook():
    if not _ok_webhook_token():
        return ("unauthorized", 401)
    payload = request.get_json(silent=True) or {}
    # TODO: trate status do saque quando ativar saques
    return jsonify({"status": "received"}), 200

# ---------- MAIN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
