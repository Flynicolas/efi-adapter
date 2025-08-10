import os
import base64
import tempfile
import json
import requests
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

# ---------- FUNÇÕES AUXILIARES ----------
def get_efi_access_token():
    url = f"{EFI_BASE_URL}/oauth/token"
    # Basic Auth com client_id/secret + grant_type
    auth = (EFI_CLIENT_ID, EFI_CLIENT_SECRET)
    payload = {"grant_type": "client_credentials"}
    resp = requests.post(url, auth=auth, json=payload, cert=EFI_CERT_PATH, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def update_wallet_balance(user_id, amount_cents, tx_type):
    """
    Atualiza a carteira no Supabase.
    """
    url = f"{SUPABASE_URL}/rest/v1/wallet_transactions"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }
    payload = {
        "user_id": user_id,
        "amount_cents": amount_cents,
        "type": tx_type
    }
    r = requests.post(url, headers=headers, json=payload)
    r.raise_for_status()

# ---------- ROTAS ----------

@app.route("/efi/charges", methods=["POST"])
def create_charge():
    """
    Cria cobrança Pix na Efí.
    Espera: { "user_id": "<uuid>", "amount_cents": 1000, "description": "opcional" }
    """
    data = request.json or {}
    amount_cents = int(data["amount_cents"])
    description = data.get("description", "Pagamento Baú Premiado")

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

    return jsonify(resp.json()), 200
    
# Aceita GET para validação de url (retorna 200 se o token confere)
@app.get("/efi/webhook")
@app.get("/efi/webhook/pix")
def pix_webhook_ping():
    if not _ok_webhook_token():
        return ("unauthorized", 401)
    return jsonify({"status": "ok"}), 200


    payload = request.get_json(silent=True) or {}

    # TODO: sua lógica atual de processamento (chamar RPC do Supabase)
    # if payload.get("type") == "pix.charge.paid":
    #     ref_id = payload["data"]["reference_id"]
    #     amount_cents = int(payload["data"]["amount"])
    #     # chamar sua RPC idempotente aqui...

    return jsonify({"status": "received"}), 200

@app.route("/efi/payouts", methods=["POST"])
def create_payout():
    """
    Cria saque Pix na EFI.
    Espera: { "user_id": "...", "amount_cents": 1000, "pix_key": "..." }
    """
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
    resp = requests.post(url, headers=headers, json=payload, cert=EFI_CERT_PATH)
    resp.raise_for_status()

    return jsonify(resp.json()), 200

@app.route("/efi/payouts/webhook", methods=["POST"])
def payout_webhook():
    # valida token ?h=<TOKEN>
    if not _ok_webhook_token():
        return ("unauthorized", 401)

    payload = request.get_json(silent=True) or {}

    # TODO: lógica de payout (chamar RPCs conforme status)
    # evt = payload.get("type")
    # if evt == "payout.paid": wallet_cashout_mark_paid(...)
    # elif evt == "payout.failed": wallet_cashout_refund(...)

    return jsonify({"status": "received"}), 200

# ---------- MAIN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
