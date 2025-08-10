import os
import base64
import tempfile
import json
import requests
from flask import Flask, request, jsonify

# ---------- CONFIGURAÇÃO INICIAL ----------

app = Flask(__name__)

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

# ---------- FUNÇÕES AUXILIARES ----------

def get_efi_access_token():
    url = f"{EFI_BASE_URL}/oauth/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": EFI_CLIENT_ID,
        "client_secret": EFI_CLIENT_SECRET
    }
    resp = requests.post(url, data=data, cert=EFI_CERT_PATH)
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

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/efi/charges", methods=["POST"])
def create_charge():
    """
    Cria cobrança Pix na EFI.
    Espera: { "user_id": "...", "amount_cents": 1000 }
    """
    data = request.json
    access_token = get_efi_access_token()

    payload = {
        "calendar": {"expiracao": 3600},
        "valor": {"original": f"{data['amount_cents']/100:.2f}"},
        "chave": "SUA_CHAVE_PIX_SANDBOX",  # TODO: trocar pela chave Pix correta
        "solicitacaoPagador": "Pagamento Baú Premiado"
    }

    url = f"{EFI_BASE_URL}/v2/cob"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json=payload, cert=EFI_CERT_PATH)
    resp.raise_for_status()

    return jsonify(resp.json()), 200

@app.route("/efi/webhook", methods=["POST"])
def pix_webhook():
    """
    Recebe webhook de pagamento Pix (depósito).
    """
    payload = request.json

    # TODO: validar assinatura se EFI_WEBHOOK_SECRET estiver configurado

    if payload.get("type") == "pix.charge.paid":
        ref_id = payload["data"]["reference_id"]
        user_id = ref_id  # TODO: ajustar se ref_id não for user_id direto
        amount_cents = int(payload["data"]["amount"])

        update_wallet_balance(user_id, amount_cents, "credit")

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
    """
    Recebe webhook de confirmação de saque.
    """
    payload = request.json

    # TODO: validar assinatura se EFI_WEBHOOK_SECRET estiver configurado

    if payload.get("type") == "pix.send.success":
        ref_id = payload["data"]["reference_id"]
        user_id = ref_id  # TODO: ajustar se ref_id não for user_id direto
        amount_cents = int(payload["data"]["amount"])

        update_wallet_balance(user_id, amount_cents, "debit")

    return jsonify({"status": "received"}), 200

# ---------- MAIN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
