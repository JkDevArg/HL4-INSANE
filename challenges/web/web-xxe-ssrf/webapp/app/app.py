import os
import io
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from lxml import etree
import requests

app = Flask(__name__)
app.secret_key = os.urandom(32)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
METADATA_URL = "http://metadata-service"
VAULT_TOKEN = "ctf-vault-token-xyz789-secret"

USERS = {
    "admin": "admin123",
    "accountant": "acc2024"
}

SAMPLE_INVOICES = [
    {"id": "INV-2024-001", "amount": "15,200.00", "vendor": "TechSupplies S.A.C.", "status": "Pagado"},
    {"id": "INV-2024-002", "amount": "8,750.50",  "vendor": "Consultoría Digital EIRL", "status": "Pendiente"},
    {"id": "INV-2024-003", "amount": "32,100.00", "vendor": "Infraestructura Cloud Corp", "status": "Revisión"},
    {"id": "INV-2024-004", "amount": "5,600.00",  "vendor": "Servicios Logísticos SAC", "status": "Pagado"},
]


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return render_template("index.html", logged_in="username" in session, username=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and USERS[username] == password:
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Credenciales inválidas"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", invoices=SAMPLE_INVOICES, username=session.get("username"))


@app.route("/import", methods=["GET", "POST"])
@login_required
def import_invoice():
    result = None
    error = None

    if request.method == "POST":
        xml_data = None

        # Accept XML from file upload or raw textarea
        if "xmlfile" in request.files and request.files["xmlfile"].filename:
            xml_data = request.files["xmlfile"].read()
        elif request.form.get("xmlcontent"):
            xml_data = request.form.get("xmlcontent").encode("utf-8")

        if not xml_data:
            error = "No se proporcionó contenido XML."
        else:
            try:
                # VULNERABLE: resolve_entities=True allows XXE
                parser = etree.XMLParser(
                    resolve_entities=True,
                    no_network=False,
                    load_dtd=True,
                )
                tree = etree.parse(io.BytesIO(xml_data), parser)
                root = tree.getroot()

                invoice_id = root.findtext("id") or "N/A"
                amount = root.findtext("amount") or "0.00"
                vendor = root.findtext("vendor") or "N/A"
                currency = root.findtext("currency") or "PEN"

                result = {
                    "invoice_id": invoice_id,
                    "amount": amount,
                    "vendor": vendor,
                    "currency": currency,
                    "status": "Importado correctamente"
                }
            except etree.XMLSyntaxError as e:
                error = f"Error de sintaxis XML: {e}"
            except Exception as e:
                error = f"Error al procesar XML: {e}"

    return render_template("import.html", result=result, error=error, username=session.get("username"))


@app.route("/api/validate")
@login_required
def api_validate():
    invoice_id = request.args.get("id", "")
    if not invoice_id:
        return jsonify({"error": "id requerido"}), 400
    try:
        resp = requests.get(f"{METADATA_URL}/latest/meta-data/", timeout=3)
        return jsonify({"invoice_id": invoice_id, "valid": True, "metadata_status": resp.status_code})
    except Exception as e:
        return jsonify({"invoice_id": invoice_id, "valid": False, "error": str(e)})


@app.route("/api/vault")
def api_vault():
    token = request.headers.get("X-Cloud-Token", "")
    if token == VAULT_TOKEN:
        return jsonify({"flag": FLAG, "message": "Acceso autorizado al vault"})
    return jsonify({"error": "Token inválido o ausente"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
