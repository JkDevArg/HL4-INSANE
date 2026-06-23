#!/usr/bin/env python3
"""
SAML Service Provider.
Vulnerabilities:
1. XML Signature Wrapping (XSW): verifies signature on the referenced assertion
   element but uses the FIRST assertion found for authorization decisions.
2. XXE in document import: uses lxml with resolve_entities=True, allowing
   file reads and SSRF to the metadata service (http://metadata-service/).
"""
import os
import base64
import hashlib
import requests
from pathlib import Path
from flask import Flask, request, session, redirect, render_template_string, jsonify, url_for, abort
from lxml import etree
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sp-secret-key-ctf")

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
IDP_METADATA_URL = os.environ.get("IDP_METADATA_URL", "http://idp:8080/saml/metadata")
IDP_SSO_URL = os.environ.get("IDP_SSO_URL", "http://idp:8080/saml/login")

SAML_NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#"
}

_idp_cert_cache = None


def get_idp_cert():
    global _idp_cert_cache
    if _idp_cert_cache:
        return _idp_cert_cache
    try:
        r = requests.get(IDP_METADATA_URL, timeout=10)
        doc = etree.fromstring(r.content)
        cert_b64 = doc.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate").text.strip()
        cert_der = base64.b64decode(cert_b64)
        cert = x509.load_der_x509_certificate(cert_der)
        _idp_cert_cache = cert
        return cert
    except Exception as e:
        print(f"[!] Failed to fetch IDP cert: {e}")
        return None


def verify_saml_response(saml_b64: str):
    """
    VULNERABILITY (XSW): This function:
    1. Finds the Signature's Reference URI to locate the signed assertion
    2. Verifies the signature over that element
    3. BUT then returns the FIRST <saml:Assertion> found in the document
       (not necessarily the signed one)

    Attacker can:
    - Take a valid signed assertion (signed as regular user)
    - Wrap it: <Response><FakeAssertion role="admin"/><OriginalSignedAssertion/></Response>
    - The fake assertion (with admin role) is processed for auth
    - The signature verification passes on the original (now second) assertion
    """
    try:
        xml_bytes = base64.b64decode(saml_b64)
        doc = etree.fromstring(xml_bytes)
    except Exception as e:
        return None, f"XML parse error: {e}"

    # Find the Reference URI in the signature
    ref_uri_el = doc.find(".//ds:Reference", SAML_NS)
    if ref_uri_el is None:
        return None, "No ds:Reference found"
    ref_uri = ref_uri_el.get("URI", "").lstrip("#")

    # Find the signed element by ID
    signed_el = None
    for el in doc.iter():
        if el.get("ID") == ref_uri:
            signed_el = el
            break

    if signed_el is None:
        return None, f"Signed element with ID={ref_uri} not found"

    # Get signature value
    sig_val_el = doc.find(".//ds:SignatureValue", SAML_NS)
    if sig_val_el is None:
        return None, "No SignatureValue"
    sig_bytes = base64.b64decode(sig_val_el.text.strip())

    # Get SignedInfo canonical form
    si_el = doc.find(".//ds:SignedInfo", SAML_NS)
    if si_el is None:
        return None, "No SignedInfo"
    si_c14n = etree.tostring(si_el, method="c14n", exclusive=True)

    # Verify digest of the signed element
    digest_val_el = ref_uri_el.find(".//ds:DigestValue", SAML_NS)
    if digest_val_el is None:
        return None, "No DigestValue"

    # Remove Signature from signed_el for digest computation
    signed_el_copy = etree.fromstring(etree.tostring(signed_el))
    for sig in signed_el_copy.findall(".//ds:Signature", SAML_NS):
        sig.getparent().remove(sig)
    el_c14n = etree.tostring(signed_el_copy, method="c14n", exclusive=True)

    computed_digest = base64.b64encode(hashlib.sha256(el_c14n).digest()).decode()
    expected_digest = digest_val_el.text.strip()
    if computed_digest != expected_digest:
        return None, "Digest mismatch"

    # Verify RSA signature
    cert = get_idp_cert()
    if cert is None:
        return None, "Cannot fetch IDP certificate"

    try:
        cert.public_key().verify(sig_bytes, si_c14n, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        return None, f"Signature verification failed: {e}"

    # *** XSW VULNERABILITY ***
    # Use the FIRST assertion found, not necessarily the signed one
    first_assertion = doc.find(".//saml:Assertion", SAML_NS)
    if first_assertion is None:
        return None, "No Assertion found"

    return first_assertion, None


def extract_user_info(assertion_el):
    """Extract username, role, email from assertion attributes."""
    info = {"username": None, "role": "user", "email": None, "admin": False}

    # NameID
    nameid = assertion_el.find(".//saml:NameID", SAML_NS)
    if nameid is not None:
        info["email"] = nameid.text

    # Attributes
    for attr in assertion_el.findall(".//saml:Attribute", SAML_NS):
        name = attr.get("Name", "")
        val_el = attr.find("saml:AttributeValue", SAML_NS)
        if val_el is not None and val_el.text:
            val = val_el.text.strip()
            if name == "username":
                info["username"] = val
            elif name == "role":
                info["role"] = val
                if val == "admin":
                    info["admin"] = True
            elif name == "email":
                info["email"] = val

    return info


HTML_BASE = """<!DOCTYPE html>
<html>
<head>
  <title>Corp DocPortal</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #f5f5f5; margin: 0; }
    nav { background: #1a3a5c; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
    nav a { color: #7eb3e8; text-decoration: none; margin-left: 1rem; }
    nav a:hover { color: white; }
    .content { padding: 2rem; max-width: 900px; margin: 0 auto; }
    .card { background: white; padding: 1.5rem; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); margin-bottom: 1rem; }
    .btn { display: inline-block; padding: 0.5rem 1.2rem; background: #1a3a5c; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 0.95rem; }
    .btn:hover { background: #2a5a8c; }
    .error { color: red; }
    .success { color: green; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    textarea { width: 100%; height: 120px; font-family: monospace; padding: 0.5rem; box-sizing: border-box; }
    .flag-box { background: #1a1a2e; color: #00ff88; padding: 1rem; border-radius: 4px; font-family: monospace; font-size: 1.1rem; }
  </style>
</head>
<body>
<nav>
  <span><strong>Corp DocPortal</strong></span>
  <span>
    {% if session.get('username') %}
      Signed in as <strong>{{ session.username }}</strong>
      {% if session.get('admin') %} <span style="color:#ffd700">[ADMIN]</span>{% endif %}
      <a href="/logout">Sign out</a>
    {% else %}
      <a href="/login">Sign in</a>
    {% endif %}
  </span>
</nav>
<div class="content">
{% block content %}{% endblock %}
</div>
</body>
</html>"""

HTML_DASHBOARD = HTML_BASE.replace("{% block content %}{% endblock %}", """
<h2>Dashboard</h2>
<div class="card">
  <h3>Welcome, {{ session.username }}!</h3>
  <p>Role: <code>{{ session.role }}</code></p>
  <p><a href="/import" class="btn">Import Document</a>
  {% if session.get('admin') %}
  <a href="/admin/vault" class="btn" style="background:#c0392b; margin-left:0.5rem">Admin Vault</a>
  {% endif %}
  </p>
</div>
<div class="card">
  <h3>Recent Documents</h3>
  <p style="color:#888">No documents yet. Use the importer to upload XML documents.</p>
</div>""")

HTML_IMPORT = HTML_BASE.replace("{% block content %}{% endblock %}", """
<h2>Import XML Document</h2>
<div class="card">
  <p>Upload an XML document to import into the system.</p>
  {% if error %}<p class="error">Error: {{ error }}</p>{% endif %}
  {% if result %}<pre style="background:#f0f0f0;padding:1rem;overflow:auto">{{ result }}</pre>{% endif %}
  <form method="POST" enctype="multipart/form-data">
    <label>XML File:</label><br>
    <input type="file" name="xmlfile" accept=".xml" style="margin:0.5rem 0"><br><br>
    <label>Or paste XML directly:</label><br>
    <textarea name="xmlcontent" placeholder="&lt;?xml version='1.0'?&gt;&#10;&lt;document&gt;...&lt;/document&gt;"></textarea><br><br>
    <button type="submit" class="btn">Import Document</button>
  </form>
  <hr>
  <h4>Supported format:</h4>
  <pre style="background:#f0f0f0;padding:1rem">&lt;document&gt;
  &lt;title&gt;My Document&lt;/title&gt;
  &lt;content&gt;Document body...&lt;/content&gt;
&lt;/document&gt;</pre>
</div>""")

HTML_VAULT = HTML_BASE.replace("{% block content %}{% endblock %}", """
<h2>Admin Credential Vault</h2>
<div class="card">
  {% if flag %}
  <p class="success">Access granted. Vault contents:</p>
  <div class="flag-box">{{ flag }}</div>
  {% else %}
  <p class="error">Access denied. Admin privileges required.</p>
  {% endif %}
</div>""")


@app.route("/")
def index():
    if session.get("username"):
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login")
def login():
    # Redirect to IDP
    return redirect(f"{IDP_SSO_URL}?RelayState=/dashboard")


@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    """Assertion Consumer Service — processes SAML responses."""
    saml_response = request.form.get("SAMLResponse", "")
    relay_state = request.form.get("RelayState", "/dashboard")

    if not saml_response:
        return "Missing SAMLResponse", 400

    assertion, error = verify_saml_response(saml_response)
    if error:
        return f"SAML error: {error}", 400

    user_info = extract_user_info(assertion)
    if not user_info.get("username"):
        return "No username in assertion", 400

    session.clear()
    session["username"] = user_info["username"]
    session["email"] = user_info.get("email", "")
    session["role"] = user_info.get("role", "user")
    session["admin"] = user_info.get("admin", False)

    return redirect(relay_state or "/dashboard")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        return redirect("/login")
    return render_template_string(HTML_DASHBOARD)


@app.route("/import", methods=["GET", "POST"])
def import_doc():
    if not session.get("username"):
        return redirect("/login")

    error = None
    result = None

    if request.method == "POST":
        xml_content = None

        if "xmlfile" in request.files and request.files["xmlfile"].filename:
            xml_content = request.files["xmlfile"].read()
        elif request.form.get("xmlcontent"):
            xml_content = request.form["xmlcontent"].encode()

        if xml_content:
            try:
                # XXE VULNERABILITY: resolve_entities=True allows external entity injection
                # Attacker can read files: <!ENTITY xxe SYSTEM "file:///etc/passwd">
                # Or do SSRF: <!ENTITY ssrf SYSTEM "http://metadata-service/latest/meta-data/iam/security-credentials/ctf-role">
                parser = etree.XMLParser(
                    resolve_entities=True,
                    no_network=False,
                    load_dtd=True
                )
                tree = etree.fromstring(xml_content, parser=parser)

                # Extract and display all text content
                result_parts = []
                for el in tree.iter():
                    if el.text and el.text.strip():
                        result_parts.append(f"<{el.tag}>: {el.text.strip()}")
                result = "\n".join(result_parts) if result_parts else "(empty document)"

            except etree.XMLSyntaxError as e:
                error = f"XML syntax error: {e}"
            except Exception as e:
                error = f"Parse error: {e}"
        else:
            error = "No XML content provided"

    return render_template_string(HTML_IMPORT, error=error, result=result)


@app.route("/admin/vault")
def admin_vault():
    if not session.get("username"):
        return redirect("/login")
    if not session.get("admin"):
        abort(403)
    return render_template_string(HTML_VAULT, flag=FLAG)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    print("[*] SAML SP starting on :8081")
    app.run(host="0.0.0.0", port=8081, debug=False)
