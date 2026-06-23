#!/usr/bin/env python3
"""
SAML Identity Provider.
Issues SAML 2.0 assertions signed with RSA-SHA256.
The assertion signing is vulnerable to XML Signature Wrapping (XSW):
the verifier finds the signed element by ID reference but does not
enforce that the signed element is the one used for authorization.
"""
import os
import base64
import hashlib
import uuid
import datetime
from pathlib import Path
from flask import Flask, request, session, redirect, render_template_string, jsonify, url_for
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

app = Flask(__name__)
app.secret_key = "idp-secret-key-not-important"

SP_ACS_URL = os.environ.get("SP_ACS_URL", "http://sp:8081/saml/acs")
IDP_ISSUER = "http://idp.corp.local/saml"

PRIVATE_KEY_PATH = Path("/app/keys/idp_private.pem")
CERT_PATH = Path("/app/keys/idp_cert.pem")

# Valid users
USERS = {
    "alice": {"password": "alice123", "role": "user", "email": "alice@corp.local"},
    "bob":   {"password": "bob123",   "role": "user", "email": "bob@corp.local"},
}

HTML_LOGIN = """<!DOCTYPE html>
<html>
<head>
  <title>Corp SSO — Login</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: white; padding: 2rem 3rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); min-width: 320px; }
    h2 { text-align: center; color: #333; margin-bottom: 1.5rem; }
    input { width: 100%; padding: 0.6rem; margin: 0.3rem 0 1rem 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
    button { width: 100%; padding: 0.7rem; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
    button:hover { background: #0055aa; }
    .error { color: red; text-align: center; margin-bottom: 1rem; }
    .brand { text-align: center; color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Corp SSO</h2>
    <p class="brand">Identity Provider</p>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="POST">
      <input type="hidden" name="relay_state" value="{{ relay_state }}">
      <label>Username</label>
      <input type="text" name="username" placeholder="alice" required>
      <label>Password</label>
      <input type="password" name="password" required>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>"""

HTML_METADATA = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="http://idp.corp.local/saml">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://idp.corp.local:8080/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""


def load_private_key():
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(), password=None
    )


def get_cert_b64():
    pem = CERT_PATH.read_text()
    lines = [l for l in pem.strip().split("\n") if not l.startswith("-----")]
    return "".join(lines)


def sign_xml(xml_string: bytes, private_key) -> bytes:
    """
    Sign an XML document using enveloped XML signature (RSA-SHA256).
    The signature covers the Assertion element identified by its ID attribute.
    VULNERABILITY: The signature references the assertion by ID, but the SP's
    verifier finds the signed element then uses a DIFFERENT element for auth
    when XSW wrapping is applied.
    """
    doc = etree.fromstring(xml_string)
    ns = {
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "ds": "http://www.w3.org/2000/09/xmldsig#"
    }

    assertion = doc.find(".//saml:Assertion", ns)
    assertion_id = assertion.get("ID")

    # Canonicalize the Assertion for digest computation (exclusive C14N)
    assertion_c14n = etree.tostring(assertion, method="c14n", exclusive=True)
    digest = hashlib.sha256(assertion_c14n).digest()
    digest_b64 = base64.b64encode(digest).decode()

    # Build SignedInfo
    signed_info_xml = f"""<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#{assertion_id}">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digest_b64}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>"""

    si_el = etree.fromstring(signed_info_xml.encode())
    si_c14n = etree.tostring(si_el, method="c14n", exclusive=True)
    sig_value = private_key.sign(si_c14n, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig_value).decode()
    cert_b64 = get_cert_b64()

    signature_xml = f"""<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  {signed_info_xml}
  <ds:SignatureValue>{sig_b64}</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>"""

    sig_el = etree.fromstring(signature_xml.encode())
    # Insert signature as first child of Assertion
    assertion.insert(0, sig_el)

    return etree.tostring(doc, xml_declaration=True, encoding="UTF-8")


def build_saml_response(username: str, user_info: dict, relay_state: str = "") -> str:
    response_id = "_" + uuid.uuid4().hex
    assertion_id = "_" + uuid.uuid4().hex
    now = datetime.datetime.utcnow()
    not_after = now + datetime.timedelta(minutes=10)
    fmt = "%Y-%m-%dT%H:%M:%SZ"

    saml_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}"
    Version="2.0"
    IssueInstant="{now.strftime(fmt)}"
    Destination="{SP_ACS_URL}"
    InResponseTo="_ctf_authn_request">
  <saml:Issuer>{IDP_ISSUER}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="{assertion_id}"
      Version="2.0"
      IssueInstant="{now.strftime(fmt)}">
    <saml:Issuer>{IDP_ISSUER}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user_info['email']}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            NotOnOrAfter="{not_after.strftime(fmt)}"
            Recipient="{SP_ACS_URL}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now.strftime(fmt)}" NotOnOrAfter="{not_after.strftime(fmt)}">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.corp.local/saml</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{now.strftime(fmt)}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="username">
        <saml:AttributeValue>{username}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>{user_info['role']}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{user_info['email']}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

    private_key = load_private_key()
    signed = sign_xml(saml_xml.encode(), private_key)
    return base64.b64encode(signed).decode()


@app.route("/")
def index():
    return redirect("/saml/login")


@app.route("/saml/login", methods=["GET", "POST"])
def saml_login():
    relay_state = request.args.get("RelayState", "") or request.form.get("relay_state", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)
        if user and user["password"] == password:
            session["username"] = username
            # Build and return SAML response
            saml_response = build_saml_response(username, user, relay_state)
            # Auto-submit form to SP ACS
            html = f"""<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="POST" action="{SP_ACS_URL}">
  <input type="hidden" name="SAMLResponse" value="{saml_response}">
  <input type="hidden" name="RelayState" value="{relay_state}">
  <button type="submit">Continue to application</button>
</form>
<p>Redirecting to application...</p>
</body></html>"""
            return html

        return render_template_string(HTML_LOGIN, error="Invalid credentials", relay_state=relay_state)

    return render_template_string(HTML_LOGIN, error=None, relay_state=relay_state)


@app.route("/saml/metadata")
def saml_metadata():
    cert_b64 = get_cert_b64()
    xml = HTML_METADATA.format(cert=cert_b64)
    return xml, 200, {"Content-Type": "application/xml"}


@app.route("/saml/sso", methods=["POST"])
def saml_sso():
    """Direct SSO endpoint — accepts SP-initiated requests."""
    username = session.get("username")
    if not username or username not in USERS:
        return redirect(f"/saml/login?RelayState={request.form.get('RelayState', '')}")

    user = USERS[username]
    relay_state = request.form.get("RelayState", "")
    saml_response = build_saml_response(username, user, relay_state)

    html = f"""<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="POST" action="{SP_ACS_URL}">
  <input type="hidden" name="SAMLResponse" value="{saml_response}">
  <input type="hidden" name="RelayState" value="{relay_state}">
</form>
</body></html>"""
    return html


if __name__ == "__main__":
    print("[*] SAML IDP starting on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
