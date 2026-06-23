import os
from flask import Flask, jsonify, Response

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")
VAULT_TOKEN = "ctf-vault-token-xyz789-secret"


@app.route("/")
def index():
    return Response("AWS Metadata Service v1.0\n", mimetype="text/plain")


@app.route("/latest/meta-data/")
def metadata_root():
    content = """ami-id
ami-launch-index
ami-manifest-path
hostname
iam/
instance-action
instance-id
instance-type
local-hostname
local-ipv4
mac
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
"""
    return Response(content, mimetype="text/plain")


@app.route("/latest/meta-data/instance-id")
def instance_id():
    return Response("i-0abcdef1234567890\n", mimetype="text/plain")


@app.route("/latest/meta-data/local-ipv4")
def local_ipv4():
    return Response("172.20.0.3\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/")
def iam_root():
    return Response("security-credentials/\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/")
def iam_creds_list():
    return Response("ctf-role\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/ctf-role")
def iam_creds_role():
    creds = {
        "Code": "Success",
        "LastUpdated": "2024-01-15T10:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": VAULT_TOKEN,
        "Expiration": "2099-01-01T00:00:00Z"
    }
    return jsonify(creds)


@app.route("/latest/user-data")
def user_data():
    return Response("userdata\n", mimetype="text/plain")


@app.route("/latest/meta-data/placement/region")
def region():
    return Response("us-east-1\n", mimetype="text/plain")


@app.route("/latest/meta-data/hostname")
def hostname():
    return Response("ip-172-20-0-3.ec2.internal\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
