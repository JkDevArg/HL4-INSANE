#!/usr/bin/env python3
"""
Simulated AWS EC2 Instance Metadata Service (IMDS).
Reachable via SSRF from the SP's XXE-vulnerable document importer.
The flag is embedded in the fake IAM security credentials response.
"""
import os
import json
from flask import Flask, jsonify, Response

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")


@app.route("/")
def root():
    return Response("EC2 Instance Metadata Service\n", mimetype="text/plain")


@app.route("/latest/")
@app.route("/latest/meta-data/")
def metadata_root():
    return Response(
        "ami-id\nami-launch-index\nami-manifest-path\nhostname\n"
        "iam/\ninstance-id\ninstance-type\nlocal-ipv4\npublic-ipv4\n",
        mimetype="text/plain"
    )


@app.route("/latest/meta-data/instance-id")
def instance_id():
    return Response("i-0a1b2c3d4e5f67890\n", mimetype="text/plain")


@app.route("/latest/meta-data/instance-type")
def instance_type():
    return Response("t3.medium\n", mimetype="text/plain")


@app.route("/latest/meta-data/local-ipv4")
def local_ipv4():
    return Response("10.0.1.42\n", mimetype="text/plain")


@app.route("/latest/meta-data/hostname")
def hostname():
    return Response("ip-10-0-1-42.corp.internal\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/")
def iam_root():
    return Response("info\nsecurity-credentials/\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/info")
def iam_info():
    return jsonify({
        "Code": "Success",
        "LastUpdated": "2024-01-15T10:30:00Z",
        "InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/ctf-role",
        "InstanceProfileId": "AIPAIOSFODNN7EXAMPLE"
    })


@app.route("/latest/meta-data/iam/security-credentials/")
def iam_creds_list():
    return Response("ctf-role\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/ctf-role")
def iam_creds():
    """
    The flag is embedded here as the SecretAccessKey.
    Reached via XXE SSRF from the SP's document importer.
    Attack chain:
      1. XSW to get admin session OR just use the XXE directly
      2. POST to /import with XXE payload referencing this URL
      3. Response contains the flag
    """
    return jsonify({
        "Code": "Success",
        "LastUpdated": "2024-01-15T10:30:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": FLAG,
        "Token": "AQoDYXdzEJr//////////wEaoAK1wvxJY12r2IWAkL8jD+MQLmZkfOmAptwn",
        "Expiration": "2099-01-16T10:30:00Z",
        "RoleArn": "arn:aws:iam::123456789012:role/ctf-role"
    })


@app.route("/latest/user-data")
def user_data():
    return Response("#!/bin/bash\necho 'Nothing interesting here'\n", mimetype="text/plain")


if __name__ == "__main__":
    print("[*] Metadata service starting on :80")
    app.run(host="0.0.0.0", port=80, debug=False)
