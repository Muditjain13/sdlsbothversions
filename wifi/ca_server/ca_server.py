"""
SLDS CA Server — issues X.509 certificates to PC and Android device.

Usage:
    pip install -r requirements.txt
    python ca_server.py

Endpoints:
    GET  /ca-cert      Returns CA certificate PEM
    POST /register     Body: {"csr": "<PEM>", "device_id": "<string>"}
                       Returns: {"certificate": "<PEM>"}
"""

from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os
import socket
import atexit

try:
    from zeroconf import ServiceInfo, Zeroconf
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False
    print("[CA] WARNING: zeroconf not installed — mDNS discovery disabled. Run: pip install zeroconf")

_UTC = datetime.timezone.utc

def _now():
    return datetime.datetime.now(_UTC)

CA_KEY_FILE  = "ca_key.pem"
CA_CERT_FILE = "ca_cert.pem"

app = Flask(__name__)
ca_key  = None
ca_cert = None

# In-memory list of registered devices  {device_id, registered_at, ip}
registered_devices = []


def load_or_create_ca():
    global ca_key, ca_cert

    if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        print("[CA] Loaded existing CA key and certificate from disk.")
    else:
        print("[CA] Generating new CA key and self-signed certificate...")
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,            "SLDS-CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,      "SLDS"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,"Auth"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now())
            .not_valid_after(_now() + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True,
                    crl_sign=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        with open(CA_KEY_FILE, "wb") as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        with open(CA_CERT_FILE, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        print("[CA] CA key and certificate saved.")


@app.route("/", methods=["GET"])
def homepage():
    ca_valid_until = ca_cert.not_valid_after_utc.strftime("%Y-%m-%d") if ca_cert else "N/A"

    rows = ""
    for i, d in enumerate(registered_devices, 1):
        # Determine type from device_id prefix
        if d["device_id"].startswith("PC-"):
            icon  = "💻"
            dtype = "Windows PC"
        else:
            icon  = "📱"
            dtype = "Android"
        rows += f"""
        <tr>
            <td>{i}</td>
            <td>{icon} {dtype}</td>
            <td><strong>{d['device_id']}</strong></td>
            <td>{d['ip']}</td>
            <td>{d['time']}</td>
            <td><span class="badge">Registered</span></td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="6" class="empty">No devices registered yet.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SLDS CA Server</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; padding: 32px 24px; }}
  h1   {{ font-size: 1.6rem; color: #fff; margin-bottom: 4px; }}
  .sub {{ color: #888; font-size: 0.9rem; margin-bottom: 32px; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }}
  .card {{ background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 10px; padding: 20px 24px; flex: 1; min-width: 180px; }}
  .card .label {{ font-size: 0.78rem; color: #888; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 6px; }}
  .card .value {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
  .card .value.green {{ color: #4ade80; }}
  .card .value.blue  {{ color: #60a5fa; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d27; border-radius: 10px; overflow: hidden; border: 1px solid #2a2d3a; }}
  thead {{ background: #13151f; }}
  th   {{ padding: 12px 16px; text-align: left; font-size: 0.78rem; color: #888; text-transform: uppercase; letter-spacing: .05em; }}
  td   {{ padding: 13px 16px; font-size: 0.9rem; border-top: 1px solid #23263a; }}
  tr:hover td {{ background: #20233a; }}
  .badge {{ background: #14532d; color: #4ade80; border-radius: 999px; padding: 2px 10px; font-size: 0.78rem; font-weight: 600; }}
  .empty {{ text-align: center; color: #555; padding: 40px; }}
  .section-title {{ font-size: 1rem; font-weight: 600; color: #ccc; margin-bottom: 12px; }}
  .dot {{ width: 8px; height: 8px; background: #4ade80; border-radius: 50%; display: inline-block; margin-right: 6px; animation: pulse 2s infinite; }}
  @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:.4}} }}
</style>
</head>
<body>
  <h1>🔐 SLDS Certificate Authority</h1>
  <p class="sub"><span class="dot"></span>Server running &nbsp;·&nbsp; CA valid until {ca_valid_until} &nbsp;·&nbsp; Port 8443</p>

  <div class="cards">
    <div class="card">
      <div class="label">Registered Devices</div>
      <div class="value green">{len(registered_devices)}</div>
    </div>
    <div class="card">
      <div class="label">Android Devices</div>
      <div class="value blue">{sum(1 for d in registered_devices if not d['device_id'].startswith('PC-'))}</div>
    </div>
    <div class="card">
      <div class="label">Windows PCs</div>
      <div class="value blue">{sum(1 for d in registered_devices if d['device_id'].startswith('PC-'))}</div>
    </div>
    <div class="card">
      <div class="label">CA Status</div>
      <div class="value green">Active</div>
    </div>
  </div>

  <p class="section-title">Registered Devices</p>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Type</th><th>Device ID</th><th>IP Address</th><th>Registered At</th><th>Status</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
    return html, 200, {"Content-Type": "text/html"}


@app.route("/ca-cert", methods=["GET"])
def get_ca_cert():
    pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    return pem, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data or "csr" not in data:
        return jsonify({"error": "Missing 'csr' field"}), 400

    device_id = data.get("device_id", "unknown-device")

    try:
        csr = x509.load_pem_x509_csr(data["csr"].encode())
    except Exception as exc:
        return jsonify({"error": f"Invalid CSR: {exc}"}), 400

    if not csr.is_signature_valid:
        return jsonify({"error": "CSR signature verification failed"}), 400

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,   # nonRepudiation — required for PDF signing
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    print(f"[CA] Issued certificate for device: {device_id}")

    registered_devices.append({
        "device_id": device_id,
        "ip":        request.remote_addr,
        "time":      _now().strftime("%Y-%m-%d %H:%M:%S UTC"),
    })

    return jsonify({"certificate": cert_pem})


def _get_local_ip():
    """Return the LAN IP address of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _start_mdns(port: int):
    """Advertise this CA server on the LAN via mDNS so clients find it automatically."""
    if not _ZEROCONF_AVAILABLE:
        return None, None

    local_ip = _get_local_ip()
    info = ServiceInfo(
        "_slds-ca._tcp.local.",
        "slds-ca._slds-ca._tcp.local.",
        addresses=[socket.inet_aton(local_ip)],
        port=port,
        properties={"version": "1"},
    )
    zc = Zeroconf()
    zc.register_service(info)
    print(f"[CA] mDNS: advertising as 'slds-ca._slds-ca._tcp.local.' at {local_ip}:{port}")
    return zc, info


if __name__ == "__main__":
    load_or_create_ca()

    PORT = 8443
    zc, mdns_info = _start_mdns(PORT)

    @atexit.register
    def _stop_mdns():
        if zc and mdns_info:
            try:
                zc.unregister_service(mdns_info)
                zc.close()
                print("[CA] mDNS service unregistered.")
            except Exception:
                pass

    print(f"[CA] Starting HTTPS server on port {PORT} ...")
    # ssl_context="adhoc" uses a temporary self-signed server cert (pyOpenSSL).
    app.run(host="0.0.0.0", port=PORT, ssl_context="adhoc")
