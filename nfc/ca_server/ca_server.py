#!/usr/bin/env python3
"""
SecureNFC Certificate Authority Server

Endpoints:
  POST /register  body: {"csr": "<PEM>", "device_id": "<string>"}
                  returns: {"certificate": "<PEM>"}
  GET  /ca-cert   returns CA certificate PEM (plain text)
  GET  /          HTML status page

Legacy endpoint (generates key+cert server-side, for testing only):
  POST /generate  body: {"device_id": "<string>", "device_type": "<string>"}
"""

import os
import json
import socket
import threading
import atexit
from datetime import datetime, timedelta, timezone

try:
    from zeroconf import ServiceInfo, Zeroconf
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False
    print("[CA] WARNING: zeroconf not installed — mDNS disabled. Run: pip install zeroconf")

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateAuthority:
    def __init__(self, ca_name="SecureNFC-CA", port=12345):
        self.ca_name = ca_name
        self.port = port
        self.ca_private_key = None
        self.ca_certificate = None
        self.issued_certs = {}   # device_id -> info dict
        self._setup_ca()

    # ── CA initialisation ──────────────────────────────────────────────────

    def _setup_ca(self):
        ca_cert_file = "ca_certificate.pem"
        ca_key_file  = "ca_private_key.pem"

        if os.path.exists(ca_cert_file) and os.path.exists(ca_key_file):
            print("Loading existing CA key and certificate...")
            with open(ca_key_file, "rb") as f:
                self.ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ca_cert_file, "rb") as f:
                self.ca_certificate = x509.load_pem_x509_certificate(f.read())
            print(f"CA loaded: {self.ca_certificate.subject}")
            return

        print(f"Generating new CA: {self.ca_name}")
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        now = datetime.now(timezone.utc)
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureNFC Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        self.ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(self.ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ), critical=True,
            )
            .sign(self.ca_private_key, hashes.SHA256(), default_backend())
        )

        with open(ca_cert_file, "wb") as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
        with open(ca_key_file, "wb") as f:
            f.write(self.ca_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        print(f"CA certificate saved to {ca_cert_file}")

    # ── Certificate issuance ───────────────────────────────────────────────

    def issue_from_csr(self, csr_pem: str, device_id: str) -> str:
        """Issue a certificate from a PKCS#10 CSR PEM. Returns cert PEM string."""
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureNFC Device"),
                x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            ]))
            .issuer_name(self.ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                ]), critical=False,
            )
            .sign(self.ca_private_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        # Save cert file
        cert_file = f"{device_id}_certificate.pem"
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self.issued_certs[device_id] = {
            "device_id": device_id,
            "cert_file": cert_file,
            "issued_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        print(f"Issued certificate for {device_id} → {cert_file}")
        return cert_pem

    def issue_with_generated_key(self, device_id: str, device_type: str = "unknown") -> dict:
        """Legacy: generate key+cert server-side. Returns dict with PEM strings."""
        device_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureNFC Device"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, device_type),
                x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            ]))
            .issuer_name(self.ca_certificate.subject)
            .public_key(device_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True,
            )
            .sign(self.ca_private_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem  = device_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        cert_file = f"{device_id}_certificate.pem"
        key_file  = f"{device_id}_private_key.pem"
        with open(cert_file, "wb") as f: f.write(cert_pem.encode())
        with open(key_file,  "wb") as f: f.write(key_pem.encode())

        self.issued_certs[device_id] = {
            "device_id": device_id, "device_type": device_type,
            "cert_file": cert_file, "key_file": key_file,
            "issued_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        return {
            "device_id": device_id,
            "certificate_pem": cert_pem,
            "private_key_pem": key_pem,
            "ca_certificate_pem": self.ca_certificate.public_bytes(serialization.Encoding.PEM).decode(),
        }

    # ── HTTP request handling ──────────────────────────────────────────────

    def handle_client(self, client_socket, address):
        print(f"Connection from {address}")
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                raw += chunk

            request = raw.decode("utf-8", errors="replace")
            first_line = request.split("\r\n", 1)[0]
            method, path, *_ = first_line.split(" ")

            # Read body if Content-Length present
            body = ""
            if "Content-Length:" in request:
                for line in request.split("\r\n"):
                    if line.startswith("Content-Length:"):
                        content_length = int(line.split(":", 1)[1].strip())
                        body_start = request.find("\r\n\r\n") + 4
                        body = request[body_start:]
                        while len(body.encode()) < content_length:
                            body += client_socket.recv(content_length - len(body.encode())).decode("utf-8", errors="replace")
                        break

            # ── Route ────────────────────────────────────────────────────

            if method == "GET" and path in ("/", "/status"):
                self._send_http(client_socket, "200 OK", "text/html", self._status_page())

            elif method == "GET" and path == "/ca-cert":
                ca_pem = self.ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
                self._send_http(client_socket, "200 OK", "text/plain", ca_pem)

            elif method == "POST" and path == "/register":
                # CSR-based registration
                data = json.loads(body)
                csr_pem   = data.get("csr", "").replace("\\n", "\n")
                device_id = data.get("device_id", "unknown")
                cert_pem  = self.issue_from_csr(csr_pem, device_id)
                resp = json.dumps({"certificate": cert_pem})
                self._send_http(client_socket, "200 OK", "application/json", resp)

            elif method == "POST" and path == "/generate":
                # Legacy: server-side key generation
                data = json.loads(body)
                device_id   = data.get("device_id", "unknown")
                device_type = data.get("device_type", "unknown")
                result = self.issue_with_generated_key(device_id, device_type)
                resp = json.dumps({"status": "success", "data": result}, indent=2)
                self._send_http(client_socket, "200 OK", "application/json", resp)

            else:
                self._send_http(client_socket, "404 Not Found", "text/plain", "Not found")

        except Exception as e:
            print(f"Error handling {address}: {e}")
            try:
                self._send_http(client_socket, "500 Internal Server Error", "application/json",
                                json.dumps({"error": str(e)}))
            except Exception:
                pass
        finally:
            client_socket.close()
            print(f"Closed {address}")

    @staticmethod
    def _send_http(sock, status, content_type, body):
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8") + body_bytes
        sock.sendall(response)

    def _status_page(self):
        rows = "".join(
            f"<tr><td>{info['device_id']}</td>"
            f"<td>{info.get('device_type', 'CSR')}</td>"
            f"<td>{info['issued_at']}</td>"
            f"<td>{info['cert_file']}</td></tr>"
            for info in self.issued_certs.values()
        )
        ca_pem = self.ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
        return f"""<!DOCTYPE html>
<html><head><title>SecureNFC CA</title>
<style>body{{font-family:Arial,sans-serif;margin:40px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#3498db;color:white}}
pre{{background:#f8f9fa;padding:10px;overflow-x:auto}}</style></head>
<body>
<h1>SecureNFC Certificate Authority</h1>
<p><b>CA:</b> {self.ca_name} &nbsp; <b>Port:</b> {self.port} &nbsp;
   <b>Issued:</b> {len(self.issued_certs)}</p>
<h2>Issued Certificates</h2>
<table><tr><th>Device ID</th><th>Type</th><th>Issued</th><th>Cert file</th></tr>
{rows}</table>
<h2>API</h2>
<pre>POST /register  {{"csr":"&lt;PEM&gt;","device_id":"PC-SLDS"}}
GET  /ca-cert   → CA certificate PEM
POST /generate  {{"device_id":"...","device_type":"..."}}  (legacy)</pre>
<h2>CA Certificate</h2><pre>{ca_pem}</pre>
</body></html>"""

    # ── Server loop ────────────────────────────────────────────────────────

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", self.port))
        server_socket.listen(10)

        print("=" * 55)
        print(f" SecureNFC Certificate Authority")
        print(f" Listening on http://0.0.0.0:{self.port}")
        print(f" POST /register  — CSR-based cert issuance")
        print(f" GET  /ca-cert   — fetch CA cert PEM")
        print(f" GET  /          — status page")
        print("=" * 55)

        try:
            while True:
                client_sock, addr = server_socket.accept()
                t = threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            server_socket.close()


def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _start_mdns(port: int):
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
    PORT = 12345
    ca = CertificateAuthority(ca_name="SecureNFC-CA", port=PORT)

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

    ca.start()
