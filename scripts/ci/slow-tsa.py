"""An RFC 3161 timestamp authority for e2e.sh that waits before every answer,
the way a slow public TSA does:

  python slow-tsa.py <port> <delay seconds> <tsa.der> <tsa.key> <ca.der>

It runs on the signing service's image, which has pyHanko, and stamps with
pyHanko's DummyTimeStamper, as the service's tests do: the certificate in
<tsa.der> and its PKCS#8 key in <tsa.key>, embedding the CA in <ca.der>.
Requests are answered concurrently, each logged with its arrival time.
"""
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from asn1crypto import keys, tsp, x509
from pyhanko.sign.timestamps import DummyTimeStamper

port, delay, cert_path, key_path, ca_path = sys.argv[1:6]


def load(path):
    with open(path, "rb") as file:
        return file.read()


stamper = DummyTimeStamper(
    tsa_cert=x509.Certificate.load(load(cert_path)),
    tsa_key=keys.PrivateKeyInfo.load(load(key_path)),
    certs_to_embed=[x509.Certificate.load(load(ca_path))],
)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        arrived = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        request = tsp.TimeStampReq.load(self.rfile.read(int(self.headers["Content-Length"])))
        time.sleep(float(delay))
        response = stamper.request_tsa_response(request).dump()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        print(f"timestamp requested at {arrived}, answered after {delay} s", flush=True)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(port)), Handler).serve_forever()
