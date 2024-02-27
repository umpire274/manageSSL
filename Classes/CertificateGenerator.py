from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os


class CertificateGenerator:
    def __init__(self):
        self.crt_file = None
        self.csr_file = None
        self.folder_name = os.path.join(os.path.expanduser('~'), 'manageSSL')
        self.ca_cert_file = os.path.join(self.folder_name, 'ca-cert/ca.crt')
        self.ca_key_file = os.path.join(self.folder_name, 'ca-cert/ca.key')
        self.dir_pk = os.path.join(self.folder_name, 'private_keys')
        self.dir_requests = os.path.join(self.folder_name, 'csr_requests')
        self.dir_certs = os.path.join(self.folder_name, 'certs')

    def check_ca_ready(self):
        if os.path.exists(self.ca_cert_file) and os.path.exists(self.ca_key_file):
            print("CA is ready\n-----------\n\n")
        else:
            print("CA is not ready, generate it first")
            print("Choose option 1 in the main menu")
            print("--------------------------------\n\n")
            return False
        return True

    def generate_certificate(self, csr_file, valid_days):
        self.csr_file = os.path.join(self.dir_requests, csr_file + '.csr')
        self.crt_file = os.path.join(self.dir_certs, csr_file + '.crt')

        with open(self.ca_cert_file, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(self.ca_key_file, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        with open(self.csr_file, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=int(valid_days)))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        with open(self.crt_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))


