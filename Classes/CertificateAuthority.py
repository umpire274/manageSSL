import datetime
import os
import shutil

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateAuthority:
    def __init__(self):
        self.folder_name = os.path.join(os.path.expanduser('~'), 'manageSSL')
        self.file_ca_csr = None
        self.file_ca_key = None
        self.file_ca_config = None
        self.file_ca_cert = None

        dir_paths = ['ca-cert', 'private_keys', 'csr_requests', 'certs']
        self.proceed = True
        if os.path.exists(self.folder_name):
            print(
                """
                \n\nWARNING. You have requested to create a new Root CA Certificate.
The old one will be removed and all certificates generated with old one will be revoked.
                """)
            agree = input("Do you want to proceed (y/N)? " or 'N')
            if agree == 'y' or agree == 'Y':
                try:
                    shutil.rmtree(self.folder_name)
                except OSError as e:
                    print("Error: %s - %s." % (e.filename, e.strerror))
            else:
                self.proceed = False
        if self.proceed:
            os.mkdir(self.folder_name, mode=0o750)
            for items in dir_paths:
                path = os.path.join(self.folder_name, items)
                os.mkdir(path, mode=0o750)
            os.chmod(os.path.join(self.folder_name, 'private_keys'), mode=0o700)
            self.dir_ca = os.path.join(self.folder_name, 'ca-cert')
            self.dir_pk = os.path.join(self.folder_name, 'private_keys')
            self.dir_requests = os.path.join(self.folder_name, 'csr_requests')
            self.dir_certs = os.path.join(self.folder_name, 'certs')

    def create_config_file(self, bits=4096, def_md='sha256', country='IT', org='MyORG', orgunit='MyUnit',
                           commonname='Common Name'):
        config_content = """
[req]
default_bits = """ + str(bits) + """
prompt = no
default_md = """ + def_md + """
encrypt_key = no
distinguished_name = dn

[dn]
C = """ + country + """
O = """ + org + """
OU = """ + orgunit + """
CN = """ + commonname + """
"""
        self.file_ca_config = os.path.join(self.dir_ca, 'ca.cnf')
        with open(self.file_ca_config, "w") as config_file:
            config_file.write(config_content)

    def generate_root_key(self, bites=2048):
        self.file_ca_key = os.path.join(self.dir_ca, 'ca.key')
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bites,
            backend=default_backend()
        )
        # Save private key
        with open(self.file_ca_key, "wt") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode('utf-8'))

    def create_csr(self):
        self.file_ca_csr = os.path.join(self.dir_ca, 'ca.csr')
        with open(self.file_ca_config, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("C = "):
                    country_name = line.split("=")[1].strip()
                elif line.startswith("O = "):
                    org_name = line.split("=")[1].strip()
                elif line.startswith("OU = "):
                    org_unit_name = line.split("=")[1].strip()
                elif line.startswith("CN = "):
                    common_name = line.split("=")[1].strip()
        with open(self.file_ca_key, "rt") as f:
            key_data = f.read()
        private_key = serialization.load_pem_private_key(
            key_data.encode(),
            password=None,
            backend=default_backend()
        )
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).sign(private_key, hashes.SHA256(), default_backend())
        with open(self.file_ca_csr, "wt") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

    def create_self_signed_certificate(self, valid_days):
        # Inizializza self.file_ca_cert con un percorso di file valido
        self.file_ca_cert = os.path.join(self.dir_ca, 'ca.crt')

        # Carica la chiave privata
        with open(self.file_ca_key, "rt") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read().encode(),
                password=None,
                backend=default_backend()
            )

        # Carica la richiesta CSR
        with open(self.file_ca_csr, "rt") as csr_file:
            csr = x509.load_pem_x509_csr(
                csr_file.read().encode(),
                default_backend()
            )

        # Crea un certificato autofirmato
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(csr.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=valid_days))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Salva il certificato
        with open(self.file_ca_cert, "wt") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))
