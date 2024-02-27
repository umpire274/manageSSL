import os.path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization


class CertificateCSRGenerator:
    def __init__(self, key_length, country_name, state_name, locality_name,
                 org_name, org_unit_name, common_name):
        dir_paths = ['private_keys', 'csr_requests', 'certs']

        self.private_key_file = None
        self.csr_file = None
        self.key_length = key_length
        self.country_name = country_name
        self.state_name = state_name
        self.locality_name = locality_name
        self.org_name = org_name
        self.org_unit_name = org_unit_name
        self.common_name = common_name

        self.folder_name = os.path.join(os.path.expanduser('~'), 'manageSSL')
        if not os.path.exists(self.folder_name):
            os.mkdir(self.folder_name, mode=0o750)
            for items in dir_paths:
                path = os.path.join(self.folder_name, items)
                os.mkdir(path, mode=0o750)
        self.dir_pk = os.path.join(self.folder_name, 'private_keys')
        self.dir_requests = os.path.join(self.folder_name, 'csr_requests')
        self.dir_certs = os.path.join(self.folder_name, 'certs')

    def generate_private_key(self, private_key_file):
        self.private_key_file = os.path.join(self.dir_pk, private_key_file + '.key')
        pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_length,
            backend=default_backend()
        )

        with open(self.private_key_file, "wb") as f:
            f.write(pkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        return pkey

    def generate_csr(self, pkey, csr_file):
        self.csr_file = os.path.join(self.dir_requests, csr_file + '.csr')
        new_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.org_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.org_unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])).sign(pkey, hashes.SHA256(), default_backend())

        with open(self.csr_file, "wb") as f:
            f.write(new_csr.public_bytes(serialization.Encoding.PEM))
