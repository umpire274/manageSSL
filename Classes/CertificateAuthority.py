import shutil
import os

from OpenSSL import crypto

# Variables
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
FILETYPE_PEM = crypto.FILETYPE_PEM


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
        ca_key = crypto.PKey()
        ca_key.generate_key(TYPE_RSA, bites)
        # Save private key
        with open(self.file_ca_key, "wt") as f:
            f.write(crypto.dump_privatekey(FILETYPE_PEM, ca_key).decode('utf-8'))

    def create_csr(self):
        self.file_ca_csr = os.path.join(self.dir_ca, 'ca.csr')
        req = crypto.X509Req()
        with open(self.file_ca_config, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("C = "):
                    req.get_subject().C = line.split("=")[1].strip()
                elif line.startswith("O = "):
                    req.get_subject().O = line.split("=")[1].strip()
                elif line.startswith("OU = "):
                    req.get_subject().OU = line.split("=")[1].strip()
                elif line.startswith("CN = "):
                    req.get_subject().CN = line.split("=")[1].strip()
        with open(self.file_ca_key, "rt") as f:
            key_data = f.read()
        private_key = crypto.load_privatekey(FILETYPE_PEM, key_data)
        req.set_pubkey(private_key)
        req.sign(private_key, "sha256")
        with open(self.file_ca_csr, "wt") as f:
            f.write(crypto.dump_certificate_request(FILETYPE_PEM, req).decode('utf-8'))

    def create_self_signed_certificate(self, valid_days):
        # Inizializza self.file_ca_cert con un percorso di file valido
        self.file_ca_cert = os.path.join(self.dir_ca, 'ca.crt')

        # Carica la chiave privata
        with open(self.file_ca_key, "rt") as key_file:
            private_key = crypto.load_privatekey(FILETYPE_PEM, key_file.read().encode())

        # Carica la richiesta CSR
        with open(self.file_ca_csr, "rt") as csr_file:
            csr = crypto.load_certificate_request(FILETYPE_PEM, csr_file.read().encode())

        # Crea un certificato autofirmato
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(valid_days * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_serial_number(1000)
        cert.sign(private_key, 'sha256')

        # Salva il certificato
        with open(self.file_ca_cert, "wt") as f:
            f.write(crypto.dump_certificate(FILETYPE_PEM, cert).decode('utf-8'))
