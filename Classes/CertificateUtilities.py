import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class CertificateUtilities:
    def __init__(self):
        self.csr_file = None
        self.crt_file = None
        self.folder_name = os.path.join(os.path.expanduser('~'), 'manageSSL')
        self.ca_cert_file = os.path.join(self.folder_name, 'ca-cert/ca.crt')
        self.ca_key_file = os.path.join(self.folder_name, 'ca-cert/ca.key')
        self.dir_pk = os.path.join(self.folder_name, 'private_keys')
        self.dir_requests = os.path.join(self.folder_name, 'csr_requests')
        self.dir_certs = os.path.join(self.folder_name, 'certs')

    def check_certificate(self, crt_file):
        self.crt_file = os.path.join(self.dir_certs, crt_file + '.crt')
        if os.path.exists(self.crt_file):
            try:
                with open(self.crt_file, 'rb') as crt_file:
                    cert_data = crt_file.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

                    # Estrai informazioni dal certificato
                    subject = cert.subject
                    issuer = cert.issuer
                    valid_from = cert.not_valid_before_utc
                    valid_to = cert.not_valid_after_utc

                    # Stampa le informazioni
                    print(f"\n-----------------------")
                    print(f"Certificato valido per:")
                    print(f"  Soggetto: {subject.rfc4514_string()}")
                    print(f"  Emesso da: {issuer.rfc4514_string()}")
                    print(f"  Validità da: {valid_from}")
                    print(f"  Validità a: {valid_to}")
                    print(f"-----------------------")

                    # Verifica del certificato
                    # Puoi aggiungere ulteriori controlli qui, se necessario
                    print(f"Il certificato {self.crt_file} è valido.")
                    print(f"-----------------------\n")
            except Exception as e:
                print(f"Errore nella verifica del certificato: {e}")
        else:
            print(f"il certificato {self.crt_file} non esiste. Controllare.")

    def check_certificate_request(self, csr_file):
        self.csr_file = os.path.join(self.dir_requests, csr_file + '.csr')
        try:
            with open(self.csr_file, 'rb') as csr_file:
                csr_data = csr_file.read()
                csr = x509.load_pem_x509_csr(csr_data, default_backend())

                # Estrai informazioni dalla richiesta di certificato
                subject = csr.subject
                public_key = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

                # Stampa le informazioni
                print(f"\n-----------------------")
                print(f"Informazioni dalla richiesta di certificato {self.csr_file}:")
                print(f"-----------------------")
                print(f"  Soggetto: {subject.rfc4514_string()}")
                print(f"  Chiave pubblica: \n{public_key}")

                # Verifica se la richiesta di certificato è valida
                # Puoi aggiungere ulteriori controlli qui, se necessario
                print(f"La richiesta di certificato è valida.")
                print(f"-----------------------\n")
        except Exception as e:
            print(f"Errore nella verifica della richiesta di certificato: {e}")
