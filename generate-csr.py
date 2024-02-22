from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Inserimento da tastiera
key_length = int(input("Inserisci la lunghezza della chiave: "))
country_name = input("Inserisci il nome del paese (es. IT): ")
state_name = input("Inserisci il nome dello stato o della provincia: ")
locality_name = input("Inserisci il nome della località: ")
org_name = input("Inserisci il nome dell'organizzazione: ")
org_unit_name = input("Inserisci il nome dell'unità organizzativa: ")
common_name = input("Inserisci il nome comune: ")
private_key_file = input("Inserisci il nome del file per la chiave privata (senza estensione): ") + ".key"
csr_file = input("Inserisci il nome del file per il CSR (senza estensione): ") + ".csr"

# Generazione della chiave privata
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=key_length,
    backend=default_backend()
)

# Generazione del CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_name),
    x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit_name),
    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
])).sign(private_key, hashes.SHA256(), default_backend())

# Salvataggio della chiave privata nel file
with open(private_key_file, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

# Salvataggio del CSR nel file
with open(csr_file, "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
