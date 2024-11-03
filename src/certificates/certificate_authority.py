from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
)
from cryptography.hazmat.primitives import serialization

from datetime import datetime, timedelta


class CertificateAuthority:
    def __init__(self, cert_path: str, key_path: str):
        """
        Initialize with paths to the x.509 certificate and private key for MQTT authentication.
        """
        self.cert_file = cert_path
        self.key_file = key_path
        self.ca_key = self._load_key(key_path)
        self.ca_cert = self._load_cert(cert_path)

    def _load_cert(self, cert_path: str):
        """Load the CA certificate from a file."""
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def _load_key(self, key_path: str):
        """Load the CA private key from a file."""
        with open(key_path, "rb") as f:
            return load_pem_private_key(f.read(), password=None)

    def sign_csr(self, csr_path: str, signed_cert_path: str, valid_after=365) -> str:

        # Load the CSR
        with open(csr_path, "rb") as f:
            try:
                csr = x509.load_pem_x509_csr(f.read())
            except ValueError as e:
                raise e
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        # Check that CSR is valid
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR signature")

        # Create the certificate using the CSR's subject and public key
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=valid_after))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(private_key=self.ca_key, algorithm=hashes.SHA256())
        )

        # Write the signed certificate to a file
        with open(signed_cert_path, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))

        return signed_cert_path

    def get_cert(self) -> str:
        """Return the CA certificate file path."""
        return self.cert_file


if __name__ == "__main__":
    ca = CertificateAuthority("path/to/ca_cert.pem", "path/to/ca_key.pem")
    signed_cert_path = ca.sign_csr(
        "path/to/client.csr", "path/to/signed_client_cert.pem"
    )
    print(f"Signed certificate saved at: {signed_cert_path}")
