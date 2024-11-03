from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from .base_cert_generator import CertificateGenerator
from .subject import Subject
from .certificate_authority import CertificateAuthority
from .cert_models import ClientCert
from typing import Optional
import os


class ClientCertificateGenerator(CertificateGenerator):
    def create_csr(
        self,
        subject: Subject,
        key_name: Optional[str] = None,
        key_path: Optional[str] = None,
    ) -> str:
        """
        Creates a CSR (Certificate Signing Request) for the client and saves it.

        Parameters:
            key_name (str): The name for the client's private key file.

        Returns:
            str: Path to the saved CSR file.
        """

        if not (key_name or key_path):
            raise ValueError("Either key_name or key_path must be set")

        # Generate a private key for the client
        key_path = key_path or self.create_private_key(key_name)

        # Load the private key for CSR creation
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        # Create CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COUNTRY_NAME,
                            subject.get("country_name"),
                        ),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME,
                            subject.get("state_or_province_name"),
                        ),
                        x509.NameAttribute(
                            NameOID.LOCALITY_NAME,
                            subject.get("locality_name"),
                        ),
                        x509.NameAttribute(
                            NameOID.ORGANIZATION_NAME,
                            subject.get("organization_name"),
                        ),
                        x509.NameAttribute(
                            NameOID.COMMON_NAME,
                            subject.get("common_name"),
                        ),
                    ]
                )
            )
            .sign(private_key, hashes.SHA256())
        )

        # Save CSR to a file
        csr_path = os.path.join(self.output_dir, f"{key_name}_csr.pem")
        with open(csr_path, "wb") as csr_file:
            csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr_path

    def get_signed_csr(
        self, ca_object: CertificateAuthority, csr_path: str, signed_cert_name: str
    ) -> str:
        """
        Sends CSR to a CA object to be signed and saves the signed certificate.

        Parameters:
            ca_object: The Certificate Authority object with a method to sign CSRs.
            csr_name (str): The path to the CSR file.
            signed_cert_name (str): The name for the signed certificate file.

        Returns:
            str: Path to the signed certificate.
        """
        # Use CA object to sign the CSR
        signed_cert_path = os.path.join(self.output_dir, f"{signed_cert_name}.pem")
        ca_object.sign_csr(csr_path, signed_cert_path)

        return signed_cert_path

    def generate_certificate(self, subject: Subject, key_name: str):
        """
        Generates a client certificate by creating a CSR and getting it signed by a CA.

        Parameters:

            key_path (str): Path to the client's private key file.

        Returns:
            str: Path to the signed client certificate.
        """
        key_path = self.create_private_key(key_name)
        csr_path = self.create_csr(subject, key_path=key_path)

        return ClientCert(key_path=key_path, csr_path=csr_path)

    def generate_signed_certificate(
        self, subject: Subject, ca: CertificateAuthority, key_name: str, cert_name
    ):
        key_path = self.create_private_key(key_name)
        csr_path = self.create_csr(subject, key_path=key_path)
        cert_path = self.get_signed_csr(ca, csr_path, cert_name)

        return ClientCert(cert_path, key_path, ca.get_cert(), csr_path)
