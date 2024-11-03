from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from .base_cert_generator import CertificateGenerator
from .cert_models import RootCert
from .subject import Subject
import os


class RootCertificateGenerator(CertificateGenerator):
    def generate_root_certificate(
        self,
        subject: Subject,
        key_name: str,
        cert_name: str = "root_ca_cert",
        valid_after: int = 3650,
    ) -> str:

        # Generate the private key for the root certificate
        key_path = os.path.join(self.output_dir, f"{key_name}.key")

        # Load the private key for signing
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        # Set certificate attributes
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject.get("country_name")),
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
                x509.NameAttribute(NameOID.COMMON_NAME, subject.get("common_name")),
            ]
        )

        # Create a self-signed certificate
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(
                datetime.now() + timedelta(days=valid_after)
            )  # 10 years validity
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )

        # Save the certificate
        cert_path = os.path.join(self.output_dir, f"{cert_name}.pem")
        fd = os.open(
            cert_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )  # Open with 600 permissions
        with os.fdopen(fd, "wb") as cert_file:
            cert_file.write(root_cert.public_bytes(encoding=serialization.Encoding.PEM))

        return cert_path

    def generate_certificate(
        self,
        subject: Subject,
        key_name: str = "root_ca",
        cert_name: str = "root_ca_cert",
        valid_after: int = 3650,
    ):
        key_path = self.create_private_key(key_name)
        cert_path = self.generate_root_certificate(
            subject, key_name, cert_name, valid_after
        )

        return RootCert(cert_path, key_path)
