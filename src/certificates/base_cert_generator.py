from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from .subject import Subject
import os


class CertificateGenerator(ABC):
    def __init__(self, output_dir: str = "./certs"):
        """
        Initialize with a directory where certificates and keys will be stored.
        """
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def create_private_key(self, key_name: str, key_size: int = 2048) -> str:
        """
        Generates an RSA private key and saves it as a PEM file in the specified directory.

        Parameters:
            key_name (str): The name for the private key file.
            key_size (int): The size of the RSA key in bits. Default is 2048.

        Returns:
            str: Path to the saved private key file.
        """
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Define the path for the private key file
        key_path = os.path.join(self.output_dir, f"{key_name}.key")

        fd = os.open(
            key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )  # Open with 600 permissions
        with os.fdopen(fd, "wb") as key_file:
            # Write the private key to a file in PEM format
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),  # No password
                )
            )

        return key_path

    @abstractmethod
    def generate_certificate(self, subject: Subject, key_path: str):
        """
        Abstract method for generating a certificate.
        Must be implemented by subclasses.

        Parameters:
            key_path (str): Path to the private key file to use for signing.
        """
        pass
