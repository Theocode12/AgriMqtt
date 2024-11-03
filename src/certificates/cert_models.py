from abc import ABC


class Cert(ABC):
    def __init__(self, cert_file, key_file) -> None:
        self.CERT_PATH = cert_file  # X.509
        self.KEY_PATH = key_file  # private_key


class ClientCert(Cert):
    def __init__(
        self, cert_path=None, key_path=None, ca_cert_path=None, csr_path=None
    ) -> None:
        self.CA_CERT_PATH = ca_cert_path
        self.CSR_PATH = csr_path
        super().__init__(cert_path, key_path)


class RootCert(Cert):
    def __init__(self, cert_path=None, key_path=None) -> None:
        super().__init__(cert_path, key_path)
