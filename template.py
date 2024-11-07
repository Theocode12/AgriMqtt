



# --- Example Usage ---
if __name__ == "__main__":
    from src.certificates import CertificateAuthority
    from src.certificates import ClientCertificateGenerator
    from src.certificates import RootCertificateGenerator
    from src.certificates import Subject
    from src.certificates import ClientCert
    from src.mqtt import MQTTClient

    """ Defines the subject parameters that will be used to create certificates.
    The common name parameter might change depending on who wants to create a certificate.
    It could be clients(backend and users) or it could be the root ca. 
    """
    # subject = Subject('AgriOk-Backend')
    
    """Generation of the root certificate"""
    # RootCertificateGenerator("root_cert").generate_certificate(subject)

    """Defines the Generation of a client signed Certificate"""
    # ca = CertificateAuthority("./root_cert/root_ca_cert.pem", "./root_cert/root_ca.key")
    # ClientCertificateGenerator("backend_certs").generate_signed_certificate(subject, ca, "backend", "backend_cert")

    """Defined how the MqttClient should be used to connect to a broker"""
    def save_data_to_db():
        pass

    client_cert = ClientCert("./backend_certs/backend_cert.pem", "./backend_certs/backend.key", "./backend_certs/root_ca_cert.pem")
    client = MQTTClient(client_cert, "Test",'132.23.21.33')
    client.connect()
    client.subscribe('test/data', save_data_to_db)

