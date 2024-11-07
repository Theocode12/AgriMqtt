
---

# MQTT Client with Certificate-based Authentication

This project provides tools to generate self-signed certificates, client certificates, and root certificates for secure MQTT communication. It includes functionalities to:

- Generate root and client certificates.
- Sign client certificate requests (CSRs) with a Certificate Authority (CA).
- Establish secure MQTT connections using these certificates.

## Requirements

Ensure you have the following dependencies installed:

```bash
pip install cryptography paho-mqtt
```

## Directory Structure

```plaintext
.
├── src/
│   ├── certificates/
│   │   ├── CertificateAuthority.py
│   │   ├── ClientCertificateGenerator.py
│   │   ├── RootCertificateGenerator.py
│   │   └── Subject.py
│   ├── mqtt/
│   │   └── MQTTClient.py
├── root_cert/                # Stores root certificates and keys
└── backend_certs/            # Stores generated client certificates and keys
```

## Usage

### 1. **Generate Root Certificate**  
To create a self-signed root certificate:

```python
from src.certificates import Subject, RootCertificateGenerator

subject = Subject(common_name="MyRootCA", country_name="US", organization_name="MyOrg")
root_gen = RootCertificateGenerator(output_dir="root_cert")
root_gen.generate_certificate(subject)
```

This will generate a root certificate (`root_ca_cert.pem`) and a private key (`root_ca.key`) in the `root_cert` directory.

### 2. **Generate Client Certificate and CSR**  
To create a client certificate and sign it using the root CA:

```python
from src.certificates import Subject, CertificateAuthority, ClientCertificateGenerator

# Define the client subject (common_name could be the name of your client)
subject = Subject(common_name="Client1", country_name="US", organization_name="MyOrg")

# Load the root CA
ca = CertificateAuthority(cert_path="root_cert/root_ca_cert.pem", key_path="root_cert/root_ca.key")

# Generate client certificate signed by the root CA
client_cert_gen = ClientCertificateGenerator(output_dir="backend_certs")
client_cert = client_cert_gen.generate_signed_certificate(subject, ca, "client1", "client1_cert")
```

This will generate a private key (`client1.key`), a certificate signing request (`client1_csr.pem`), and a signed certificate (`client1_cert.pem`) in the `backend_certs` directory.

### 3. **Set Up MQTT Client with Secure TLS Connection**

To connect to an MQTT broker securely using the client certificate:

```python
from src.certificates import ClientCert
from src.mqtt import MQTTClient

# Initialize client certificate
client_cert = ClientCert(
    cert_path="backend_certs/client1_cert.pem",
    key_path="backend_certs/client1.key",
    ca_cert_path="root_cert/root_ca_cert.pem"
)

# Set up the MQTT client
client = MQTTClient(cert=client_cert, client_id="Client1", broker="mqtt-broker.com")

# Connect to the broker
client.connect()

# Define callback function for subscribing to a topic
def save_data_to_db():
    pass

# Subscribe to a topic
client.subscribe("test/data", save_data_to_db)

# Start the MQTT loop to keep the client connected
client.loop_forever()
```

This code connects to an MQTT broker at `mqtt-broker.com`, subscribes to the `test/data` topic, and listens for messages. The `save_data_to_db()` function will handle the incoming messages.

---

## Key Classes and Methods

### `CertificateAuthority`
- **Methods:**
  - `sign_csr(csr_path, signed_cert_path, valid_after)`: Signs a client CSR and generates a signed certificate.
  - `get_cert()`: Returns the CA certificate path.

### `CertificateGenerator`
- **Methods:**
  - `create_private_key(key_name, key_size)`: Generates an RSA private key and saves it to a file.
  - `generate_certificate(subject, key_path)`: Abstract method to generate a certificate (implemented in subclasses).

### `RootCertificateGenerator`
- **Methods:**
  - `generate_root_certificate(subject, key_name, cert_name, valid_after)`: Generates a self-signed root certificate.

### `ClientCertificateGenerator`
- **Methods:**
  - `create_csr(subject, key_name, key_path)`: Creates a CSR for the client.
  - `get_signed_csr(ca, csr_path, signed_cert_name)`: Sends the CSR to the CA for signing.
  - `generate_signed_certificate(subject, ca, key_name, cert_name)`: Generates a signed client certificate.

### `MQTTClient`
- **Methods:**
  - `connect()`: Connects to the MQTT broker using SSL/TLS.
  - `subscribe(topic, on_message_callback)`: Subscribes to a topic and sets the callback for incoming messages.
  - `publish(topic, payload)`: Publishes a message to a topic.
  - `loop_forever()`: Starts a blocking loop to process incoming messages.

---

## Notes

- Ensure the paths to certificates and keys are correctly specified.
- MQTT communication is secured using TLS with certificates for both the client and the server.
- This project assumes you have an MQTT broker running and accessible for testing.


---

### **Integrating MQTT Client with Django**

Once you've set up the MQTT client code and ensured it runs asynchronously in the background, it's time to integrate it into your Django application.

#### **1. Create an AppConfig to Initialize MQTT Client**

To run the MQTT client automatically when the Django app starts, we’ll use Django's `AppConfig`. This will ensure that the MQTT client is initialized during the Django application startup.

In your app's `apps.py`, ensure the MQTT client starts by placing it inside the `ready` method.

**`yourapp/apps.py`**:

```python
import asyncio
from django.apps import AppConfig
from src.certificates import ClientCert
from src.mqtt import MQTTClient

class YourAppConfig(AppConfig):
    name = 'yourapp'  # Your app name
    verbose_name = 'Your App'

    def ready(self):
        # Ensure the MQTT client starts in the background when the app is ready
        asyncio.get_event_loop().create_task(self.start_mqtt_client())

    async def start_mqtt_client(self):
        """
        Starts the MQTT client in an asynchronous manner.
        """
        # Initialize your client certificate
        client_cert = ClientCert(
            "./backend_certs/backend_cert.pem",
            "./backend_certs/backend.key",
            "./backend_certs/root_ca_cert.pem"
        )

        # Initialize MQTT Client
        mqtt_client = MQTTClient(client_cert, "Test", "132.23.21.33")

        # Connect the client
        mqtt_client.connect()

        # Define your callback function to process messages
        def save_data_to_db(client, userdata, message):
            # Logic to save or process the received message
            pass

        # Subscribe to a topic and attach the callback function
        mqtt_client.subscribe("test/data", save_data_to_db)

        # Start the loop in the background
        await asyncio.to_thread(mqtt_client.loop_forever)
```

#### **2. Add AppConfig to `INSTALLED_APPS`**

Make sure that the `YourAppConfig` class is used to configure your Django app. Update the `INSTALLED_APPS` setting to use the full path to the `AppConfig` class.

**`settings.py`**:

```python
INSTALLED_APPS = [
    # Other apps...
    'yourapp.apps.YourAppConfig',  # Add this line to use the custom AppConfig
]
```

This ensures that the MQTT client will start when the Django app is initialized.

#### **3. Running the Application**

Now, when you start your Django application, the MQTT client will be initialized in the background and ready to process messages.

To run the app:

```bash
python manage.py runserver
```

The MQTT client will automatically start in the background as soon as the app is ready.

#### **4. Handling Long-Running Tasks**

Since the MQTT client runs asynchronously in the background, it will not block the main Django application, allowing your server to handle incoming requests while also listening to the MQTT broker. However, be mindful that the MQTT client’s loop will run indefinitely until the application stops.

---

This concludes the basic integration of the MQTT client into your Django project. The key is using Django’s `AppConfig` to trigger the asynchronous MQTT connection setup, and the client will operate in the background throughout the lifetime of the Django app.