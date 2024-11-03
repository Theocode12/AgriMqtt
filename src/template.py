import ssl
import os
from paho.mqtt import client as mqtt


# --- Example Usage ---
if __name__ == "__main__":
    # Example parameters (use actual paths and values)
    CERT_PATH = "/path/to/cert.pem"
    KEY_PATH = "/path/to/private.key"
    BROKER = "mqtt.example.com"
    PORT = 8883
    CLIENT_ID = "client_id"

    # Instantiate the facade
    facade = MQTTFacade(
        cert_path=CERT_PATH,
        key_path=KEY_PATH,
        broker=BROKER,
        port=PORT,
        client_id=CLIENT_ID,
    )

    # Define a simple callback for received messages
    def on_message(client, userdata, message):
        print(f"Received message on {message.topic}: {message.payload.decode()}")

    # Connect, subscribe, and start listening
    facade.connect_and_subscribe(topic="sensor/data", on_message_callback=on_message)

    # Publishing example (for testing)
    facade.publish_message(topic="sensor/data", message="Test message")
