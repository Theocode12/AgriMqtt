from paho.mqtt import client as mqtt
from certificates import ClientCert


# --- MQTTClient Class (Handles MQTT operations) ---
class MQTTClient:
    def __init__(
        self,
        cert: ClientCert,
        broker: str,
        port: int,
        client_id: str,
    ):
        """
        Initializes an MQTT client with secure connection settings.
        """
        self.client = mqtt.Client(client_id=client_id)
        # Set SSL/TLS configuration
        self.client.tls_set(cert.CERT_PATH, cert.KEY_PATH, cert.CA_CERT_PATH)

        self.broker = broker
        self.port = port

    def connect(self):
        """
        Establishes a connection to the MQTT broker.
        """
        try:
            self.client.connect(self.broker, self.port)
            print("MQTT Client connected successfully.")
        except Exception as e:
            print(f"Failed to connect to MQTT broker: {e}")

    def subscribe(self, topic: str, on_message_callback):
        """
        Subscribes to a specified MQTT topic and sets a callback for received messages.
        """
        self.client.subscribe(topic)
        self.client.on_message = on_message_callback
        print(f"Subscribed to topic: {topic}")

    def publish(self, topic: str, payload: str):
        """
        Publishes a message to a specified MQTT topic.
        """
        self.client.publish(topic, payload)
        print(f"Published message to {topic}: {payload}")

    def loop_forever(self):
        """
        Runs a blocking loop to maintain the connection and receive messages.
        """
        self.client.loop_forever()
