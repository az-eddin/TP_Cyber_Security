"""
FernetGUI.py 
Fait par :  Az-eddine ABOUHAFS
5A IOT - POLYTECH ORLEANS

Ce code implémente une interface graphique pour une application de chat sécurisée utilisant le chiffrement Fernet (basé sur AES). 
L'utilisateur se connecte au serveur en fournissant un hôte, un port, un nom et un mot de passe. 
Le mot de passe est converti en une clé Fernet pour chiffrer les messages envoyés et déchiffrer ceux reçus. 
Les messages sont envoyés et reçus via un serveur de chat sécurisé, et affichés dans l'interface graphique.
"""
import hashlib
import logging
import base64
import dearpygui.dearpygui as dpg

from cryptography.fernet import Fernet
from chat_client import ChatClient, GenericCallback
from CipheredGUI import CipheredGUI  # on importe la classe CipheredGUI

# Valeurs par défaut pour la connexion
DEFAULT_VALUES = {
    "host" : "127.0.0.1",  # Adresse locale
    "port" : "6666",  # Port par défaut
    "name" : "az-eddine"  # Nom par défaut
}

# Classe FernetGUI hérite de CipheredGUI
class FernetGUI(CipheredGUI):
    def __init__(self):
        super().__init__()  # Appel au constructeur parent
        self._key = None  # Clé pour le chiffrement
        self._fernet_key = None  # Clé Fernet utilisée pour chiffrer les messages
        self._salt = b''  # Pas de sel utilisé ici

    def _create_connection_window(self):  # Création de la fenêtre de connexion
        # Fenêtre pour se connecter avec hôte, port, nom et mot de passe
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            fields = ["host", "port", "name", "password"]  # Champs nécessaires pour la connexion
            for field in fields:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)  # Affiche le texte pour chaque champ
                    if field == "password":
                        dpg.add_input_text(password=True, tag="mdp")  # Champ pour le mot de passe
                    else:
                        dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")  # Champs pour hôte, port, nom
            dpg.add_button(label="Connexion", callback=self.run_chat)  # Bouton de connexion

    def run_chat(self, sender, app_data):
        # Récupère les valeurs saisies pour hôte, port, nom, et mot de passe
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("password")
        self._log.info(f"Connecting {name}@{host}:{port}")

        # Création d'une clé à partir du mot de passe via SHA-256
        self._key = hashlib.sha256(password.encode()).digest()
        self._fernet_key = base64.urlsafe_b64encode(self._key)  # Clé Fernet basée sur la clé dérivée
        self._callback = GenericCallback()  # Callback pour gérer les messages reçus
        self._client = ChatClient(host, port)  # Initialisation du client de chat
        self._client.start(self._callback)  # Démarre le client
        self._client.register(name)  # Enregistre l'utilisateur sur le serveur

        dpg.hide_item("connection_windows")  # Cache la fenêtre de connexion
        dpg.show_item("chat_windows")  # Affiche la fenêtre de chat
        dpg.set_value("screen", "Connecting")  # Affiche un message de connexion

    def encrypt(self, message_to_encrypt: str) -> str:
        # Chiffrement du message avec la clé Fernet
        cipher = Fernet(self._fernet_key)
        encrypted_message = (cipher.encrypt(message_to_encrypt.encode('utf-8'))).decode('utf-8') 
        return encrypted_message  # Retourne le message chiffré

    def decrypt(self, message_to_decrypt: str) -> str:
        # Déchiffrement du message avec la clé Fernet
        cipher = Fernet(self._fernet_key)
        decrypted_message = (cipher.decrypt(message_to_decrypt.encode('utf-8'))).decode('utf-8')
        return decrypted_message  # Retourne le message déchiffré

    def send(self, message_to_send: str) -> None:
        # Chiffre le message avant de l'envoyer
        encrypted_message = self.encrypt(message_to_send) 
        message_encrypted = {"message": encrypted_message}  # Message chiffré dans un dictionnaire
        self._client.send_message(message_encrypted)  # Envoie le message au serveur

    def recv(self) -> None:
        # Vérifie s'il y a des messages à recevoir
        if self._callback is not None:
            for user, data_encrypted in self._callback.get():
                self._log.debug(f"Data received: {data_encrypted}")

                if isinstance(data_encrypted, dict) and 'message' in data_encrypted:
                    # Déchiffre le message reçu
                    encrypted_message = data_encrypted['message']
                    decrypted_message = self.decrypt(encrypted_message) 
                    self.update_text_screen(f"{user}: {decrypted_message}")  # Affiche le message déchiffré
                else:
                    self._log.error("ERROR")
                    continue  # Passe à l'itération suivante en cas d'erreur
            self._callback.clear()  # Vide le callback après traitement des messages

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Configuration du logging pour déboguer
    client = FernetGUI()  # Crée une instance de l'interface graphique Fernet
    client.create()  # Initialisation de l'interface
    client.loop()  # Lancement de la boucle principale de l'application
