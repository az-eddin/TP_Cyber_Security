"""
CipheredGUI.py 
Fait par :  Az-eddine ABOUHAFS
5A IOT - POLYTECH ORLEANS

Ce code implémente une application de chat sécurisée avec une interface graphique. 
Les utilisateurs se connectent à un serveur de chat, et leurs messages sont chiffrés avec AES en mode CTR avant d'être envoyés. 
Les messages reçus sont également déchiffrés et affichés dans l'interface. 
Le chiffrement utilise une clé dérivée du mot de passe de l'utilisateur pour assurer la sécurité des échanges.

"""

# Importation des bibliothèques nécessaires pour le chiffrement, GUI, et la gestion du chat
import os
import base64
import logging
import dearpygui.dearpygui as dpg

from chat_client import ChatClient  # Import du client de chat
from generic_callback import GenericCallback  # Callback pour la gestion des événements
from basic_gui import BasicGUI, DEFAULT_VALUES  # GUI de base et valeurs par défaut
from cryptography.hazmat.primitives import hashes, padding  # Fonctions cryptographiques
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Dérivation de clé (KDF)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Chiffrement AES
from cryptography.hazmat.backends import default_backend  # Backend pour la cryptographie

# Définition des constantes pour la taille des clés et le sel
TAILLE_CLE = 16  # Taille de la clé AES en bytes
NB_ITERATIONS = 1500  # Nombre d'itérations pour la dérivation de la clé
SEL_PERSONNALISE = b"mon_sel_unique"  # Sel personnalisé pour la dérivation de clé
TAILLE_BLOC_AES = 128  # Taille du bloc pour le padding AES

class CipheredGUI(BasicGUI):
    def __init__(self) -> None:
        super().__init__()  # Appel du constructeur de la classe parent BasicGUI
        self._key = None  # Variable pour stocker la clé dérivée

    def _create_connection_window(self) -> None:
        # Création de la fenêtre de connexion avec les champs hôte, port, nom, et mot de passe
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)  # Ajoute le texte pour le champ
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")  # Ajoute un champ de saisie pour chaque donnée
            with dpg.group(horizontal=True):
                dpg.add_text("password")  # Ajoute le texte pour le champ mot de passe
                dpg.add_input_text(default_value="", tag="connection_password", password=True)  # Champ de saisie pour le mot de passe
            dpg.add_button(label="Connect", callback=self.run_chat)  # Bouton pour lancer la connexion

    def run_chat(self, sender, app_data) -> None:
        # Récupération des valeurs d'hôte, port, nom, et mot de passe depuis l'interface
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._log.info(f"Connecting {name}@{host}:{port}")

        # Utilisation de PBKDF2 pour dériver une clé à partir du mot de passe et du sel
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Algorithme de hachage SHA-256
            length=TAILLE_CLE,  # Longueur de la clé dérivée
            salt=SEL_PERSONNALISE,  # Utilisation du sel personnalisé
            iterations=NB_ITERATIONS,  # Nombre d'itérations pour sécuriser la dérivation
            backend=default_backend()  # Backend utilisé pour les fonctions cryptographiques
        )

        # Dérivation de la clé à partir du mot de passe
        self._key = kdf.derive(bytes(password, "utf8"))

        # Initialisation du client de chat et démarrage de la communication
        self._callback = GenericCallback()
        self._client = ChatClient(host, port)
        self._client.start(self._callback)  # Démarrage du client avec callback
        self._client.register(name)  # Enregistrement du nom d'utilisateur

        # Affichage de l'interface du chat
        dpg.hide_item("connection_windows")  # Cache la fenêtre de connexion
        dpg.show_item("chat_windows")  # Affiche la fenêtre de chat
        dpg.set_value("screen", "Connecting...")  # Message indiquant la connexion en cours

    # Fonction pour chiffrer les messages avant de les envoyer
    def encrypt(self, message):
        iv = os.urandom(16)  # Génère un IV aléatoire pour chaque message
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv))  # AES avec mode CTR
        encryptor = cipher.encryptor()  # Création de l'objet pour chiffrer

        # Application du padding PKCS7 pour ajuster la taille du message
        padder = padding.PKCS7(TAILLE_BLOC_AES).padder()
        padded_message = padder.update(bytes(message, "utf8")) + padder.finalize()

        # Chiffrement du message
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return (iv, encrypted_message)  # Retourne l'IV et le message chiffré

    # Fonction pour déchiffrer les messages reçus
    def decrypt(self, encrypted_message):
        # Extraction de l'IV et des données chiffrées
        iv = base64.b64decode(encrypted_message[0]['data'])
        encrypted_data = base64.b64decode(encrypted_message[1]['data'])

        # Déchiffrement en utilisant AES en mode CTR avec l'IV extrait
        decryptor = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Suppression du padding PKCS7 pour retrouver le message original
        unpadder = padding.PKCS7(TAILLE_BLOC_AES).unpadder()
        message_dechiffre = unpadder.update(decrypted_data) + unpadder.finalize()
        return message_dechiffre.decode("utf8")  # Retourne le message déchiffré

    # Fonction pour envoyer des messages chiffrés
    def send(self, text) -> None:
        # Chiffrement du message avant l'envoi
        encrypted_message = self.encrypt(text)
        # Envoi du message chiffré au serveur
        self._client.send_message(encrypted_message)

    # Fonction pour recevoir et déchiffrer des messages
    def recv(self) -> None:
        # Vérifie s'il y a des messages à recevoir
        if self._callback is not None:
            for user, encrypted_message in self._callback.get():
                # Déchiffre le message reçu
                decrypted_message = self.decrypt(encrypted_message)
                # Affiche le message dans l'interface
                self.update_text_screen(f"{user}: {decrypted_message}")
            self._callback.clear()

if __name__ == "__main__":
    # Initialisation du logging pour le débogage
    logging.basicConfig(level=logging.DEBUG)
    client = CipheredGUI()  # Création d'une instance de CipheredGUI
    client.create()  # Initialisation de l'interface graphique
    client.loop()  # Boucle principale de l'application
