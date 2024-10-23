
"""
TimeFernetGUI.py 
Fait par :  Az-eddine ABOUHAFS
5A IOT - POLYTECH ORLEANS


Ce code implémente une interface graphique pour une application de chat avec un chiffrement Fernet et une durée de validité des messages (TTL). 
Les messages envoyés sont chiffrés avec une clé dérivée d'un mot de passe et leur validité est limitée dans le temps. 
L'interface permet de se connecter à un serveur de chat, d'envoyer et de recevoir des messages chiffrés.
"""

import os
import time
import base64
import dearpygui.dearpygui as dpg
import serpent
import logging
import Pyro5

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from FernetGUI import FernetGUI  # Importation de la classe parente

# Classe qui hérite de FernetGUI pour ajouter une gestion du temps (TTL)
class TimeFernetGUI(FernetGUI):
    def __init__(self):
        super().__init__()  # Appel au constructeur parent
        self.TTL = 30  # Temps de validité du message (en secondes)

    def _create_connection_window(self):
        # Création de la fenêtre de connexion avec hôte, port, nom, et mot de passe
        with dpg.window(label="Connexion", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name", "password"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)  # Affichage des noms de champs
                    if field == "password":
                        dpg.add_input_text(default_value="", tag="mdp", password=True)  # Champ mot de passe masqué
                    else:
                        dpg.add_input_text(default_value=DEFAULT_VALUES.get(field, ""), tag=f"connection_{field}")  # Champs texte standard
            dpg.add_button(label="Connexion", callback=self.run_chat)  # Bouton de connexion

    def run_chat(self, sender, app_data):
        # Récupération des informations saisies (hôte, port, nom, mot de passe)
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("password")

        # Création d'une clé de chiffrement à partir du mot de passe
        key = hashes.Hash(hashes.SHA256())  # Utilisation de SHA-256 pour dériver la clé
        key.update(password.encode())
        key_bytes = key.finalize()
        fernet_key = base64.b64encode(key_bytes)  # Conversion en clé Fernet
        self._fernet = Fernet(fernet_key)
        self._log.debug(f"the key is: {fernet_key.decode()}")  # Log de la clé dérivée
        super().run_chat(sender, app_data)  # Appel à la méthode run_chat de la classe parente

    def encrypt(self, message: str) -> bytes:
        # Chiffrement du message en ajoutant un décalage de temps (pour tester)
        current_time = int(time.time()) - 45  
        encrypted_data = self._fernet.encrypt_at_time(message.encode(), current_time=current_time)
        self._log.debug(f"Message chiffré : {current_time}")
        return encrypted_data  # Renvoie les données chiffrées

    def decrypt(self, encrypted_data: bytes) -> str:
        try:
            # Déchiffrement du message en vérifiant le TTL (validité du message)
            current_time = int(time.time())
            decrypted_data = self._fernet.decrypt_at_time(encrypted_data, ttl=self.TTL, current_time=current_time)
            return decrypted_data.decode()  # Renvoie le message déchiffré
        except InvalidToken as e:
            self._log.error(f"Token is invalid: {str(e)}")  # Si le message a expiré
            return "*** Expiré ***"
        except Exception as e:
            self._log.error(f"Erreur de déchiffrement: {str(e)}")  # Autre erreur de déchiffrement
            return "<déchiffrement échoué>"

    def send(self, text):
        # Chiffre et envoie le message
        if self._fernet is None:
            self._log.error("No key found")  # Si la clé n'a pas été générée
            return
        try:
            encrypted_data = self.encrypt(text)  # Chiffre le message
            serialized_data = base64.b64encode(encrypted_data).decode('utf-8')  # Encodage en base64
            self._client.send_message(serialized_data)  # Envoie le message chiffré
        except Exception as e:
            self._log.error(f"Error : {e}")  # Gestion des erreurs

    def recv(self):
        # Réception et déchiffrement des messages
        if self._callback is not None:
            for user, encrypted_data in self._callback.get():
                try:
                    self._log.debug(f"{user} a envoyé un message.")
                    decoded_data = base64.b64decode(encrypted_data)  # Décodage du message reçu
                    message = self.decrypt(decoded_data)  # Déchiffrement du message
                    self.update_text_screen(f"{user} : {message}")  # Affichage du message
                except Exception as e:
                    self._log.error(f"Échec du traitement du msg de {user} : {e}")  # Erreur lors du traitement
                    self._log.error(f"Donnees reçues : {encrypted_data}")  # Affiche les données reçues
            self._callback.clear()  # Efface le callback après réception

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Configuration du logging
    DEFAULT_VALUES = {
        "host": "127.0.0.1",  # Valeurs par défaut
        "port": "6666",
        "name": "az-eddine",
    }

    client = TimeFernetGUI()  # Création de l'interface TimeFernetGUI
    client.create()  # Création de l'interface graphique
    client.loop()  # Lancement de la boucle principale de l'application
