import re
import string
import hashlib
import getpass
import bcrypt
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from colorama import Fore, Style
import cryptography.x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import utils, rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend



def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# Saisi et vérification de l'adresse mail lors de l'inscription
def verif_mail():
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Za-z]{2,})+')
    while True:
        email = input("Veuillez indiquer votre adresse mail: ")
        if re.fullmatch(regex, email):
            print("\033[1;32;40m" + "Adresse e-mail valide." + "\033[0m")
            return email.lower()  # Retourner l'e-mail en minuscules s'il est valide
        else:
            print("\033[1;31;40m" + "Adresse e-mail invalide." + "\033[0m")

# Saisi et vérification de mot de passe lors de l'inscription
def introduire_pwd():
    while True:
        p = getpass.getpass(prompt="Veuillez indiquer votre Mot de passe")
# 8 caractères avec au moins un caractère minuscule, un caractère majuscule, un chiffre et un caractère spécial: ")
        if len(p) == 8:
            if any(car in string.digits for car in p):
                if any(car in string.ascii_uppercase for car in p):
                    if any(car in string.ascii_lowercase for car in p):
                        if any(car in string.punctuation for car in p):
                            p = hashlib.sha256(p.encode()).hexdigest()
                            return p
                        else:
                            print("\033[1;31;40m" + "Au moins un caractère spécial est requis." + "\033[0m")
                    else:
                        print("\033[1;31;40m" + "Au moins une lettre minuscule est requise." + "\033[0m")
                else:
                    print("\033[1;31;40m" + "Au moins une lettre majuscule est requise." + "\033[0m")
            else:
                print("\033[1;31;40m" + "Au moins un chiffre est requis." + "\033[0m")
        else:
            print("\033[1;31;40m" + "Le mot de passe doit contenir exactement 8 caractères." + "\033[0m")

# Vérifier si l'utilisateur existe déjà dans le fichier Enregistrement.txt ou non
def check_if_email_exists(email, file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            if email in line:
                return True
        return False

# Ajouter un nouvel utilisateur dans le fichier Enregistrement.txt
def ajout_user(email, pwd):
    email = email.lower()  # Convertir l'adresse e-mail en minuscules
    if check_if_email_exists(email, "Enregistrement.txt"):
        print("\033[1;31;40m" + "L'utilisateur existe déjà, veuillez vous authentifier." + "\033[0m")

    else:
        clear_console()
        with open("Enregistrement.txt", "a") as file:
            file.write(f"{email}:{pwd}\n")
            print("\033[1;32;40m" + "Utilisateur créé avec succès, vous pouvez vous connecter à présent." + "\033[0m")
            print("\n \n \n")
# Fonction principale d'enregistrement
def Enregistrement():
    email = verif_mail()
    pwd = introduire_pwd()
    ajout_user(email, pwd)



def Authentification(essais=0):
    MAX_ESSAIS = 3
    if essais >= MAX_ESSAIS:
        print("\033[1;31;40m" + "Trop de mauvais mots de passe. Au revoir !" + "\033[0m")
        return

    email = verif_mail()
    pwd = introduire_pwd()
    email = email.lower()
    with open("Enregistrement.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            if f"{email}:{pwd}\n" == line:
                print("\033[1;32;40m" + f"Bienvenue, {email} !" + "\033[0m")
                menu_principal()
                return
        print("\033[1;31;40m" + "Veuillez vérifier votre adresse mail ou mot de passe." + "\033[0m")
        Authentification(essais + 1)

def mot_hach() :
    mot = getpass.getpass("Veuillez saisir le mot à hasher: \n")
    return mot

def hash_sha256(mot) :
    mot_hashe=hashlib.sha256(mot.encode()).hexdigest()
    print("\033[1;32;40m" + "Le haché avec sha256 est : " + mot_hashe + "\033[0m")
    print("\n \n \n")
    return hashlib.sha256(mot.encode()).hexdigest()

def hash_salt(mot):
    # Générer un salt
    salt = bcrypt.gensalt()
    # Hacher le mot de passe en utilisant le salt
    mot_hache = bcrypt.hashpw(mot.encode('utf-8'), salt)
    print("\033[1;32;40m" + "Le haché avec salt est: " + mot_hache.decode('utf-8') + "\033[0m")
    print("\n \n \n")

def load_dictionary(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

DICTIONARY_FILE_PATH = 'dic.txt'

def attaque_dec(mot_attaque):
    dictionary = load_dictionary(DICTIONARY_FILE_PATH)
    for mot in dictionary:
        if hashlib.sha256(mot.lower().encode()).hexdigest() == mot_attaque :
            print("\033[1;32;40m" + "Votre secret a été trouvé, votre mot est:" + mot + "\033[0m")
            print("\n \n \n")
            return True
    
    print("\033[1;31;40m" + "Votre secret n'a pas été trouvé" + "\033[0m")
    print("\n \n \n")



# Génération d'une clé RSA
def generer_cle_rsa():
    # Utilisation du backend par défaut
    backend = default_backend()

    # Générer une clé RSA avec une taille de 2048 bits
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend
    )

    # Obtenir la clé publique correspondante
    cle_publique = cle_privee.public_key()

    # Sérialiser la clé privée au format PEM
    pem_cle_privee = cle_privee.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Sérialiser la clé publique au format PEM
    pem_cle_publique = cle_publique.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Enregistrer la clé privée dans un fichier
    with open("cle_privee.pem", "wb") as fichier_cle_privee:
        fichier_cle_privee.write(pem_cle_privee)

    with open("cle_publique.pem", "wb") as fichier_cle_publique:
        fichier_cle_publique.write(pem_cle_publique)

    print("\033[1;32;40m" + "clés générés" + "\033[0m")
    print("\n \n \n")

# Chiffrer un message avec la clé publique RSA
def chiffrer_message_rsa( cle_publique):
    message=input("Donnez le message à chiffrer avec la clé publique\n")
    cle_publique = serialization.load_pem_public_key(cle_publique, backend=default_backend())
    message = message.encode('utf-8')

    # Utilisation du padding OAEP pour le chiffrement
    message_chiffre = cle_publique.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("\033[1;32;40m" +"Voici le message chiffré: \n" + message_chiffre.hex() + "\033[0m")
    print("\n \n \n")

    return message_chiffre

# Déchiffrer un message avec la clé privée RSA
def dechiffrer_message_rsa(cle_privee, message_chiffre):
    with open(cle_privee, "rb") as fichier_cle_privee:
        cle_privee = serialization.load_pem_private_key(
            fichier_cle_privee.read(),
            password=None,
            backend=default_backend()
        )

    # Utilisation du padding OAEP pour le déchiffrement
    message_dechiffre = cle_privee.decrypt(
        message_chiffre,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("\033[1;32;40m" + "Message déchiffré:\n" + message_dechiffre.decode('utf-8') + "\033[0m")
    print("\n \n \n")

def sign_message(private_key_file, message):
    with open(private_key_file, 'r') as key_file:
        private_key = RSA.import_key(key_file.read())
        hash = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hash)
        print("\033[92m" +"Voici le message après signature:\n"+ str(signature) + "\033[0m")  # Impression en vert
        print("\n \n \n")
        return signature

def verify_signature(public_key_file, message, signature):
    with open(public_key_file, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
        hash = SHA256.new(message)
        try:
            pkcs1_15.new(public_key).verify(hash, signature)
            print("\033[1;32;40m" + "Signature valide" + "\033[0m")
            print("\n \n \n")
        except (ValueError, TypeError):
            print("\033[1;31;40m" + "Signature non valide" + "\033[0m")
            print("\n \n \n")


# Générer un certificat autosigné par RSA
def generate_self_signed_certificate():
    backend = default_backend()
    subject = issuer = cryptography.x509.Name([cryptography.x509.NameAttribute(cryptography.x509.NameOID.COMMON_NAME, u"MyCN")])
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    cert = cryptography.x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()).serial_number(cryptography.x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=10)).sign(private_key, hashes.SHA256(), backend=backend)
    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("\033[1;32;40m" + "Le certificat a été généré" + "\033[0m")
    print("\n \n \n")
# Chiffrer un message avec le certificat autosigné
def encrypt_message_with_certificate(cert_file, message):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate

    # Load the public key from the certificate
    with open(cert_file, "rb") as f:
        cert_data = f.read()
        cert_obj = load_pem_x509_certificate(cert_data, default_backend())
        public_key = cert_obj.public_key()

    # Encrypt the message using the public key
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("\033[92m" + "Voici le message chiffré par le certificat:\n" +str(encrypted_message) + "\033[0m")  # Impression en vert
    return encrypted_message


######Les menus#####
def print_menu_title(title):
    print(f"{Style.BRIGHT}{Fore.CYAN}{title}{Style.RESET_ALL}")

def print_menu_options(options):
    for idx, option in enumerate(options, start=1):
        print(f"{Fore.GREEN}{idx}{Style.RESET_ALL}-{option}")

def print_menu_options_lettre(options):
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    for idx, option in enumerate(options):
        print(f"{Fore.GREEN}{letters[idx]}{Style.RESET_ALL}-{option}")
##menu d'accueil
def menu_accueil():
    print_menu_title("MENU d'accueil")
    print_menu_options(["Enregistrement", "Authentification", "Quitter"])
    choix = input("Choix: ")

    if choix == '1':
        Enregistrement()
        menu_accueil()
    elif choix == '2':
        Authentification()
    elif choix == '3':
        print("Merci pour votre visite")
        return
    else:
        print(f"{Fore.RED}Veuillez choisir entre 1-Enregistrement, 2-Authentification ou 3-pour quitter{Style.RESET_ALL}")
        menu_accueil()

# Fonction de menu certificat
def menu_certificat():
    print_menu_title("MENU CERTIFICAT")
    print_menu_options_lettre(["Générer les paires de clés dans un fichier",
                        "Générer un certificat autosigné par RSA",
                        "Chiffrer un message de votre choix par ce certificat",
                        "Revenir au menu principal"])
    choix_certificat = input("Choix: ")

    if choix_certificat.lower() == 'a':
        clear_console()
        generer_cle_rsa()
        menu_certificat()
    elif choix_certificat.lower() == 'b':
        clear_console()
        generate_self_signed_certificate()
        menu_certificat()
    elif choix_certificat.lower() == 'c':
        clear_console()
        message = input("Veuillez donner le message à chiffrer par le certificat\n")
        encrypt_message_with_certificate('certificate.pem',message)
        menu_certificat()
    elif choix_certificat.lower() == 'd':
        clear_console()
        menu_principal()
        return
    else:
        clear_console()
        print(f"{Fore.RED}Veuillez vérifier votre choix{Style.RESET_ALL}")
        menu_certificat()



# Fonction de menu après authentification
def menu_principal():
    clear_console()
    print_menu_title("MENU PRINCIPAL")
    print_menu_options_lettre(["Donnez un mot à hacher (en mode invisible)",
                        "Chiffrement (RSA)",
                        "Certificat (RSA)",
                        "Revenir au menu d'accueil"])
    choix_after_authentification = input("Choix: ")

    if choix_after_authentification.lower() == 'a':
        clear_console()
        mot = mot_hach()
        menu_hash(mot)
    elif choix_after_authentification.lower() == 'b':
        clear_console()
        menu_chiffrement()
    elif choix_after_authentification.lower() == 'c':
        clear_console()
        menu_certificat()
    elif choix_after_authentification.lower() == 'd':
        clear_console()
        menu_accueil()
        return
    else:
        print(f"{Fore.RED}Veuillez vérifier votre choix{Style.RESET_ALL}")
        menu_principal()
# Fonction de menu pour hachage
def menu_hash(mot,mot_attaque=None):
#    global mot_attaque
    print_menu_title("MENU DE HACHAGE")
    print_menu_options_lettre(["Hacher le mot par sha256",
                        "Hacher le mot en générant un salt (bcrypt)",
                        "Attaquer par dictionnaire le mot inséré",
                        "Revenir au menu principal"])
    choix_hash = input("Choix: ")
    mot_attaque=mot_attaque
    if choix_hash.lower() == 'a':
        clear_console()
        mot_attaque = hash_sha256(mot)
        menu_hash(mot,mot_attaque)
    elif choix_hash.lower() == 'b':
        clear_console()
        hash_salt(mot)
        menu_hash(mot,mot_attaque)
    elif choix_hash.lower() == 'c':
        clear_console()
        if not mot_attaque:   # Vérifier si mot_attaque est vide
            print("\033[1;31;40m" + "Veuillez hasher le mot avec sha256 avant" + "\033[0m")
            print("\n \n \n")
        else:
            attaque_dec(mot_attaque)  # exécuter attaque_dec(mot_attaque) si mot_attaque n'est pas vide
        menu_hash(mot,mot_attaque)
    elif choix_hash.lower() == 'd':
        clear_console()
        menu_principal()
        return
    else:
        print(f"{Fore.RED}Veuillez vérifier votre choix{Style.RESET_ALL}")
        menu_hash(mot)

# Fonction de menu pour chiffrement
def menu_chiffrement():
    global message_chiffre
    global signature
    global message_sign
    print_menu_title("MENU DE CHIFFREMENT")
    print_menu_options_lettre(["Générer les paires de clés dans un fichier",
                        "Chiffrer un message de votre choix par RSA",
                        "Déchiffrer le message",
                        "Signer un message de votre choix par RSA",
                        "Vérifier la signature du message",
                        "Revenir au menu principal"])
    choix_chiffrement = input("Choix: ")

    if choix_chiffrement.lower() == 'a':
        clear_console()
        generer_cle_rsa()
        menu_chiffrement()
        return
    elif choix_chiffrement.lower() == 'b':
        clear_console()
        with open("cle_publique.pem", "rb") as fichier_cle_publique:
            cle_publique = fichier_cle_publique.read()
        message_chiffre = chiffrer_message_rsa(cle_publique)
        menu_chiffrement()
        return
    elif choix_chiffrement.lower() == 'c':
        clear_console()
        dechiffrer_message_rsa("cle_privee.pem", message_chiffre)
        menu_chiffrement()
        return
    elif choix_chiffrement.lower() == 'd':
        clear_console()
        message_sign = input("Veuillez donner le texte à signer\n")
        signature = sign_message("cle_privee.pem", message_sign)
        menu_chiffrement()
        return
    elif choix_chiffrement.lower() == 'e':
        clear_console()
        verify_signature("cle_publique.pem", message_sign.encode('utf-8'), signature)
        menu_chiffrement()
        return
    elif choix_chiffrement.lower() == 'f':
        menu_principal()
        clear_console()
    else:
        clear_console()
        print(f"{Fore.RED}Veuillez vérifier votre choix{Style.RESET_ALL}")
        menu_chiffrement()

#code principal
menu_accueil()
