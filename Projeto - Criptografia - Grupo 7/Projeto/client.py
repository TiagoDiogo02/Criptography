# Cliente.py

import socket
import ssl
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Variáveis globais para as chaves do cliente
client_private_key = None
client_public_key = None

# Função para carregar ou gerar par de chaves RSA para o cliente
def load_or_generate_keys(id_origin):
    private_key_path = f'client_private_key_{id_origin}.pem'
    public_key_path = f'client_public_key_{id_origin}.pem'
    
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        # Carregar as chaves existentes
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        print("🔑 Chaves carregadas do arquivo específico do cliente.")
    else:
        # Gerar novas chaves
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        # Guardar as chaves em arquivos específicos deste cliente
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("🔑 Novas chaves geradas e guardadas para este cliente.")
    
    return private_key, public_key

# Função para criptografar o conteúdo usando AES
def encrypt_content(content):
    key = os.urandom(32)  # Gera uma chave aleatória de 256 bits
    nonce = os.urandom(12)  # Gera um nonce aleatório de 96 bits
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(content.encode()) + encryptor.finalize()
    # Concatenar tag, nonce e conteúdo criptografado e codificar em base64
    return base64.b64encode(encryptor.tag + nonce + encrypted_content).decode('utf-8'), key

# Função para decifrar o conteúdo
def decrypt_content(encrypted_content, key):
    try:
        data = base64.b64decode(encrypted_content)
    except Exception as e:
        print("⚠️ Erro ao decifrar o conteúdo em base64:", e)
        return None
    try:
        tag = data[:16]       
        nonce = data[16:28]   
        encrypted_data = data[28:]  
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        print("⚠️ Erro ao decifrar o conteúdo:", e)
        return None

# Função para criptografar a chave AES com a chave pública do destinatário
def encrypt_key_with_recipient_public_key(key, recipient_public_key):
    encrypted_key = recipient_public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')

# Função para decifrar a chave AES com a chave privada do destinatário
def decrypt_key_with_private_key(encrypted_key):
    global client_private_key
    encrypted_key_bytes = base64.b64decode(encrypted_key)
    key = client_private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return key

# Função para se conectar ao servidor de forma segura (SSL)
def secure_connect():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    
    # Carregar o certificado do servidor como CA confiável
    context.load_verify_locations('server_cert.pem')  
    
    # Exigir a verificação do certificado
    context.verify_mode = ssl.CERT_REQUIRED  
    
    # Definir o nome do host para correspondência com o CN do certificado
    secure_socket = context.wrap_socket(client_socket, server_hostname="192.168.137.1")  
    
    secure_socket.connect(("192.168.137.1", 9999))  
    return secure_socket

# Dicionário para armazenar chaves públicas de outros clientes (cache)
cached_public_keys = {}

def get_public_key(id_requested, token):
    if id_requested in cached_public_keys:
        return cached_public_keys[id_requested]
    
    secure_socket = secure_connect()
    request = {
        "action": "get_public_key",
        "token": token, 
        "id_requested": id_requested
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    
    try:
        response_data = json.loads(response.decode())
    except json.JSONDecodeError:
        print("⚠️ Erro: Resposta inválida do servidor ao obter a chave pública.")
        secure_socket.close()
        return None
    
    secure_socket.close()
    
    if "public_key" in response_data:
        public_key_pem = response_data["public_key"]
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        cached_public_keys[id_requested] = public_key 
        return public_key
    else:
        print("⚠️ Erro ao obter chave pública:", response_data.get("error"))
        return None

def register_client(id_origin):
    global client_private_key, client_public_key
    password = input("🔒 Crie a sua senha: ").strip()
    confirm_password = input("🔒 Confirme a sua senha: ").strip()

    if password != confirm_password:
        print("⚠️ Erro: As senhas não coincidem.")
        return

    secure_socket = secure_connect()
    public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    request = {
        "action": "register",
        "id_origin": id_origin,
        "password": password,
        "public_key": public_key_pem.decode()
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    try:
        response_data = json.loads(response.decode())
        if "error" in response_data:
            print("⚠️ Erro:", response_data.get("error"))
        else:
            print("📬 Resposta do servidor:", response_data.get("status", "Registo bem-sucedido."))
    except json.JSONDecodeError:
        print("📬 Resposta do servidor:", response.decode())
    secure_socket.close()

def login_client(id_origin):
    password = input("🔑 Informe a sua senha: ").strip()
    secure_socket = secure_connect()
    request = {
        "action": "login",
        "id_origin": id_origin,
        "password": password
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    try:
        response_data = json.loads(response.decode())
        if "error" in response_data:
            print("⚠️ Erro:", response_data.get("error"))
            return None
        else:
            print("✅", response_data.get("status", "Login bem-sucedido."))
            return response_data.get("token")
    except json.JSONDecodeError:
        print("⚠️ Erro: Resposta inválida do servidor.")
        return None
    finally:
        secure_socket.close()

def send_message(id_origin, token):
    global client_private_key, client_public_key
    id_destination = input("🔹 Informe o ID do destinatário: ").strip()
    subject = input("📝 Informe o assunto da mensagem: ").strip()
    content = input("📨 Informe o conteúdo da mensagem: ").strip()
    
    if len(subject) > 50:
        print("⚠️ Erro: Assunto excede 50 caracteres.")
        return

    # Obter a chave pública do destinatário, passando o token
    recipient_public_key = get_public_key(id_destination, token)
    if recipient_public_key is None:
        print("⚠️ Erro: Não foi possível obter a chave pública do destinatário.")
        return

    # Criptografar o conteúdo
    encrypted_content, key = encrypt_content(content)  # Criptografa o conteúdo com AES
    # Criptografar a chave AES com a chave pública do destinatário
    encrypted_key = encrypt_key_with_recipient_public_key(key, recipient_public_key)
    
    # Assinar o conteúdo criptografado
    signature = client_private_key.sign(
        encrypted_content.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    encoded_signature = base64.b64encode(signature).decode('utf-8')

    # Logs de depuração
    print("🔐 Conteúdo Criptografado:", encrypted_content)
    print("✍️ Assinatura (base64):", encoded_signature)

    # Preparar a mensagem para enviar
    message = {
        "action": "send",
        "token": token,  
        "id_origin": id_origin,
        "id_destination": id_destination,
        "subject": subject,
        "content": encrypted_content,
        "signature": encoded_signature,
        "key": encrypted_key  # Chave AES criptografada
    }

    # Enviar a mensagem ao servidor
    secure_socket = secure_connect()
    secure_socket.send(json.dumps(message).encode())
    response = secure_socket.recv(4096)
    try:
        response_data = json.loads(response.decode())
        if "error" in response_data:
            print("⚠️ Erro ao enviar mensagem:", response_data["error"])
        else:
            print("✅ Mensagem enviada com sucesso! ID da mensagem:", response_data["msg_id"])
    except json.JSONDecodeError:
        print("⚠️ Erro: Resposta inválida do servidor.")
    secure_socket.close()

def consult_all_messages(id_origin, token):
    secure_socket = secure_connect()
    request = {
        "action": "consult_all",
        "token": token,
        "id_destination": id_origin
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    try:
        messages = json.loads(response.decode())
        print("\n📥 Todas as mensagens recebidas:")
        if not messages:
            print("Nenhuma mensagem encontrada.")
        else:
            for msg in messages:
                print(f"ID: {msg['id']} | De: {msg['id_origin']} | Assunto: {msg['subject']} | Lida: {'Sim' if msg['read'] else 'Não'}")
    except json.JSONDecodeError:
        print("⚠️ Erro ao decifrar a resposta do servidor.")
    secure_socket.close()

def consult_new_messages(id_origin, token):
    secure_socket = secure_connect()
    request = {
        "action": "consult_new",
        "token": token,
        "id_destination": id_origin
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    try:
        messages = json.loads(response.decode())
        print("\n📥 Novas mensagens:")
        if not messages:
            print("Nenhuma nova mensagem encontrada.")
        else:
            for msg in messages:
                print(f"ID: {msg['id']} | De: {msg['id_origin']} | Assunto: {msg['subject']} | Data: {msg['timestamp']}")
    except json.JSONDecodeError:
        print("⚠️ Erro ao decifrar a resposta do servidor.")
    secure_socket.close()

def read_message(id_origin, token):
    global client_private_key, client_public_key
    try:
        id_msg_input = input("📬 Informe o ID da mensagem que deseja ler: ").strip()
        id_msg = int(id_msg_input)
    except ValueError:
        print("⚠️ Erro: Por favor, insira um ID de mensagem válido (número).")
        return
    
    secure_socket = secure_connect()
    request = {
        "action": "read_message",
        "token": token,
        "id_destination": id_origin,
        "id_msg": id_msg
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    
    try:
        message = json.loads(response.decode())
    
        if "id_origin" in message:
            # Decifrar a chave AES
            encrypted_key = message['key']
            key = decrypt_key_with_private_key(encrypted_key)  
            
            # Decifrar o conteúdo
            decrypted_content = decrypt_content(message['content'], key)
            if decrypted_content is None:
                print("⚠️ Erro: Não foi possível decifrar o conteúdo. A mensagem pode ter sido adulterada.")
                return
            
            # Obter a chave pública do remetente
            sender_public_key = get_public_key(message['id_origin'], token)
            if sender_public_key is None:
                print("⚠️ Não foi possível verificar a assinatura sem a chave pública do remetente.")
                return
            
            # Verificar a assinatura
            signature = base64.b64decode(message['signature'])
            try:
                sender_public_key.verify(
                    signature,
                    message['content'].encode(),  # Verifica a assinatura no conteúdo criptografado
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                signature_valid = True
            except Exception as e:
                signature_valid = False
                print("⚠️ Assinatura inválida:", e)
            
            print("\n📨 Mensagem:")
            print(f"De: {message['id_origin']} | Para: {message['id_destination']} | Assunto: {message['subject']}")
            print(f"Data: {message['timestamp']}")
            print(f"Conteúdo: {decrypted_content.decode('utf-8')}")
            print(f"Assinatura válida: {'Sim' if signature_valid else 'Não'}")
        elif "error" in message:
            print("⚠️ Erro:", message["error"])
        else:
            print("⚠️ Resposta inesperada do servidor.")
    except json.JSONDecodeError:
        print("⚠️ Erro: resposta inesperada do servidor.")
    finally:
        secure_socket.close()

def delete_message(id_origin, token):
    try:
        id_msg = int(input("🗑️ Informe o ID da mensagem que deseja excluir: ").strip())
    except ValueError:
        print("⚠️ Erro: Por favor, insira um ID de mensagem válido (número).")
        return
    
    secure_socket = secure_connect()
    request = {
        "action": "delete_message",
        "token": token,
        "id_destination": id_origin,
        "id_msg": id_msg
    }
    secure_socket.send(json.dumps(request).encode())
    response = secure_socket.recv(4096)
    try:
        response_data = json.loads(response.decode())
        if "error" in response_data:
            print("⚠️ Erro:", response_data["error"])
        else:
            print("🗑️ Resposta do servidor:", response_data.get("status", "Mensagem excluída com sucesso."))
    except json.JSONDecodeError:
        print("🗑️ Resposta do servidor:", response.decode())
    secure_socket.close()

def display_menu():
    print("\n🌐  Sistema de Mensagens Seguras  🌐")
    print(""" 
    ──▄▀▀▀▄───────────────
    ──█───█───────────────
    ─███████─────────▄▀▀▄─
    ░██─▀─██░░█▀█▀▀▀▀█░░█░
    ░███▄███░░▀░▀░░░░░▀▀░░
    \nCripto Trabalho Prático
        """)
    print("📜 **Menu de Opções**")
    print("1 - ✉️  Enviar mensagem")
    print("2 - 📬 Consultar todas as mensagens")
    print("3 - 🆕 Consultar novas mensagens")
    print("4 - 📨 Ler uma mensagem")
    print("5 - 🗑️  Excluir uma mensagem")
    print("6 - 🚪 Sair")

def main():
    global client_private_key, client_public_key
    id_origin = input("🆔 Informe seu ID: ").strip()
    # Carregar ou gerar um par de chaves distinto para este cliente
    client_private_key, client_public_key = load_or_generate_keys(id_origin)
    
    # Realizar o login ou registo
    while True:
        print("\n🔒 **Autenticação**")
        print("1 - 🔐 Login")
        print("2 - 📝 Registrar novo cliente")
        choice = input("➡️  Escolha uma opção (1-2): ").strip()

        if choice == "1":
            token = login_client(id_origin)
            if token:
                break
        elif choice == "2":
            register_client(id_origin)
        else:
            print("⚠️ Opção inválida. Tente novamente.")

    # Loop principal de operações
    while True:
        display_menu()
        choice = input("➡️  Escolha uma opção (1-6): ").strip()

        if choice == "1":
            send_message(id_origin, token)

        elif choice == "2":
            consult_all_messages(id_origin, token)

        elif choice == "3":
            consult_new_messages(id_origin, token)

        elif choice == "4":
            read_message(id_origin, token)

        elif choice == "5":
            delete_message(id_origin, token)

        elif choice == "6":
            print("👋 Saindo...")
            break

        else:
            print("⚠️ Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
