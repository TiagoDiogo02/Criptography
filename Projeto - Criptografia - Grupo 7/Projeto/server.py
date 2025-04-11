# Servidor.py

import socket
import ssl
import threading
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Name, NameOID, CertificateBuilder, BasicConstraints, ExtendedKeyUsage
from cryptography.x509.oid import ExtendedKeyUsageOID
from datetime import datetime, timedelta, timezone
import os
from ipaddress import ip_address
from cryptography import x509
import base64
import sqlite3
import bcrypt
import uuid

# Caminhos para os arquivos de certificado e chave
CERTIFICATE_PATH = 'server_cert.pem'
PRIVATE_KEY_PATH = 'server_key.pem'
DATABASE_PATH = 'messages.db'

# Função para gerar um novo certificado e chave
def generate_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    with open(PRIVATE_KEY_PATH, "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    subject = Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Braga"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Guimarães"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Uminho"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),  
    ])

    cert = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ip_address(u"192.168.137.1"))
    ]),
        critical=False
    ).sign(key, hashes.SHA256())

    with open(CERTIFICATE_PATH, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

# Verifica se os certificados existem e cria se necessário
if not os.path.exists(CERTIFICATE_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
    print("Certificados não encontrados. A criar novos certificados...")
    generate_self_signed_cert()
else:
    print("Certificados encontrados. Usando certificados existentes.")

# Função para inicializar a base de dados
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Criação da tabela de clientes com senha hash
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Criação da tabela de mensagens
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id_msg INTEGER PRIMARY KEY AUTOINCREMENT,
            id_origin TEXT NOT NULL,
            id_destination TEXT NOT NULL,
            subject TEXT NOT NULL,
            content TEXT NOT NULL,
            key TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            FOREIGN KEY(id_origin) REFERENCES clients(id),
            FOREIGN KEY(id_destination) REFERENCES clients(id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Inicializa a base de dados no início do servidor
init_db()

# Função para registar logs com timestamp
def log(message):
    print(f"[{datetime.now().isoformat()}] {message}")

# Função para gerar hash seguro da senha
def generate_password_hash(password):
    # bcrypt automaticamente lida com o salt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode()

# Função para verificar a senha
def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

# Dicionário para armazenar tokens de sessão
session_tokens = {}  # token: client_id

# Função para lidar com registo de clientes
def handle_register(request_data, client_socket):
    client_id = request_data.get("id_origin")
    password = request_data.get("password")
    client_public_key = request_data.get("public_key")
    
    if not client_id or not password or not client_public_key:
        client_socket.send(json.dumps({"error": "Dados de registo incompletos."}).encode())
        return
    
    # Gerar hash para a senha usando bcrypt
    password_hash = generate_password_hash(password)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute('INSERT INTO clients (id, public_key, password_hash) VALUES (?, ?, ?)',
                       (client_id, client_public_key, password_hash))
        conn.commit()
        client_socket.send(json.dumps({"status": "Registo bem-sucedido."}).encode())
        log(f"Cliente {client_id} registado com sucesso.")
    except sqlite3.IntegrityError:
        client_socket.send(json.dumps({"error": "Cliente já registado."}).encode())
    finally:
        conn.close()

# Função para lidar com login de clientes
def handle_login(request_data, client_socket):
    client_id = request_data.get("id_origin")
    password = request_data.get("password")
    
    if not client_id or not password:
        client_socket.send(json.dumps({"error": "Dados de login incompletos."}).encode())
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash FROM clients WHERE id = ?', (client_id,))
    result = cursor.fetchone()
    
    if not result:
        client_socket.send(json.dumps({"error": "Cliente não registado."}).encode())
        conn.close()
        return
    
    stored_hash = result[0]
    if verify_password(password, stored_hash):
        # Gerar token de sessão
        token = str(uuid.uuid4())
        session_tokens[token] = client_id
        client_socket.send(json.dumps({"status": "Login bem-sucedido.", "token": token}).encode())
        log(f"Cliente {client_id} autenticado com sucesso. Token: {token}")
    else:
        client_socket.send(json.dumps({"error": "Senha incorreta."}).encode())
        log(f"Falha na autenticação para o cliente {client_id}.")
    
    conn.close()

# Função para verificar token de sessão
def authenticate(request_data):
    token = request_data.get("token")
    if not token:
        return None
    return session_tokens.get(token)

# Função para lidar com envio de mensagens
def handle_send(request_data, client_socket):
    client_id = request_data.get("id_origin")
    destination_id = request_data.get("id_destination")
    subject = request_data.get("subject")
    content = request_data.get("content")
    signature = request_data.get("signature")
    encrypted_key = request_data.get("key")
    timestamp = datetime.now(timezone.utc).isoformat()
    
    if not all([client_id, destination_id, subject, content, signature, encrypted_key]):
        client_socket.send(json.dumps({"error": "Dados de mensagem incompletos."}).encode())
        return
    
    if len(subject) > 50:
        client_socket.send(json.dumps({"error": "Assunto excede 50 caracteres."}).encode())
        return
    
    # Adicione os logs abaixo
    log(f"🔐 Conteúdo Recebido do Cliente {client_id}: {content}")
    log(f"✍️ Assinatura Recebida (base64): {signature}")
    
    # Validação da assinatura
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT public_key FROM clients WHERE id = ?', (client_id,))
    result = cursor.fetchone()
    
    if not result:
        log(f"Erro: Cliente {client_id} não registado.")
        client_socket.send(json.dumps({"error": "Cliente não registado."}).encode())
        conn.close()
        return
    
    client_public_key_pem = result[0]
    try:
        client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode())
    except Exception as e:
        log(f"Erro ao carregar chave pública do cliente {client_id}: {e}")
        client_socket.send(json.dumps({"error": "Chave pública inválida."}).encode())
        conn.close()
        return
    
    try:
        signature_bytes = base64.b64decode(signature)
        client_public_key.verify(
            signature_bytes,
            content.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        log("✅ Assinatura válida.")
    except Exception as e:
        log(f"Erro de validação de assinatura: {e}")
        client_socket.send(json.dumps({"error": "Assinatura inválida."}).encode())
        conn.close()
        return
    
    # Inserir a mensagem na base de dados
    cursor.execute('''
        INSERT INTO messages (id_origin, id_destination, subject, content, key, signature, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (client_id, destination_id, subject, content, encrypted_key, signature, timestamp))
    msg_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log(f"Mensagem {msg_id} enviada de {client_id} para {destination_id}.")
    client_socket.send(json.dumps({"msg_id": msg_id}).encode())

# Função para lidar com a consulta de todas as mensagens
def handle_consult_all(request_data, client_socket):
    id_destination = request_data.get("id_destination")
    if not id_destination:
        client_socket.send(json.dumps({"error": "id_destination não fornecido."}).encode())
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id_msg, id_origin, subject, timestamp, read
        FROM messages
        WHERE id_destination = ?
    ''', (id_destination,))
    
    rows = cursor.fetchall()
    all_messages = [
        {
            "id": row[0],
            "id_origin": row[1],
            "subject": row[2],
            "timestamp": row[3],
            "read": bool(row[4])
        }
        for row in rows
    ]
    
    log(f"Cliente {id_destination} consultou todas as mensagens.")
    client_socket.send(json.dumps(all_messages).encode())
    conn.close()

# Função para lidar com a consulta de novas mensagens
def handle_consult_new(request_data, client_socket):
    id_destination = request_data.get("id_destination")
    if not id_destination:
        client_socket.send(json.dumps({"error": "id_destination não fornecido."}).encode())
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id_msg, id_origin, subject, timestamp
        FROM messages
        WHERE id_destination = ? AND read = 0
    ''', (id_destination,))
    
    rows = cursor.fetchall()
    new_messages = [
        {
            "id": row[0],
            "id_origin": row[1],
            "subject": row[2],
            "timestamp": row[3]
        }
        for row in rows
    ]
    
    log(f"Cliente {id_destination} consultou novas mensagens.")
    client_socket.send(json.dumps(new_messages).encode())
    conn.close()

# Função para lidar com a leitura de mensagens
def handle_read_message(request_data, client_socket):
    msg_id = request_data.get("id_msg")
    id_destination = request_data.get("id_destination")
    
    if not msg_id or not id_destination:
        client_socket.send(json.dumps({"error": "Dados para a leitura de mensagem incompletos."}).encode())
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id_origin, id_destination, subject, content, key, signature, timestamp, read
        FROM messages
        WHERE id_msg = ? AND id_destination = ?
    ''', (msg_id, id_destination))
    
    row = cursor.fetchone()
    
    if row:
        # Atualizar o status da mensagem para lida
        cursor.execute('UPDATE messages SET read = 1 WHERE id_msg = ?', (msg_id,))
        conn.commit()
        
        response = {
            "id_origin": row[0],
            "id_destination": row[1],
            "subject": row[2],
            "content": row[3],
            "key": row[4],
            "signature": row[5],
            "timestamp": row[6]
        }
        log(f"Mensagem {msg_id} lida por {id_destination}.")
        client_socket.send(json.dumps(response).encode())
    else:
        log(f"Erro: Mensagem {msg_id} não encontrada ou acesso negado para {id_destination}.")
        client_socket.send(json.dumps({"error": "Mensagem não encontrada ou acesso negado"}).encode())
    
    conn.close()

# Função para lidar com a exclusão de mensagens
def handle_delete_message(request_data, client_socket):
    msg_id = request_data.get("id_msg")
    id_destination = request_data.get("id_destination")
    
    if not msg_id or not id_destination:
        client_socket.send(json.dumps({"error": "Dados para exclusão de mensagem incompletos."}).encode())
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id_msg FROM messages
        WHERE id_msg = ? AND id_destination = ?
    ''', (msg_id, id_destination))
    
    row = cursor.fetchone()
    
    if row:
        cursor.execute('DELETE FROM messages WHERE id_msg = ?', (msg_id,))
        conn.commit()
        log(f"Mensagem {msg_id} excluída por {id_destination}.")
        client_socket.send(json.dumps({"status": f"Mensagem {msg_id} apagada."}).encode())
    else:
        log(f"Erro: Mensagem {msg_id} não encontrada ou acesso negado para {id_destination}.")
        client_socket.send(json.dumps({"error": "Mensagem não encontrada ou acesso negado"}).encode())
    
    conn.close()

# Função para lidar com a obtenção de chave pública de um cliente
def handle_get_public_key(request_data, client_socket):
    client_id = request_data.get("id_requested")
    
    if not client_id:
        client_socket.send(json.dumps({"error": "id_requested não fornecido."}).encode())
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT public_key FROM clients WHERE id = ?', (client_id,))
    result = cursor.fetchone()
    
    if result:
        public_key = result[0]
        client_socket.send(json.dumps({"public_key": public_key}).encode())
    else:
        client_socket.send(json.dumps({"error": "Cliente não encontrado."}).encode())
    
    conn.close()

# Função para lidar com as requisições do cliente
def handle_client(client_socket):
    try:
        log("Cliente conectado.")
        while True:
            request = client_socket.recv(4096)
            if not request:
                break
            try:
                request_data = json.loads(request.decode())
            except json.JSONDecodeError:
                client_socket.send(json.dumps({"error": "Formato de mensagem inválido."}).encode())
                continue
            action = request_data.get("action")

            if action == "register":
                handle_register(request_data, client_socket)

            elif action == "login":
                handle_login(request_data, client_socket)

            else:
                # Todas as ações além de register e login requerem autenticação
                client_id = authenticate(request_data)
                if not client_id:
                    client_socket.send(json.dumps({"error": "Autenticação necessária ou token inválido."}).encode())
                    continue

                if action == "send":
                    handle_send(request_data, client_socket)

                elif action == "consult_all":
                    handle_consult_all(request_data, client_socket)

                elif action == "consult_new":
                    handle_consult_new(request_data, client_socket)

                elif action == "read_message":
                    handle_read_message(request_data, client_socket)

                elif action == "delete_message":
                    handle_delete_message(request_data, client_socket)

                elif action == "get_public_key":
                    handle_get_public_key(request_data, client_socket)

                else:
                    client_socket.send(json.dumps({"error": "Ação desconhecida."}).encode())

    except Exception as e:
        log(f"Erro no cliente: {e}")
    finally:
        client_socket.close()
        log("Cliente desconectado.")

# Função principal do servidor
def server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERTIFICATE_PATH, keyfile=PRIVATE_KEY_PATH)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("192.168.137.1", 9999))  # Aceita conexões de qualquer IP
    server_socket.listen(5)
    log("Servidor a funcionar e a aguardar ligações...")
    
    while True:
        client_socket, addr = server_socket.accept()
        log(f"Conexão recebida de {addr}")
        
        try:
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            threading.Thread(target=handle_client, args=(secure_socket,)).start()
        except ssl.SSLError as e:
            log(f"Erro TLS: {e}")
            client_socket.close()

if __name__ == "__main__":
    server()
