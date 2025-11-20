import json
import base64
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import secrets
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------------------------
# 🔧 CONFIGURACIÓN DE BASE DE DATOS
# --------------------------------------------------------------------------

DB_CONFIG = {
    'dbname': 'votaciones_db',
    'user': 'votaciones_user',
    'password': 'password',  # ¡CAMBIAR EN PRODUCCIÓN!
    'host': 'localhost',
    'port': '5432'
}

def get_db_connection():
    """Obtiene una conexión a la base de datos PostgreSQL."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"ERROR DE CONEXIÓN A BD: {e}")
        return None

def init_database():
    """Inicializa las tablas de la base de datos si no existen."""
    conn = get_db_connection()
    if not conn:
        print("No se pudo conectar a la base de datos")
        return False
    
    try:
        cur = conn.cursor()
        
        # Tabla de usuarios
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                clave_publica_pem TEXT NOT NULL,
                rol VARCHAR(20) NOT NULL DEFAULT 'voter',
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabla de encuestas
        cur.execute("""
            CREATE TABLE IF NOT EXISTS encuestas (
                id VARCHAR(50) PRIMARY KEY,
                titulo VARCHAR(200) NOT NULL,
                opciones JSONB NOT NULL,
                clave_publica_pem TEXT NOT NULL,
                clave_privada_pem_cifrada TEXT NOT NULL,
                creador_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activa BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Tabla de votos
        cur.execute("""
            CREATE TABLE IF NOT EXISTS votos (
                id SERIAL PRIMARY KEY,
                encuesta_id VARCHAR(50) REFERENCES encuestas(id) ON DELETE CASCADE,
                voto_cifrado TEXT NOT NULL,
                fecha_voto TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabla de tokens de votación
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tokens_votacion (
                id SERIAL PRIMARY KEY,
                token_hash VARCHAR(256) UNIQUE NOT NULL,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                encuesta_id VARCHAR(50) REFERENCES encuestas(id) ON DELETE CASCADE,
                usado BOOLEAN DEFAULT FALSE,
                fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                fecha_uso TIMESTAMP
            )
        """)
        
        # Índices
        cur.execute("CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_votos_encuesta ON votos(encuesta_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_usuario ON tokens_votacion(usuario_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_encuesta ON tokens_votacion(encuesta_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens_votacion(token_hash)")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("✅ Base de datos inicializada correctamente")
        return True
        
    except Exception as e:
        print(f"❌ Error inicializando base de datos: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

# --------------------------------------------------------------------------
# 🔐 LÓGICA CENTRAL DEL SERVIDOR
# --------------------------------------------------------------------------

class ServidorCentral:
    """
    Contiene toda la lógica de negocio integrada con PostgreSQL.
    """
    
    def registrar_usuario(self, nombre_usuario, email, password, clave_publica_pem_bytes):
        """Registra un nuevo usuario en la base de datos."""
        conn = get_db_connection()
        if not conn:
            return False, "Error de conexión a la base de datos"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Verificar si el email ya existe
            cur.execute("SELECT email FROM usuarios WHERE email = %s", (email,))
            if cur.fetchone():
                cur.close()
                conn.close()
                return False, "Este correo electrónico ya está registrado"
            
            # Determinar el rol (el primero es admin)
            cur.execute("SELECT COUNT(*) as count FROM usuarios")
            count = cur.fetchone()['count']
            rol = "admin" if count == 0 else "voter"
            
            # Validar la clave pública
            try:
                serialization.load_pem_public_key(
                    clave_publica_pem_bytes,
                    backend=default_backend()
                )
            except Exception as e:
                cur.close()
                conn.close()
                return False, f"Clave pública inválida: {str(e)}"
            
            # Hash del password
            password_hash = generate_password_hash(password)
            
            # Insertar usuario
            cur.execute("""
                INSERT INTO usuarios (nombre, email, password_hash, clave_publica_pem, rol)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (nombre_usuario, email, password_hash, clave_publica_pem_bytes.decode('utf-8'), rol))
            
            user_id = cur.fetchone()['id']
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"✅ Usuario '{nombre_usuario}' ({email}) registrado como '{rol}' (ID: {user_id})")
            return True, {"message": "Registro exitoso", "rol": rol}
            
        except Exception as e:
            print(f"❌ Error registrando usuario: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, str(e)
    
    def validar_login(self, email, password, clave_privada_pem):
        """Valida las credenciales del usuario con contraseña Y clave privada."""
        conn = get_db_connection()
        if not conn:
            return False, None, "Error de conexión a la base de datos"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Buscar usuario
            cur.execute("""
                SELECT id, nombre, email, password_hash, clave_publica_pem, rol
                FROM usuarios WHERE email = %s
            """, (email,))
            
            user = cur.fetchone()
            cur.close()
            conn.close()
            
            if not user:
                return False, None, "Usuario no encontrado"
            
            # ✅ VALIDAR CONTRASEÑA PRIMERO
            if not check_password_hash(user['password_hash'], password):
                return False, None, "Contraseña incorrecta"
            
            # ✅ LUEGO VALIDAR CLAVE PRIVADA
            try:
                # Cargar clave privada
                private_key = serialization.load_pem_private_key(
                    clave_privada_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                
                # Cargar clave pública registrada
                public_key_registered = serialization.load_pem_public_key(
                    user['clave_publica_pem'].encode('utf-8'),
                    backend=default_backend()
                )
                
                # Obtener clave pública de la privada proporcionada
                public_key_from_private = private_key.public_key()
                
                # Comparar las claves públicas
                pub_registered_pem = public_key_registered.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                pub_from_private_pem = public_key_from_private.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                if pub_registered_pem != pub_from_private_pem:
                    return False, None, "Clave privada no corresponde al usuario"
                
                # Login exitoso (contraseña Y clave privada válidas)
                user_data = {
                    'id': user['id'],
                    'name': user['nombre'],
                    'email': user['email'],
                    'rol': user['rol']
                }
                
                print(f"✅ Login exitoso (2FA) para {email} (Rol: {user['rol']})")
                return True, user_data, "Login exitoso"
                
            except Exception as e:
                return False, None, f"Error validando clave privada: {str(e)}"
                
        except Exception as e:
            print(f"❌ Error en login: {e}")
            if conn:
                conn.close()
            return False, None, str(e)
    
    def publicar_encuesta(self, user_email, datos_encuesta_bytes, firma_bytes):
        """Publica una encuesta (solo admin)."""
        conn = get_db_connection()
        if not conn:
            return False, "Error de conexión a la base de datos"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Verificar que el usuario existe y es admin
            cur.execute("""
                SELECT id, rol, clave_publica_pem
                FROM usuarios WHERE email = %s
            """, (user_email,))
            
            user = cur.fetchone()
            if not user:
                cur.close()
                conn.close()
                return False, "Usuario no registrado"
            
            if user['rol'] != 'admin':
                cur.close()
                conn.close()
                return False, "Permiso denegado: Solo los administradores pueden crear encuestas"
            
            # Verificar firma
            try:
                public_key = serialization.load_pem_public_key(
                    user['clave_publica_pem'].encode('utf-8'),
                    backend=default_backend()
                )
                
                public_key.verify(
                    firma_bytes,
                    datos_encuesta_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except InvalidSignature:
                cur.close()
                conn.close()
                return False, "Firma inválida"
            
            # Parsear datos de la encuesta
            datos_creacion = json.loads(datos_encuesta_bytes.decode('utf-8'))
            
            # Generar par de claves para la encuesta
            private_key_enc = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key_enc = private_key_enc.public_key()
            
            # Serializar claves
            public_key_pem = public_key_enc.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Cifrar la clave privada con una contraseña (en producción usar KMS)
            private_key_pem = private_key_enc.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Preparar opciones en formato JSON
            opciones_json = json.dumps([{"text": opt, "votes": 0} for opt in datos_creacion['opciones']])
            
            # Insertar encuesta
            cur.execute("""
                INSERT INTO encuestas 
                (id, titulo, opciones, clave_publica_pem, clave_privada_pem_cifrada, creador_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                datos_creacion['id_encuesta'],
                datos_creacion['pregunta'],
                opciones_json,
                public_key_pem,
                private_key_pem,
                user['id']
            ))
            
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"✅ Encuesta '{datos_creacion['pregunta']}' publicada por {user_email}")
            return True, "Encuesta publicada exitosamente"
            
        except Exception as e:
            print(f"❌ Error publicando encuesta: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, str(e)
    
    def obtener_encuestas(self, user_email=None):
        """Obtiene la lista de encuestas activas."""
        conn = get_db_connection()
        if not conn:
            return []
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Obtener encuestas
            cur.execute("""
                SELECT id, titulo, opciones, clave_publica_pem, fecha_creacion
                FROM encuestas
                WHERE activa = TRUE
                ORDER BY fecha_creacion DESC
            """)
            
            encuestas = cur.fetchall()
            print(f"📊 BACKEND: Se encontraron {len(encuestas)} encuestas en la BD")
            
            # Si hay un usuario, verificar si ya votó
            user_id = None
            if user_email:
                cur.execute("SELECT id FROM usuarios WHERE email = %s", (user_email,))
                user_row = cur.fetchone()
                if user_row:
                    user_id = user_row['id']
            
            resultado = []
            for enc in encuestas:
                has_voted = False
                user_vote = None
                
                if user_id:
                    # Verificar si el usuario ya solicitó token para esta encuesta
                    cur.execute("""
                        SELECT usado FROM tokens_votacion
                        WHERE usuario_id = %s AND encuesta_id = %s
                    """, (user_id, enc['id']))
                    token_row = cur.fetchone()
                    if token_row:
                        has_voted = token_row['usado']
                
                # Contar votos totales
                cur.execute("""
                    SELECT COUNT(*) as total FROM votos WHERE encuesta_id = %s
                """, (enc['id'],))
                total_votos = cur.fetchone()['total']
                
                # Parsear opciones - IMPORTANTE: Manejar tanto string como objeto JSON
                try:
                    if isinstance(enc['opciones'], str):
                        opciones = json.loads(enc['opciones'])
                    else:
                        opciones = enc['opciones']
                except Exception as parse_error:
                    print(f"⚠️ Error parseando opciones de encuesta {enc['id']}: {parse_error}")
                    opciones = []
                
                encuesta_dict = {
                    'id': enc['id'],
                    'title': enc['titulo'],
                    'options': opciones,
                    'hasVoted': has_voted,
                    'userVote': user_vote,
                    'clave_publica_pem': enc['clave_publica_pem'],
                    'totalVotes': total_votos
                }
                
                print(f"  📋 Encuesta: {enc['titulo']} (ID: {enc['id']}, Votos: {total_votos})")
                
                resultado.append(encuesta_dict)
            
            cur.close()
            conn.close()
            
            print(f"✅ BACKEND: Devolviendo {len(resultado)} encuestas al frontend\n")
            return resultado
            
        except Exception as e:
            print(f"❌ Error obteniendo encuestas: {e}")
            import traceback
            traceback.print_exc()
            if conn:
                conn.close()
            return []
    
    def solicitar_token_votacion(self, user_email, poll_id, firma_bytes):
        """Genera un token de votación de un solo uso."""
        conn = get_db_connection()
        if not conn:
            return False, None, "Error de conexión"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Obtener usuario
            cur.execute("""
                SELECT id, clave_publica_pem FROM usuarios WHERE email = %s
            """, (user_email,))
            user = cur.fetchone()
            
            if not user:
                cur.close()
                conn.close()
                return False, None, "Usuario no encontrado"
            
            # Verificar firma
            try:
                public_key = serialization.load_pem_public_key(
                    user['clave_publica_pem'].encode('utf-8'),
                    backend=default_backend()
                )
                public_key.verify(
                    firma_bytes,
                    poll_id.encode('utf-8'),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except InvalidSignature:
                cur.close()
                conn.close()
                return False, None, "Firma inválida"
            
            # Verificar que no haya solicitado token antes
            cur.execute("""
                SELECT id FROM tokens_votacion
                WHERE usuario_id = %s AND encuesta_id = %s
            """, (user['id'], poll_id))
            
            if cur.fetchone():
                cur.close()
                conn.close()
                return False, None, "Ya has solicitado un token para esta encuesta"
            
            # Generar token
            token = secrets.token_hex(32)
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            
            # Guardar token
            cur.execute("""
                INSERT INTO tokens_votacion (token_hash, usuario_id, encuesta_id, usado)
                VALUES (%s, %s, %s, FALSE)
            """, (token_hash, user['id'], poll_id))
            
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"✅ Token generado para {user_email} en encuesta {poll_id}")
            return True, token, "Token generado"
            
        except Exception as e:
            print(f"❌ Error generando token: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, None, str(e)
    
    def registrar_voto(self, poll_id, voto_cifrado_base64, token):
        """Registra un voto cifrado en la base de datos."""
        conn = get_db_connection()
        if not conn:
            return False, "Error de conexión"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Validar token
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            
            cur.execute("""
                SELECT id, encuesta_id, usado FROM tokens_votacion
                WHERE token_hash = %s
            """, (token_hash,))
            
            token_row = cur.fetchone()
            
            if not token_row:
                cur.close()
                conn.close()
                return False, "Token inválido"
            
            if token_row['usado']:
                cur.close()
                conn.close()
                return False, "Token ya utilizado"
            
            if token_row['encuesta_id'] != poll_id:
                cur.close()
                conn.close()
                return False, "Token no válido para esta encuesta"
            
            # Marcar token como usado
            cur.execute("""
                UPDATE tokens_votacion
                SET usado = TRUE, fecha_uso = %s
                WHERE id = %s
            """, (datetime.now(), token_row['id']))
            
            # Guardar voto
            cur.execute("""
                INSERT INTO votos (encuesta_id, voto_cifrado)
                VALUES (%s, %s)
            """, (poll_id, voto_cifrado_base64))
            
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"✅ Voto registrado para encuesta {poll_id}")
            return True, "Voto registrado exitosamente"
            
        except Exception as e:
            print(f"❌ Error registrando voto: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, str(e)
    
    def contar_votos(self, poll_id, user_email):
        """Cuenta los votos de una encuesta (solo admin)."""
        conn = get_db_connection()
        if not conn:
            return False, None, "Error de conexión"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Verificar que el usuario es admin
            cur.execute("""
                SELECT rol FROM usuarios WHERE email = %s
            """, (user_email,))
            user = cur.fetchone()
            
            if not user or user['rol'] != 'admin':
                cur.close()
                conn.close()
                return False, None, "Permiso denegado: Solo administradores pueden ver resultados"
            
            # Obtener clave privada de la encuesta
            cur.execute("""
                SELECT clave_privada_pem_cifrada FROM encuestas WHERE id = %s
            """, (poll_id,))
            enc = cur.fetchone()
            
            if not enc:
                cur.close()
                conn.close()
                return False, None, "Encuesta no encontrada"
            
            # Cargar clave privada
            private_key = serialization.load_pem_private_key(
                enc['clave_privada_pem_cifrada'].encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # Obtener votos cifrados
            cur.execute("""
                SELECT voto_cifrado FROM votos WHERE encuesta_id = %s
            """, (poll_id,))
            votos = cur.fetchall()
            
            # Descifrar y contar
            resultados = {}
            for voto in votos:
                try:
                    voto_cifrado_bytes = base64.b64decode(voto['voto_cifrado'])
                    voto_descifrado = private_key.decrypt(
                        voto_cifrado_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    voto_json = json.loads(voto_descifrado.decode('utf-8'))
                    opcion = int(voto_json['vote'])
                    resultados[opcion] = resultados.get(opcion, 0) + 1
                except Exception as e:
                    print(f"⚠️ Voto corrupto: {e}")
            
            cur.close()
            conn.close()
            
            total = len(votos)
            print(f"📊 Resultados para {poll_id}: {resultados} (Total: {total})")
            
            return True, {"results": resultados, "total_votos": total}, "Conteo exitoso"
            
        except Exception as e:
            print(f"❌ Error contando votos: {e}")
            if conn:
                conn.close()
            return False, None, str(e)

    def borrar_encuesta(self, poll_id, user_email):
        """Borra una encuesta (solo admin)."""
        conn = get_db_connection()
        if not conn:
            return False, "Error de conexión"
        
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Verificar que el usuario es admin
            cur.execute("""
                SELECT rol FROM usuarios WHERE email = %s
            """, (user_email,))
            user = cur.fetchone()
            
            if not user or user['rol'] != 'admin':
                cur.close()
                conn.close()
                return False, "Permiso denegado: Solo administradores pueden borrar encuestas"
            
            # Verificar que la encuesta existe
            cur.execute("SELECT id FROM encuestas WHERE id = %s", (poll_id,))
            if not cur.fetchone():
                cur.close()
                conn.close()
                return False, "Encuesta no encontrada"

            # Borrar la encuesta. ON DELETE CASCADE se encargará del resto.
            cur.execute("DELETE FROM encuestas WHERE id = %s", (poll_id,))
            
            conn.commit()
            cur.close()
            conn.close()
            
            print(f"🗑️ Encuesta {poll_id} borrada por {user_email}")
            return True, "Encuesta borrada exitosamente"
            
        except Exception as e:
            print(f"❌ Error borrando encuesta: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return False, str(e)

# --------------------------------------------------------------------------
# 🌐 CONFIGURACIÓN E INICIO DEL SERVIDOR WEB (FLASK)
# --------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)
servidor = ServidorCentral()

# Inicializar base de datos al arrancar
init_database()

# --------------------------------------------------------------------------
# 🛤️ API ENDPOINTS
# --------------------------------------------------------------------------

@app.route('/registrar', methods=['POST'])
def endpoint_registrar():
    """Endpoint para registrar un nuevo usuario."""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    public_key_pem = data.get('public_key_pem')
    
    if not all([username, email, password, public_key_pem]):
        return jsonify({"error": "Faltan datos"}), 400
    
    public_key_bytes = public_key_pem.encode('utf-8')
    success, result = servidor.registrar_usuario(username, email, password, public_key_bytes)
    
    if success:
        return jsonify(result), 201
    else:
        return jsonify({"error": result}), 400

@app.route('/login', methods=['POST'])
def endpoint_login():
    """Endpoint para validar login con contraseña Y clave privada."""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    private_key_pem = data.get('private_key_pem')
    
    if not all([email, password, private_key_pem]):
        return jsonify({"error": "Faltan datos (email, contraseña y clave privada requeridos)"}), 400
    
    success, user_data, message = servidor.validar_login(email, password, private_key_pem)
    
    if success:
        return jsonify({"message": message, "user": user_data}), 200
    else:
        return jsonify({"error": message}), 401

@app.route('/publicar-encuesta', methods=['POST'])
def endpoint_publicar():
    """Endpoint para publicar encuesta (solo admin)."""
    data = request.json
    username = data.get('username')
    poll_data_json_str = data.get('poll_data_json')
    signature_base64 = data.get('signature_base64')
    
    if not all([username, poll_data_json_str, signature_base64]):
        return jsonify({"error": "Faltan datos"}), 400
    
    try:
        poll_data_bytes = poll_data_json_str.encode('utf-8')
        signature_bytes = base64.b64decode(signature_base64)
    except Exception as e:
        return jsonify({"error": f"Datos inválidos: {e}"}), 400
    
    success, message = servidor.publicar_encuesta(username, poll_data_bytes, signature_bytes)
    
    if success:
        return jsonify({"message": message}), 201
    else:
        status_code = 403 if "Permiso denegado" in message else 400
        return jsonify({"error": message}), status_code

@app.route('/get-polls', methods=['GET'])
def endpoint_get_polls():
    """Endpoint para obtener lista de encuestas."""
    user_email = request.args.get('user_email')
    encuestas = servidor.obtener_encuestas(user_email)
    return jsonify(encuestas), 200

@app.route('/solicitar-token-votacion', methods=['POST'])
def endpoint_solicitar_token():
    """Endpoint para solicitar token de votación."""
    data = request.json
    user_email = data.get('user_email')
    poll_id = data.get('poll_id')
    signature_base64 = data.get('signature_base64')
    
    if not all([user_email, poll_id, signature_base64]):
        return jsonify({"error": "Faltan datos"}), 400
    
    try:
        signature_bytes = base64.b64decode(signature_base64)
    except Exception:
        return jsonify({"error": "Firma inválida"}), 400
    
    success, token, message = servidor.solicitar_token_votacion(
        user_email, poll_id, signature_bytes
    )
    
    if success:
        return jsonify({"token_votacion": token}), 200
    else:
        return jsonify({"error": message}), 403

@app.route('/votar', methods=['POST'])
def endpoint_votar():
    """Endpoint para registrar un voto."""
    data = request.json
    poll_id = data.get('poll_id')
    voto_cifrado = data.get('voto_cifrado')
    token = data.get('token')
    
    if not all([poll_id, voto_cifrado, token]):
        return jsonify({"error": "Faltan datos"}), 400
    
    success, message = servidor.registrar_voto(poll_id, voto_cifrado, token)
    
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 403

@app.route('/contar-votos/<poll_id>', methods=['GET'])
def endpoint_contar_votos(poll_id):
    """Endpoint para contar votos (solo admin)."""
    user_email = request.args.get('user_email')
    
    if not user_email:
        return jsonify({"error": "Se requiere email de usuario"}), 400
    
    success, data, message = servidor.contar_votos(poll_id, user_email)
    
    if success:
        return jsonify(data), 200
    else:
        return jsonify({"error": message}), 403

@app.route('/borrar-encuesta/<poll_id>', methods=['DELETE'])
def endpoint_borrar_encuesta(poll_id):
    """Endpoint para borrar una encuesta (solo admin)."""
    user_email = request.args.get('user_email')
    
    if not user_email:
        return jsonify({"error": "Se requiere email de usuario"}), 400
    
    success, message = servidor.borrar_encuesta(poll_id, user_email)
    
    if success:
        return jsonify({"message": message}), 200
    else:
        status_code = 403 if "Permiso denegado" in message else 404
        return jsonify({"error": message}), status_code

# --------------------------------------------------------------------------
# 🖥️ RUTAS DE VISTAS
# --------------------------------------------------------------------------

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/app.js')
def serve_js():
    return send_from_directory('.', 'app.js')

@app.route('/styles.css')
def serve_css():
    return send_from_directory('.', 'styles.css')

# --------------------------------------------------------------------------
# 🚀 ARRANQUE
# --------------------------------------------------------------------------

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🗳️  SISTEMA DE VOTACIÓN SEGURO CON AUTENTICACIÓN 2FA")
    print("="*60)
    print("Servidor ejecutándose en: http://127.0.0.1:5000")
    print("🔐 Autenticación: Contraseña + Clave Privada RSA")
    print("="*60 + "\n")
    app.run(port=5000, debug=True)