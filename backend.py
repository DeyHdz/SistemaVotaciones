import json
import base64
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import secrets  # Para generar tokens seguros
import hashlib  # Para hashear los tokens

# --------------------------------------------------------------------------
# 🔐 LÓGICA CENTRAL DEL SERVIDOR
# --------------------------------------------------------------------------

class ServidorCentral:
    """
    Contiene toda la lógica de negocio y el estado (en memoria) 
    de la aplicación de votación.
    """
    def __init__(self):
        """Inicializa el estado del servidor."""
        self.usuarios_registrados = {} 
        self.encuestas_activas = [] 
        self.claves_privadas_encuestas = {}
        
        # Guarda los tokens válidos { "hash_del_token": "poll_id" }
        self.tokens_autorizados = {}
        
        # Guarda qué usuarios ya pidieron token { "poll_id": ["user_email_1", ...] }
        self.votantes_autorizados = {}

        # La Urna Digital (Fase 4) { "poll_id": [voto_cifrado_1, ...] }
        self.urna_digital = {}
        # --- FIN DE LO AÑADIDO ---
        
        # Estas claves son para el cifrado de votos (Fase 3)
        self.clave_publica_encuesta = None
        self.clave_privada_encuesta = None

    def mostrar_usuarios(self):
        """Muestra los usuarios registrados en la consola."""
        print("\n--- Estado Actual de Usuarios Registrados ---")
        if not self.usuarios_registrados:
            print(" (No hay usuarios registrados en memoria)")
        else:
            for email, data in self.usuarios_registrados.items():
                print(f"  - Email: {email}")
                print(f"    Rol:   {data['role']}")
                print(f"    Nombre: {data['name']}")
        print("----------------------------------------------\n")

    def registrar_usuario(self, nombre_usuario, email, clave_publica_pem_bytes):
        """Fase 1: Registra un nuevo usuario y le asigna un rol."""

        if email in self.usuarios_registrados:
            print(f"SERVIDOR: ¡FALLO DE REGISTRO! El email '{email}' ya existe.")
            return False, "Este correo electrónico ya está registrado."


        rol_asignado = "admin" if not self.usuarios_registrados else "user"
        if rol_asignado == "admin":
            print(f"SERVIDOR: ¡Asignando rol de 'admin' al primer usuario: {email}!")

        try:
            public_key = serialization.load_pem_public_key(
                clave_publica_pem_bytes,
                backend=default_backend()
            )
            
            self.usuarios_registrados[email] = {
                "public_key": public_key,
                "role": rol_asignado,
                "name": nombre_usuario
            }
            
            print(f"SERVIDOR: Usuario '{nombre_usuario}' ({email}) registrado con rol '{rol_asignado}'.")
            self.mostrar_usuarios()
            return True, "Registro exitoso"
        
        except Exception as e:
            print(f"SERVIDOR: Error registrando a '{email}': {e}")
            return False, str(e)


    def publicar_encuesta(self, nombre_creador, datos_encuesta_bytes, firma_bytes):
        """Fase 2: Publica una encuesta (solo si es admin y la firma es válida)."""
        print(f"\nSERVIDOR: Recibida encuesta de '{nombre_creador}'. Verificando...")

        # 1. Autenticación y Autorización
        if nombre_creador not in self.usuarios_registrados:
            print(f"SERVIDOR: ¡FALLO! Usuario '{nombre_creador}' no registrado.")
            return False, "User no registrado"

        user_data = self.usuarios_registrados[nombre_creador]
        if user_data['role'] != 'admin':
            print(f"SERVIDOR: ¡FALLO DE PERMISO! El usuario '{nombre_creador}' (rol: '{user_data['role']}') intentó crear una encuesta.")
            return False, "Permiso denegado: Solo los administradores pueden crear encuestas."

        # 3. Verificación Criptográfica
        creador_public_key = user_data['public_key']
        try:
            creador_public_key.verify(
                firma_bytes,
                datos_encuesta_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            print("SERVIDOR: ¡Firma verificada! Encuesta auténtica.")
            
            # --- INICIO DE LA LÓGICA CLAVE ---
            # Cargar y Transformar la encuesta
            datos_creacion = json.loads(datos_encuesta_bytes.decode('utf-8'))
            
            # 1. Generar un nuevo par de claves PARA ESTA ENCUESTA
            key_priv_esc, key_pub_esc = self._generar_claves_escrutinio()
            
            # 2. Convertir la clave pública a formato PEM (texto)
            key_pub_pem = key_pub_esc.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # 3. Guardar la clave PRIVADA en el servidor (¡SECRETO!)
            if not hasattr(self, 'claves_privadas_encuestas'):
                self.claves_privadas_encuestas = {}
            self.claves_privadas_encuestas[datos_creacion['id_encuesta']] = key_priv_esc
            
            # 4. Construir la encuesta (CON LA CLAVE PÚBLICA)
            encuesta_transformada = {
                "id": datos_creacion['id_encuesta'],
                "title": datos_creacion['pregunta'],
                "options": [{"text": opt, "votes": 0} for opt in datos_creacion['opciones']],
                "hasVoted": False,
                "userVote": None,
                "clave_publica_pem": key_pub_pem  # <-- ¡ESTA LÍNEA ES LA QUE ARREGLA EL BUG!
            }

            # Añadimos la nueva encuesta a la LISTA
            self.encuestas_activas.append(encuesta_transformada)
            
            print(f"SERVIDOR: Encuesta publicada: {encuesta_transformada['title']}")
            # --- FIN DE LA LÓGICA CLAVE ---
            
            return True, "Encuesta publicada"

        except InvalidSignature:
            print("SERVIDOR: ¡¡¡FALLO DE VERIFICACIÓN!!! Firma no válida.")
            return False, "Firma no válida o datos manipulados"
        except Exception as e:
            print(f"SERVIDOR: Error inesperado: {e}")
            return False, str(e)

    def _generar_claves_escrutinio(self):
        """Genera y DEVUELVE un par de claves (Pública/Privada) para una encuesta."""
        print("SERVIDOR: Generando claves de escrutinio...")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        # DEVUELVE las claves
        return private_key, public_key


# --------------------------------------------------------------------------
# 🌐 CONFIGURACIÓN E INICIO DEL SERVIDOR WEB (FLASK)
# --------------------------------------------------------------------------

app = Flask(__name__)
servidor = ServidorCentral()

print("\n[Servidor Iniciado]")
servidor.mostrar_usuarios()

# --------------------------------------------------------------------------
# 🏛️ API ENDPOINTS (Manejo de Datos JSON)
# --------------------------------------------------------------------------

@app.route('/registrar', methods=['POST'])
def endpoint_registrar():
    """Endpoint de FASE 1: Registrar Usuario"""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    public_key_pem = data.get('public_key_pem')

    if not all([username, email, public_key_pem]):
        return jsonify({"error": "Faltan datos"}), 400
    
    public_key_pem_bytes = public_key_pem.encode('utf-8')
    success, message = servidor.registrar_usuario(username, email, public_key_pem_bytes)
    
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 500

@app.route('/publicar-encuesta', methods=['POST'])
def endpoint_publicar():
    """Endpoint de FASE 2: Publicar Encuesta Firmada"""
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
        return jsonify({"error": f"Datos de entrada inválidos: {e}"}), 400
        
    success, message = servidor.publicar_encuesta(username, poll_data_bytes, signature_bytes)
    
    if success:
        return jsonify({"message": message}), 201
    else:
        status_code = 403 if "Permiso denegado" in message else 400
        return jsonify({"error": message}), status_code

@app.route('/get-polls', methods=['GET'])
def endpoint_get_polls():
    """Endpoint para OBTENER la lista de encuestas activas."""
    # --- CORREGIDO ---
    # Devuelve la lista completa de encuestas
    return jsonify(servidor.encuestas_activas), 200

# En servidor.py, REEMPLAZA el endpoint_votar

@app.route('/votar', methods=['POST'])
def endpoint_votar():
    """
    Endpoint de FASE 3 y 4: Recibe un voto cifrado ANÓNIMO.
    Valida el token de un solo uso y lo guarda en la Urna Digital.
    """
    data = request.json
    poll_id = data.get('poll_id')
    voto_cifrado_base64 = data.get('voto_cifrado')
    token = data.get('token') # ¡El token ahora es requerido!

    if not all([poll_id, voto_cifrado_base64, token]):
        return jsonify({"error": "Faltan datos (poll_id, voto_cifrado o token)"}), 400

    # 1. Validar el token
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    # Buscamos el hash del token en nuestros tokens autorizados
    if token_hash not in servidor.tokens_autorizados:
        print(f"SERVIDOR: Voto rechazado (Token inválido o ya usado)")
        return jsonify({"error": "Token de votación inválido o ya utilizado"}), 403
    
    # Verificamos que el token sea para esta encuesta
    if servidor.tokens_autorizados[token_hash] != poll_id:
        print(f"SERVIDOR: Voto rechazado (Token no corresponde a esta encuesta)")
        return jsonify({"error": "Token no válido para esta encuesta"}), 403

    # 2. El token es válido. ¡Quemarlo (hacerlo de un solo uso)!
    del servidor.tokens_autorizados[token_hash]

    # 3. Guardar el voto cifrado en la Urna Digital (Fase 4)
    if poll_id not in servidor.urna_digital:
        servidor.urna_digital[poll_id] = []
    
    servidor.urna_digital[poll_id].append(voto_cifrado_base64)
    
    print(f"\nSERVIDOR: ¡Voto cifrado aceptado y guardado en la urna para {poll_id}!")
    print(f" (Tamaño actual de la urna para {poll_id}: {len(servidor.urna_digital[poll_id])} votos)")
    
    return jsonify({"message": "Voto anónimo recibido y guardado"}), 201


@app.route('/solicitar-token-votacion', methods=['POST'])
def endpoint_solicitar_token():
    """
    Endpoint de FASE 3.B: El usuario se autentica (con firma) 
    para recibir un token de votación de un solo uso.
    """
    data = request.json
    user_email = data.get('user_email')
    poll_id = data.get('poll_id')
    signature_base64 = data.get('signature_base64') # Firma de "poll_id"

    if not all([user_email, poll_id, signature_base64]):
        return jsonify({"error": "Faltan datos"}), 400

    # 1. Autenticar al usuario
    if user_email not in servidor.usuarios_registrados:
        return jsonify({"error": "Usuario no registrado"}), 401
    
    user_public_key = servidor.usuarios_registrados[user_email]['public_key']
    
    # 2. Verificar la firma (el usuario firma el ID de la encuesta)
    try:
        signature_bytes = base64.b64decode(signature_base64)
        # El usuario debe firmar el ID de la encuesta para probar que es él
        user_public_key.verify(
            signature_bytes,
            poll_id.encode('utf-8'), # Dato firmado
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"SERVIDOR: Fallo de firma al solicitar token: {e}")
        return jsonify({"error": "Firma inválida"}), 403

    # 3. Verificar que no haya pedido un token antes para esta encuesta
    if poll_id not in servidor.votantes_autorizados:
        servidor.votantes_autorizados[poll_id] = []

    if user_email in servidor.votantes_autorizados[poll_id]:
        return jsonify({"error": "Ya has solicitado un token para esta encuesta"}), 403

    # 4. Generar y almacenar el token
    token = secrets.token_hex(32) # Genera un token de 64 caracteres
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

    servidor.tokens_autorizados[token_hash] = poll_id # Guardamos el HASH
    servidor.votantes_autorizados[poll_id].append(user_email) # Marcamos al usuario

    print(f"SERVIDOR: Token emitido para {user_email} (para poll {poll_id}).")
    
    # 5. Devolver el token en TEXTO PLANO (solo esta vez)
    return jsonify({"token_votacion": token}), 200

# En servidor.py, en la sección 🏛️ API ENDPOINTS

@app.route('/contar-votos/<poll_id>', methods=['GET'])
def endpoint_contar_votos(poll_id):
    """
    Endpoint de FASE 4: Escrutinio.
    Público y anónimo. Descifra y cuenta todos los votos
    en la urna para una encuesta específica.
    """
    print(f"\nSERVIDOR: ¡Solicitud de escrutinio recibida para {poll_id}!")

    # 1. Encontrar la Clave Privada de Escrutinio
    if poll_id not in servidor.claves_privadas_encuestas:
        return jsonify({"error": "Clave de escrutinio no encontrada"}), 404
    
    clave_privada = servidor.claves_privadas_encuestas[poll_id]

    # 2. Encontrar la Urna Digital
    if poll_id not in servidor.urna_digital or not servidor.urna_digital[poll_id]:
        print("SERVIDOR: No hay votos en la urna para contar.")
        return jsonify({"message": "No hay votos en la urna", "results": {}}), 200

    urna = servidor.urna_digital[poll_id]
    print(f"SERVIDOR: Contando {len(urna)} votos cifrados...")

    # 3. Descifrar y Contar
    resultados = {} # Ej: { 0: 5, 1: 3 } (índice_opcion: conteo)
    
    for voto_cifrado_base64 in urna:
        try:
            voto_cifrado_bytes = base64.b64decode(voto_cifrado_base64)
            
            # Descifrar usando el mismo padding que el cliente (OAEP)
            voto_descifrado_bytes = clave_privada.decrypt(
                voto_cifrado_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Convertir el voto (JSON) de nuevo a un objeto
            voto_json = json.loads(voto_descifrado_bytes.decode('utf-8'))
            opcion_votada = int(voto_json['vote']) # Ej: 0, 1, 2...
            
            # Incrementar el contador
            resultados[opcion_votada] = resultados.get(opcion_votada, 0) + 1

        except Exception as e:
            print(f"SERVIDOR: ¡Error! Un voto en la urna estaba corrupto o no se pudo descifrar: {e}")
            # En un sistema real, este voto se marcaría como 'inválido'
            
    # --- ¡CUMPLIENDO TU 1ª SUGERENCIA! ---
    print("\n--- RESULTADOS DEL ESCRUTINIO (Consola) ---")
    print(f"Encuesta: {poll_id}")
    print(f"Resultados (Índice de Opción: Votos): {resultados}")
    print("-------------------------------------------\n")

    # 4. Devolver los resultados
    return jsonify({"results": resultados, "total_votos": len(urna)}), 200

# --------------------------------------------------------------------------
# 🖥️ RUTAS DE VISTAS (Servir archivos del Frontend)
# --------------------------------------------------------------------------

@app.route('/')
def serve_index():
    return send_from_directory('.', 'Votaciones/index.html')

@app.route('/app.js')
def serve_js():
    return send_from_directory('.', 'Votaciones/app.js')

@app.route('/styles.css')
def serve_css():
    return send_from_directory('.', 'Votaciones/styles.css')

# --------------------------------------------------------------------------
# 🚀 ARRANQUE
# --------------------------------------------------------------------------

if __name__ == '__main__':
    print("Iniciando servidor Flask en http://127.0.0.1:5000")
    app.run(port=5000, debug=True)