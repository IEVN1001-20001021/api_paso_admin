from flask import Flask, request, jsonify
import json
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timedelta
import jwt
import bcrypt
from functools import wraps
import os
from flask import request
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO
from flask_swagger_ui import get_swaggerui_blueprint
from flask import jsonify

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app, resources={r"/*": {"origins": "*"}}) 

# Configuración de la conexión a la base de datos
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'paso_db'
}

# Configuración para Swagger
SWAGGER_URL = '/api/docs'  # URL para acceder a la documentación
API_URL = '/swagger'  # URL permanente para obtener el JSON de Swagger

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "API Documentation"}
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/swagger')
def swagger_spec():
    return jsonify({
        "swagger": "2.0",
        "info": {
            "version": "1.0",
            "title": "API Administracion"
        },
        "paths": {
            "/login": {
                "post": {
                    "summary": "Login",
                    "description": "User login endpoint",
                    "responses": {
                        "200": {"description": "Successful login"}
                    }
                }
            },
            "/register": {
                "post": {
                    "summary": "Register",
                    "description": "Register a new user",
                    "responses": {
                        "201": {"description": "User created successfully"}
                    }
                }
            },
            "/dashboard": {
                "get": {
                    "summary": "Dashboard",
                    "description": "Get dashboard data",
                    "responses": {
                        "200": {"description": "Successful operation"}
                    }
                }
            },
            "/productos": {
                "get": {
                    "summary": "Get products",
                    "description": "Get all products",
                    "responses": {
                        "200": {"description": "Successful operation"}
                    }
                }
            },
            "/tiendas": {
                "get": {
                    "summary": "Get stores",
                    "description": "Get all stores",
                    "responses": {
                        "200": {"description": "Successful operation"}
                    }
                }
            },
            "/pedidos": {
                "get": {
                    "summary": "Get orders",
                    "description": "Get all orders",
                    "responses": {
                        "200": {"description": "Successful operation"}
                    }
                }
            },
        }
    })

# Decorador para proteger las rutas con autenticación JWT
def token_required(f):
    @wraps(f)  # Usamos wraps para preservar la información de la función original
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Obtener el token del encabezado

        if not token:
            return jsonify({'message': 'Token es necesario'}), 403

        try:
            # Decodificar el token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']  # Obtener el user_id del token
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'El token ha expirado'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 403

        return f(current_user, *args, **kwargs)
    return decorator

def get_db_connection():
    return mysql.connector.connect(**db_config)

# Verificar que el servidor funcione correctamente
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({'message': 'El servidor está funcionando correctamente.'})

@app.route('/login', methods=['POST'])
def login():
    try:
        # Obtener los datos del cuerpo de la solicitud
        data = request.json
        usuario = data['usuario']
        password = data['password']

        # Conectar a la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario existe en la base de datos
        query_check_user = "SELECT id, usuario, password_hash, rol FROM usuariosadmin WHERE usuario = %s"
        cursor.execute(query_check_user, (usuario,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'Usuario o contraseña incorrectos.'}), 400

        # Verificar la contraseña con bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Usuario o contraseña incorrectos.'}), 400

        # Asegurarse de que la clave secreta sea una cadena de texto
        if not isinstance(app.config['SECRET_KEY'], str):
            app.config['SECRET_KEY'] = '137950'  # O usa os.urandom(24)

        # Generar un token JWT para el usuario
        token = jwt.encode(
            {
                'user_id': user['id'],
                'exp': datetime.utcnow() + timedelta(days=1)  # Expiración del token en 1 día
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        # Responder con el mensaje de éxito y el token generado
        return jsonify({'message': 'Login exitoso', 'token': token, 'rol': user['rol']}), 200

    except Exception as e:
        # Manejar excepciones y devolver el mensaje de error
        return jsonify({'error': f'Error en el servidor: {str(e)}'}), 500

    finally:
        # Cerrar el cursor y la conexión de la base de datos
        if 'cursor' in locals(): cursor.close()
        if 'connection' in locals(): connection.close()

def initialize_admin_user():
    """Inicializa el usuario admin en la base de datos si no existe."""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Verificar si ya existe un usuario con rol "owner"
        cursor.execute("SELECT * FROM usuariosadmin WHERE rol = 'owner'")
        admin_exists = cursor.fetchone()

        if not admin_exists:
            # Generar hash de la contraseña
            password_hash = bcrypt.hashpw("Admin137950".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Insertar el usuario admin en la tabla
            cursor.execute(
                """
                INSERT INTO usuariosadmin (nombre, apaterno, amaterno, usuario, password_hash, rol)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                ('Miguel Angel', 'Rumbo', 'Rebolledo', 'miguel_rumbo', password_hash, 'owner')
            )
            connection.commit()
            print("Usuario admin creado exitosamente.")
        else:
            print("El usuario admin ya existe.")
    except mysql.connector.Error as err:
        print(f"Error al inicializar el usuario admin: {err}")
    finally:
        cursor.close()
        connection.close()

@app.route('/register', methods=['POST'])
@token_required  # Protegemos la ruta con el decorador
def register(current_user_id):
    data = request.json

    # Validamos el token para asegurarnos que es un "owner"
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT rol FROM usuariosadmin WHERE id = %s", (current_user_id,))
    user = cursor.fetchone()
    
    if not user or user['rol'] != 'owner':
        return jsonify({'message': 'Acceso denegado. Solo los usuarios "owner" pueden registrar nuevos usuarios.'}), 403

    nombre = data.get('nombre')
    apaterno = data.get('apaterno')
    amaterno = data.get('amaterno', '')  # Opcional
    rol = data.get('rol')
    password = data.get('password')

    # Validar datos
    if not nombre or not apaterno or not password or rol not in ['owner', 'administrador']:
        return jsonify({'message': 'Faltan datos obligatorios o el rol es inválido'}), 400

    # Generar usuario
    usuario = f"{nombre.lower()}_{apaterno.lower()}"

    # Hash de la contraseña
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        # Insertar el usuario en la base de datos
        cursor.execute(
            """
            INSERT INTO usuariosadmin (nombre, apaterno, amaterno, usuario, password_hash, rol)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (nombre, apaterno, amaterno, usuario, password_hash, rol)
        )
        connection.commit()
        return jsonify({'message': 'Usuario registrado exitosamente', 'usuario': usuario}), 201
    except mysql.connector.IntegrityError:
        return jsonify({'message': 'El nombre de usuario ya existe. Intente con otros datos.'}), 400
    finally:
        cursor.close()
        connection.close()
        
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Consulta total de pedidos
        cursor.execute("SELECT COUNT(*) AS total_pedidos FROM pedidos")
        total_pedidos = cursor.fetchone()['total_pedidos']

        # Consulta pedidos en proceso (pendientes o aceptados)
        cursor.execute("SELECT COUNT(*) AS pedidos_en_proceso FROM pedidos WHERE estado IN ('pendiente', 'aceptado')")
        pedidos_en_proceso = cursor.fetchone()['pedidos_en_proceso']

        # Consulta pedidos completados
        cursor.execute("SELECT COUNT(*) AS pedidos_completados FROM pedidos WHERE entregado = 1")
        pedidos_completados = cursor.fetchone()['pedidos_completados']

        # Consulta total de usuarios
        cursor.execute("SELECT COUNT(*) AS total_usuarios FROM usuarios")
        total_usuarios = cursor.fetchone()['total_usuarios']

        # Consulta nuevos usuarios del día de hoy
        hoy = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) AS nuevos_usuarios FROM usuarios WHERE DATE(fecha_registro) = %s", (hoy,))
        nuevos_usuarios = cursor.fetchone()['nuevos_usuarios']

        # Consulta pedidos por tienda
        cursor.execute(
            """
            SELECT tiendas.nombre, COUNT(pedidos.id) AS num_pedidos
            FROM pedidos
            JOIN tiendas ON pedidos.tienda_id = tiendas.id
            GROUP BY tiendas.nombre
            """
        )
        pedidos_por_tienda = cursor.fetchall()

        # Consulta pedidos por ciudad
        cursor.execute(
            """
            SELECT tiendas.ciudad, COUNT(pedidos.id) AS num_pedidos
            FROM pedidos
            JOIN tiendas ON pedidos.tienda_id = tiendas.id
            GROUP BY tiendas.ciudad
            """
        )
        pedidos_por_ciudad = cursor.fetchall()

        return jsonify({
            'total_pedidos': total_pedidos,
            'pedidos_en_proceso': pedidos_en_proceso,
            'pedidos_completados': pedidos_completados,
            'total_usuarios': total_usuarios,
            'nuevos_usuarios': nuevos_usuarios,
            'pedidos_por_tienda': pedidos_por_tienda,
            'pedidos_por_ciudad': pedidos_por_ciudad
        })

    except Exception as e:
        return jsonify({'error': f'Error al obtener datos del dashboard: {str(e)}'}), 500

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'connection' in locals(): connection.close()
        
# Endpoint para obtener productos y ventas
@app.route('/productos', methods=['GET'])
@token_required
def get_productos(current_user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Consulta para obtener todos los productos
        cursor.execute("SELECT * FROM productos")
        productos = cursor.fetchall()

        # Obtener los pedidos (detalles de los productos vendidos)
        cursor.execute("SELECT detalles, fecha_pedido FROM pedidos WHERE entregado = 1")
        pedidos = cursor.fetchall()

        # Cálculo de las ventas de productos
        ventas_por_producto = {}
        for pedido in pedidos:
            detalles = json.loads(pedido['detalles'])  # Convertir JSON a diccionario

            # Asegurarse de que 'productIds' esté en los detalles
            if 'productIds' in detalles:
                for item in detalles['productIds']:
                    producto_id = item['productId']
                    cantidad = item['quantity']

                    # Agregar al contador de ventas
                    ventas_por_producto[producto_id] = ventas_por_producto.get(producto_id, 0) + cantidad

        # Añadir las ventas al listado de productos
        productos_vendidos = []
        for producto in productos:
            producto_id = producto['id']
            producto['ventas'] = ventas_por_producto.get(producto_id, 0)
            productos_vendidos.append(producto)

        # Fechas clave para las estadísticas
        today = datetime.now().date()
        week_start = today - timedelta(days=today.weekday())  # Lunes de esta semana
        month_start = today.replace(day=1)  # Primer día del mes

        # Pedidos hoy
        cursor.execute("SELECT COUNT(*) AS total FROM pedidos WHERE DATE(fecha_pedido) = %s", (today,))
        pedidos_hoy = cursor.fetchone()['total']

        # Pedidos esta semana
        cursor.execute(
            "SELECT COUNT(*) AS total FROM pedidos WHERE DATE(fecha_pedido) BETWEEN %s AND %s", 
            (week_start, today)
        )
        pedidos_semana = cursor.fetchone()['total']

        # Pedidos este mes
        cursor.execute(
            "SELECT COUNT(*) AS total FROM pedidos WHERE MONTH(fecha_pedido) = %s AND YEAR(fecha_pedido) = %s", 
            (today.month, today.year)
        )
        pedidos_mes = cursor.fetchone()['total']

        return jsonify({
            'productos': productos_vendidos,
            'pedidosHoy': pedidos_hoy,
            'pedidosSemana': pedidos_semana,
            'pedidosMes': pedidos_mes
        })

    except Exception as e:
        return jsonify({'error': f'Error al obtener datos: {str(e)}'}), 500
    finally:
        # Cerrar cursor y conexión si existen
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/tiendas', methods=['GET'])
@token_required
def get_tiendas(current_user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Consulta para obtener todas las tiendas
        cursor.execute("SELECT * FROM tiendas")
        tiendas = cursor.fetchall()

        # Obtener los totales de ventas y la cantidad de pedidos para cada tienda
        cursor.execute("""
            SELECT 
                tienda_id,
                SUM(total) as total_ingresos, 
                COUNT(id) as cantidad_pedidos 
            FROM 
                pedidos 
            WHERE 
                entregado = 1 
            GROUP BY 
                tienda_id
        """)
        ventas_tiendas = cursor.fetchall()

        # Crear un diccionario para mapear tienda_id a los totales de ventas y cantidad de pedidos
        ventas_por_tienda = {venta['tienda_id']: venta for venta in ventas_tiendas}

        # Agregar información de ventas y cantidad de pedidos a cada tienda
        for tienda in tiendas:
            tienda_id = tienda['id']
            ventas_info = ventas_por_tienda.get(tienda_id, {'total_ingresos': 0, 'cantidad_pedidos': 0})
            tienda['totalIngresos'] = ventas_info['total_ingresos']
            tienda['cantidadPedidos'] = ventas_info['cantidad_pedidos']

        return jsonify({'tiendas': tiendas})

    except Exception as e:
        return jsonify({'error': f'Error al obtener datos: {str(e)}'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()
            
@app.route('/pedidos', methods=['GET'])
@token_required
def get_orders(current_user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Obtener todos los pedidos
        cursor.execute("SELECT * FROM pedidos")
        pedidos = cursor.fetchall()

        # Agregar detalles de productos a los pedidos
        for pedido in pedidos:
            # Parsear el JSON de detalles
            detalles = json.loads(pedido['detalles'])
            product_ids = [item['productId'] for item in detalles.get('productIds', [])]

            # Obtener los nombres de los productos relacionados
            if product_ids:
                format_strings = ','.join(['%s'] * len(product_ids))
                cursor.execute(
                    f"SELECT id, nombre FROM productos WHERE id IN ({format_strings})", tuple(product_ids)
                )
                productos = cursor.fetchall()
                detalles['productDetails'] = productos
            else:
                detalles['productDetails'] = []

            # Actualizar el campo detalles con los nombres de productos
            pedido['detalles'] = detalles

        return jsonify(pedidos)

    except Exception as e:
        return jsonify({'error': f'Error al obtener los pedidos: {str(e)}'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

if __name__ == '__main__':
    print("Inicializando servidor...")
    initialize_admin_user()  # Llama a la función para registrar el usuario admin
    app.run(debug=True)
