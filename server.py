#!/usr/bin/env python3
"""Recreo Express - Backend + API REST + Mercado Pago + Google Workspace SSO.
Ejecutar:  python3 server.py   ->   http://localhost:8000
"""
import json, re, sqlite3, mimetypes, os, secrets, hmac, math, unicodedata, hashlib
import urllib.request, urllib.error
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE = Path(__file__).parent
DB_PATH = BASE / "recreo_express.db"
PUBLIC = BASE / "public"
RECREOS = ["1er recreo", "2do recreo", "3er recreo"]
ESTADOS = ["Pendiente", "Listo", "Entregado", "Cancelado"]
ESTADOS_PAGO = ["Pendiente", "Pagado", "Rechazado"]
CATEGORIAS = {"Golosinas", "Bebidas", "Snacks", "Galletitas", "Almacén"}

# Configuración de Seguridad e Identidad Institucional
DOMINIO_INSTITUCIONAL = os.environ.get("DOMINIO_ESCOLAR", "sanjoserosario.com.ar")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "1083942992838-265lbggin4f0vcr1j3gnq52bbm0qlnae.apps.googleusercontent.com")
CLAVE_VENDEDOR = os.environ.get("RECREO_CLAVE", "kiosco2026")
MP_ACCESS_TOKEN = os.environ.get("MP_ACCESS_TOKEN", "")

# Sesiones activas: token -> {"id": int, "usuario": str, "rol": "vendedor"|"consumidor", "nombre": str}
TOKENS = {}
IMG_RE = re.compile(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+")

SEED = [
    ("Alfajor Capitán del Espacio Triple", "Golosinas", 1200, 35, 10),
    ("Coca Cola 500ml", "Bebidas", 1800, 4, 8),
    ("Papas Fritas Lay's Clásicas 85g", "Snacks", 2100, 15, 5),
    ("Galletitas Chocolinas 170g", "Galletitas", 1450, 18, 6),
    ("Agua Mineral Villavicencio 500ml", "Bebidas", 1100, 3, 10),
    ("Chocolate Shot con Maní 40g", "Golosinas", 950, 25, 5),
    ("Tostado de jamón y queso", "Almacén", 2900, 12, 4),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario TEXT UNIQUE NOT NULL,
  clave TEXT NOT NULL,
  rol TEXT NOT NULL CHECK(rol IN ('vendedor', 'consumidor')),
  nombre TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS productos(
  id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT NOT NULL, categoria TEXT NOT NULL,
  precio REAL NOT NULL CHECK(precio >= 0), stock INTEGER NOT NULL CHECK(stock >= 0),
  stock_minimo INTEGER NOT NULL DEFAULT 5, imagen TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS pedidos(
  id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, alumno TEXT NOT NULL,
  usuario_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  recreo TEXT NOT NULL, metodo_pago TEXT NOT NULL, total REAL NOT NULL,
  estado TEXT NOT NULL DEFAULT 'Pendiente',
  estado_pago TEXT NOT NULL DEFAULT 'Pendiente',
  mp_link TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS detalles_pedido(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pedido_id INTEGER NOT NULL REFERENCES pedidos(id) ON DELETE CASCADE,
  producto_id INTEGER REFERENCES productos(id) ON DELETE SET NULL,
  nombre TEXT NOT NULL, cantidad INTEGER NOT NULL, precio_unitario REAL NOT NULL);
"""

class ApiError(Exception):
    def __init__(self, status, message, extra=None):
        self.status, self.message, self.extra = status, message, extra

# ---------------- SEGURIDAD & VERIFICACIÓN GOOGLE ----------------
def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
    return f"{salt}${key.hex()}"

def verify_password(stored_hash, provided_password):
    try:
        if "$" not in stored_hash:
            return hmac.compare_digest(stored_hash, provided_password)
        salt, stored_key = stored_hash.split("$")
        key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100_000)
        return hmac.compare_digest(key.hex(), stored_key)
    except Exception:
        return False

def es_email_institucional(email):
    pattern = rf"^[a-zA-Z0-9._%+-]+@{re.escape(DOMINIO_INSTITUCIONAL)}$"
    return bool(re.match(pattern, email.strip().lower()))

def verify_google_token(id_token):
    """Valida el token de identidad contra la API de Google."""
    url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if GOOGLE_CLIENT_ID and data.get("aud") != GOOGLE_CLIENT_ID:
                    print("Advertencia: El client_id difiere de GOOGLE_CLIENT_ID")
                return data
    except urllib.error.HTTPError as e:
        print("Error al verificar token con Google (HTTPError):", e.code, e.read().decode("utf-8"))
    except Exception as e:
        print("Error general verificando token Google:", e)
    return None

# ---------------- BASE DE DATOS ----------------
def db():
    con = sqlite3.connect(DB_PATH, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    con = db()
    con.executescript(SCHEMA)
    
    cols_prod = [r[1] for r in con.execute("PRAGMA table_info(productos)")]
    if "imagen" not in cols_prod:
        con.execute("ALTER TABLE productos ADD COLUMN imagen TEXT NOT NULL DEFAULT ''")
        
    cols_ped = [r[1] for r in con.execute("PRAGMA table_info(pedidos)")]
    if "usuario_id" not in cols_ped:
        con.execute("ALTER TABLE pedidos ADD COLUMN usuario_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL")
    if "estado_pago" not in cols_ped:
        con.execute("ALTER TABLE pedidos ADD COLUMN estado_pago TEXT NOT NULL DEFAULT 'Pendiente'")
    if "mp_link" not in cols_ped:
        con.execute("ALTER TABLE pedidos ADD COLUMN mp_link TEXT NOT NULL DEFAULT ''")
    
    if not con.execute("SELECT 1 FROM productos").fetchone():
        con.executemany("INSERT INTO productos(nombre,categoria,precio,stock,stock_minimo) VALUES(?,?,?,?,?)", SEED)
    
    if not con.execute("SELECT 1 FROM usuarios WHERE usuario='vendedor'").fetchone():
        clave_hash = hash_password(CLAVE_VENDEDOR)
        con.execute("INSERT INTO usuarios(usuario,clave,rol,nombre) VALUES('vendedor',?,'vendedor','Vendedor Kiosco')", (clave_hash,))
    con.close()

# ---------------- INTEGRACIÓN MERCADO PAGO ----------------
def crear_preferencia_mp(pedido):
    if not MP_ACCESS_TOKEN:
        return None
    url = "https://api.mercadopago.com/checkout/preferences"
    headers = {
        "Authorization": f"Bearer {MP_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "items": [
            {
                "title": str(item["nombre"])[:256],
                "quantity": int(item["cantidad"]),
                "unit_price": float(item["precio"]),
                "currency_id": "ARS"
            } for item in pedido["items"]
        ],
        "external_reference": str(pedido["id"]),
        "back_urls": {
            "success": "http://localhost:8000/",
            "failure": "http://localhost:8000/",
            "pending": "http://localhost:8000/"
        }
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("init_point")
    except Exception as e:
        print("Error Mercado Pago API:", e)
        return None

# ---------------- LÓGICA DE NEGOCIO ----------------
def solo_vendedor(user):
    if not user or user.get("rol") != "vendedor":
        raise ApiError(401, "Acción reservada exclusivamente al vendedor")

def clean_text(s):
    return s.replace("<", "&lt;").replace(">", "&gt;")

def get_product(con, pid):
    p = con.execute("SELECT * FROM productos WHERE id=?", (pid,)).fetchone()
    if not p:
        raise ApiError(404, "Producto no encontrado")
    return dict(p)

def clean_product(d):
    try:
        v = (clean_text(str(d["nombre"]).strip()), str(d["categoria"]).strip(), round(float(d["precio"]), 2),
             int(d["stock"]), int(d.get("stock_minimo", 5)))
    except (KeyError, TypeError, ValueError):
        raise ApiError(400, "Datos de producto inválidos")
    if not v[0] or v[1] not in CATEGORIAS or v[2] < 0 or v[3] < 0 or v[4] < 0:
        raise ApiError(400, "Datos de producto inválidos")
    img = d.get("imagen") or ""
    if not isinstance(img, str) or (img and (len(img) > 400_000 or not IMG_RE.fullmatch(img))):
        raise ApiError(400, "Imagen inválida (PNG, JPG o WEBP, hasta ~300 KB)")
    return (*v, img)

def fmt_order(con, o):
    items = [dict(id=r["producto_id"], nombre=r["nombre"], cantidad=r["cantidad"], precio=r["precio_unitario"])
             for r in con.execute("SELECT * FROM detalles_pedido WHERE pedido_id=?", (o["id"],))]
    return {
        "id": f"ORD-{o['id']:04d}",
        "fecha": o["fecha"],
        "alumno": o["alumno"],
        "recreo": o["recreo"],
        "metodo_pago": o["metodo_pago"],
        "total": o["total"],
        "estado": o["estado"],
        "estado_pago": o["estado_pago"] if "estado_pago" in o.keys() else "Pendiente",
        "mp_link": o["mp_link"] if "mp_link" in o.keys() else "",
        "items": items,
        "usuario_id": o["usuario_id"]
    }

def get_order_row(con, oid):
    o = con.execute("SELECT * FROM pedidos WHERE id=?", (oid,)).fetchone()
    if not o:
        raise ApiError(404, "Pedido no encontrado")
    return o

def create_order(con, d, user):
    if not user:
        raise ApiError(400, "Debés iniciar sesión con tu cuenta escolar para reservar un pedido")
        
    alumno = user["nombre"]
    if d.get("recreo") not in RECREOS:
        raise ApiError(400, "Recreo inválido")
    if not isinstance(d.get("items"), list) or not d["items"]:
        raise ApiError(400, "El pedido no tiene productos")
        
    qty = {}
    for it in d["items"]:
        try:
            pid, c = int(it["id"]), int(it["cantidad"])
        except (KeyError, TypeError, ValueError):
            raise ApiError(400, "Ítem inválido")
        if c <= 0:
            raise ApiError(400, "Cantidad inválida")
        qty[pid] = qty.get(pid, 0) + c
        
    total, lines = 0.0, []
    for pid, c in qty.items():
        p = get_product(con, pid)
        if p["stock"] < c:
            raise ApiError(400, f"Stock insuficiente para {p['nombre']} (quedan {p['stock']})")
        lines.append((p, c))
        total += p["precio"] * c
    
    metodo = clean_text(str(d.get("metodo_pago") or "Efectivo"))[:50]
    cur = con.execute(
        "INSERT INTO pedidos(fecha,alumno,usuario_id,recreo,metodo_pago,total,estado,estado_pago,mp_link) VALUES(?,?,?,?,?,?,'Pendiente','Pendiente','')",
        (datetime.now().strftime("%d/%m/%Y %H:%M"), alumno, user["id"], d["recreo"], metodo, round(total, 2))
    )
    order_id = cur.lastrowid
                       
    for p, c in lines:
        con.execute("INSERT INTO detalles_pedido(pedido_id,producto_id,nombre,cantidad,precio_unitario) VALUES(?,?,?,?,?)",
                    (order_id, p["id"], p["nombre"], c, p["precio"]))
        con.execute("UPDATE productos SET stock = stock - ? WHERE id=?", (c, p["id"]))

    res_order = fmt_order(con, get_order_row(con, order_id))

    if "mercado pago" in metodo.lower():
        mp_url = crear_preferencia_mp(res_order)
        if mp_url:
            con.execute("UPDATE pedidos SET mp_link=? WHERE id=?", (mp_url, order_id))
            res_order["mp_link"] = mp_url

    return res_order

def set_status(con, oid, estado, estado_pago=None):
    o = get_order_row(con, oid)
    if estado and estado not in ESTADOS:
        raise ApiError(400, "Estado inválido")
    if estado_pago and estado_pago not in ESTADOS_PAGO:
        raise ApiError(400, "Estado de pago inválido")

    if estado and o["estado"] == "Cancelado" and estado != "Cancelado":
        raise ApiError(400, "Un pedido cancelado no se puede reactivar")

    if estado == "Cancelado" and o["estado"] != "Cancelado":
        con.execute("""UPDATE productos SET stock = stock + (SELECT cantidad FROM detalles_pedido d
                       WHERE d.pedido_id=? AND d.producto_id=productos.id)
                       WHERE id IN (SELECT producto_id FROM detalles_pedido WHERE pedido_id=?)""", (oid, oid))

    if estado:
        con.execute("UPDATE pedidos SET estado=? WHERE id=?", (estado, oid))
    if estado_pago:
        con.execute("UPDATE pedidos SET estado_pago=? WHERE id=?", (estado_pago, oid))

    return fmt_order(con, get_order_row(con, oid))

# ---------------- CARGA MASIVA ----------------
def sin_tildes(s):
    return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c)).casefold().strip()

def to_num(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        x = float(v)
    else:
        s = str(v).replace("$", "").replace(" ", "").strip()
        if "," in s and "." in s:
            s = s.replace(".", "").replace(",", ".") if s.rfind(",") > s.rfind(".") else s.replace(",", "")
        elif re.fullmatch(r"\d{1,3}(\.\d{3})+", s):
            s = s.replace(".", "")
        else:
            s = s.replace(",", ".")
        x = float(s)
    if not math.isfinite(x):
        raise ValueError("número inválido")
    return x

def import_products(con, d):
    filas = d.get("filas")
    if not isinstance(filas, list) or not filas:
        raise ApiError(400, "La planilla no tiene filas")
    if len(filas) > 500:
        raise ApiError(400, "Máximo 500 filas por planilla")
    cats = {sin_tildes(c): c for c in CATEGORIAS}
    prods = {r["nombre"].casefold(): dict(r) for r in con.execute("SELECT * FROM productos")}
    errores, tocados = [], {}
    for pos, f in enumerate(filas, start=2):
        n = f["_fila"] if isinstance(f, dict) and isinstance(f.get("_fila"), int) else pos
        try:
            if not isinstance(f, dict):
                raise ValueError("fila inválida")
            nombre = clean_text(str(f.get("nombre") or "").strip())
            if not nombre or len(nombre) > 100:
                raise ValueError("falta el nombre (o es muy largo)")
            key = nombre.casefold()
            p = prods.get(key) or {"id": None, "nombre": nombre, "categoria": None, "precio": None,
                                   "stock": None, "stock_minimo": 5, "imagen": ""}
            cat = str(f.get("categoria") or "").strip()
            if cat:
                if sin_tildes(cat) not in cats:
                    raise ValueError("categoría inválida (usar: " + ", ".join(sorted(CATEGORIAS)) + ")")
                p["categoria"] = cats[sin_tildes(cat)]
            for campo in ("precio", "stock", "stock_minimo"):
                v = f.get(campo)
                if v is None or str(v).strip() == "":
                    continue
                try:
                    x = to_num(v)
                except ValueError:
                    raise ValueError(f"{campo} no es un número")
                if x < 0 or (campo != "precio" and x != int(x)):
                    raise ValueError(f"{campo} inválido (no puede ser negativo ni tener decimales)" if campo != "precio" else "precio inválido")
                p[campo] = round(x, 2) if campo == "precio" else int(x)
            if p["id"] is None and (p["categoria"] is None or p["precio"] is None or p["stock"] is None):
                raise ValueError("producto nuevo: faltan categoría, precio o stock")
            prods[key] = tocados[key] = p
        except ValueError as e:
            errores.append({"fila": n, "error": str(e)})
    if errores:
        raise ApiError(400, f"Hay {len(errores)} fila(s) con errores. No se importó nada.", {"errores": errores[:50]})
    creados = actualizados = 0
    for p in tocados.values():
        vals = (p["nombre"], p["categoria"], p["precio"], p["stock"], p["stock_minimo"], p["imagen"])
        if p["id"] is None:
            con.execute("INSERT INTO productos(nombre,categoria,precio,stock,stock_minimo,imagen) VALUES(?,?,?,?,?,?)", vals)
            creados += 1
        else:
            con.execute("UPDATE productos SET nombre=?,categoria=?,precio=?,stock=?,stock_minimo=?,imagen=? WHERE id=?", (*vals, p["id"]))
            actualizados += 1
    return {"creados": creados, "actualizados": actualizados}

# ---------------- CAPA DE API (rutas) ----------------
def route(con, method, path, query, body, user=None):
    # LOGIN / REGISTRO CON GOOGLE WORKSPACE SSO
    if path == "/api/auth/google" and method == "POST":
        credential = body.get("credential")
        if not credential:
            raise ApiError(400, "Falta la credencial de autenticación de Google")
            
        g_data = verify_google_token(credential)
        if not g_data:
            raise ApiError(401, "Token de Google inválido o no autenticado")
            
        email = g_data.get("email", "").lower().strip()
        email_verified = g_data.get("email_verified")
        nombre = clean_text(g_data.get("name") or email.split("@")[0])
        
        if not email or not (email_verified is True or str(email_verified).lower() == "true"):
            raise ApiError(400, "El correo de Google debe estar verificado")
            
        if not es_email_institucional(email):
            raise ApiError(403, f"Acceso restringido: Solo se permiten correos @{DOMINIO_INSTITUCIONAL}")

        row = con.execute("SELECT * FROM usuarios WHERE usuario=?", (email,)).fetchone()
        if not row:
            clave_aleatoria = hash_password(secrets.token_hex(16))
            cur = con.execute("INSERT INTO usuarios(usuario,clave,rol,nombre) VALUES(?,?,'consumidor',?)", (email, clave_aleatoria, nombre))
            uid = cur.lastrowid
            rol = "consumidor"
        else:
            uid = row["id"]
            rol = row["rol"]
            nombre = row["nombre"]

        session_data = {"id": uid, "usuario": email, "rol": rol, "nombre": nombre}
        t = secrets.token_hex(16)
        TOKENS[t] = session_data
        return 200, {"data": {"token": t, "user": session_data}, "message": f"Bienvenido/a {nombre}"}

    # LOGIN DE ADMINISTRADOR / VENDEDOR
    if path == "/api/login" and method == "POST":
        usr = str(body.get("usuario", "")).strip().lower()
        clave = str(body.get("clave", "")).strip()
        
        if hmac.compare_digest(clave.encode(), CLAVE_VENDEDOR.encode()):
            u_row = con.execute("SELECT * FROM usuarios WHERE usuario='vendedor'").fetchone()
            session_data = dict(u_row) if u_row else {"id": 1, "usuario": "vendedor", "rol": "vendedor", "nombre": "Vendedor Kiosco"}
            t = secrets.token_hex(16)
            TOKENS[t] = session_data
            return 200, {"data": {"token": t, "user": session_data}, "message": "Sesión iniciada como Vendedor"}

        raise ApiError(400, "Para alumnos usá el botón 'Iniciar sesión con Google'")

    if path == "/api/me" and method == "GET":
        if not user:
            raise ApiError(401, "No hay sesión activa")
        return 200, {"data": user}

    if path == "/api/products":
        if method == "GET":
            return 200, {"data": [dict(r) for r in con.execute("SELECT * FROM productos ORDER BY id")]}
        if method == "POST":
            solo_vendedor(user)
            cur = con.execute("INSERT INTO productos(nombre,categoria,precio,stock,stock_minimo,imagen) VALUES(?,?,?,?,?,?)", clean_product(body))
            return 201, {"data": get_product(con, cur.lastrowid), "message": "Producto creado exitosamente"}

    if path == "/api/products/import" and method == "POST":
        solo_vendedor(user)
        r = import_products(con, body)
        return 200, {"data": r, "message": f"Importación lista: {r['creados']} creados, {r['actualizados']} actualizados"}

    m = re.fullmatch(r"/api/products/(\d+)", path)
    if m:
        pid = int(m[1])
        if method == "GET":
            return 200, {"data": get_product(con, pid)}
        if method == "PUT":
            solo_vendedor(user)
            body.setdefault("imagen", get_product(con, pid)["imagen"])
            con.execute("UPDATE productos SET nombre=?,categoria=?,precio=?,stock=?,stock_minimo=?,imagen=? WHERE id=?", (*clean_product(body), pid))
            return 200, {"data": get_product(con, pid), "message": "Producto actualizado"}
        if method == "DELETE":
            solo_vendedor(user)
            get_product(con, pid)
            con.execute("DELETE FROM productos WHERE id=?", (pid,))
            return 200, {"message": "Producto eliminado correctamente"}

    if path == "/api/orders":
        if method == "GET":
            if not user:
                raise ApiError(401, "Iniciá sesión para ver tus pedidos")
            
            if user["rol"] == "vendedor":
                rows = con.execute("SELECT * FROM pedidos ORDER BY id DESC").fetchall()
            else:
                rows = con.execute("SELECT * FROM pedidos WHERE usuario_id=? OR alumno LIKE ? ORDER BY id DESC",
                                   (user["id"], f"%{user['nombre']}%")).fetchall()
            
            est = query.get("estado", [None])[0]
            return 200, {"data": [fmt_order(con, r) for r in rows if not est or r["estado"] == est]}

        if method == "POST":
            return 201, {"data": create_order(con, body, user), "message": "Pedido reservado con éxito"}

    m = re.fullmatch(r"/api/orders/(?:ORD-)?(\d+)(/status)?", path)
    if m:
        oid = int(m[1])
        if method == "GET" and not m[2]:
            o = fmt_order(con, get_order_row(con, oid))
            if not user:
                raise ApiError(401, "Debes iniciar sesión")
            if user["rol"] != "vendedor" and o["usuario_id"] != user["id"] and user["nombre"].lower() not in o["alumno"].lower():
                raise ApiError(403, "No tenés permiso para ver este pedido")
            return 200, {"data": o}
            
        if method == "PUT" and m[2]:
            solo_vendedor(user)
            return 200, {
                "data": set_status(con, oid, body.get("estado"), body.get("estado_pago")),
                "message": "Estado de pedido actualizado"
            }

    if path == "/api/recreos" and method == "GET":
        return 200, {"data": RECREOS}

    if path == "/api/stats" and method == "GET":
        solo_vendedor(user)
        q = lambda s: con.execute(s).fetchone()[0]
        return 200, {"data": {
            "total_productos": q("SELECT COUNT(*) FROM productos"),
            "productos_stock_bajo": q("SELECT COUNT(*) FROM productos WHERE stock <= stock_minimo"),
            "pedidos_pendientes": q("SELECT COUNT(*) FROM pedidos WHERE estado='Pendiente'"),
            "total_pedidos": q("SELECT COUNT(*) FROM pedidos"),
            "ingresos_totales": q("SELECT COALESCE(SUM(total),0) FROM pedidos WHERE estado != 'Cancelado'")}}

    raise ApiError(404, "Endpoint no encontrado")

# ---------------- SERVIDOR HTTP ----------------
class Handler(BaseHTTPRequestHandler):
    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _send(self, status, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
        if ctype.startswith(("text/", "application/json")):
            ctype += "; charset=utf-8"
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _static(self, path):
        f = (PUBLIC / ("index.html" if path in ("", "/") else path.lstrip("/"))).resolve()
        if PUBLIC.resolve() not in f.parents or not f.is_file():
            return self._send(404, {"message": "No encontrado"})
        self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")

    def _handle(self, method):
        url = urlparse(self.path)
        if not url.path.startswith("/api/"):
            return self._static(url.path) if method == "GET" else self._send(405, {"message": "Método no permitido"})
        body = {}
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            return self._send(413, {"message": "Pedido demasiado grande"})
        if n:
            try:
                body = json.loads(self.rfile.read(n))
            except ValueError:
                return self._send(400, {"message": "JSON inválido"})
        if not isinstance(body, dict):
            body = {}
        con = db()
        try:
            if method != "GET":
                con.execute("BEGIN IMMEDIATE")
            
            token_header = self.headers.get("Authorization", "").removeprefix("Bearer ")
            user = TOKENS.get(token_header)
            
            status, payload = route(con, method, url.path, parse_qs(url.query), body, user)
            if con.in_transaction:
                con.execute("COMMIT")
        except ApiError as e:
            if con.in_transaction:
                con.execute("ROLLBACK")
            status, payload = e.status, {"message": e.message, **(e.extra or {})}
        except Exception as e:
            if con.in_transaction:
                con.execute("ROLLBACK")
            print("ERROR SERVIDOR:", e)
            status, payload = 500, {"message": "Error interno del servidor"}
        finally:
            con.close()
        self._send(status, payload)

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self): self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8000))
    print(f"Recreo Express corriendo en http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()