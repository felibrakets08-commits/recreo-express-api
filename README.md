# Recreo Express

Quiosco escolar: los alumnos consultan productos y reservan pedidos para un recreo.

## Cómo correrlo
Requiere Python 3 (no hay que instalar nada más):

    python3 server.py

Abrir http://localhost:8000

## Arquitectura
| Componente | Archivo | Responsabilidad |
|---|---|---|
| Frontend | `public/index.html` | Interfaz. Solo hace `fetch()` a `/api/*`. No toca la BD. |
| Capa de API | `route()` en `server.py` | Rutas REST: productos, pedidos, recreos, stats. |
| Backend | `create_order`, `set_status`, etc. en `server.py` | Calcula totales con los precios de la BD, valida stock, devuelve stock al cancelar. |
| Base de datos | `recreo_express.db` (SQLite) | Tablas `productos`, `pedidos`, `detalles_pedido`. Se crea sola al iniciar. |

## Endpoints
- `GET/POST /api/products` · `GET/PUT/DELETE /api/products/<id>`
- `GET/POST /api/orders` · `GET /api/orders/<id>` · `PUT /api/orders/<id>/status`
- `GET /api/recreos` · `GET /api/stats`
