from __future__ import annotations
from typing import Optional
from datetime import date, datetime, timedelta
import os
import bcrypt
import databases

from fastapi import FastAPI, HTTPException, Depends, Request, Query, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth

# ======================
# CONFIG
# ======================
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def _split_env_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]

ALLOWED_ORIGINS = _split_env_csv(
    os.getenv("FRONTEND_ORIGINS", "http://localhost:4200,http://127.0.0.1:4200")
)

database = databases.Database(DATABASE_URL)

app = FastAPI(title="Proyecto API")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# OAuth Microsoft (opcional)
oauth = OAuth()
oauth.register(
    name="microsoft",
    client_id=os.getenv("MICROSOFT_CLIENT_ID"),
    client_secret=os.getenv("MICROSOFT_CLIENT_SECRET"),
    server_metadata_url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ======================
# MODELOS
# ======================
class UsuarioIn(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    activo: bool
    email: EmailStr
    fono: str = Field(..., min_length=8, max_length=15)

class UsuarioOut(UsuarioIn):
    id: int

class PasswordChange(BaseModel):
    nueva_password: str = Field(..., min_length=6)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class PropuestaIn(BaseModel):
    anio: str = Field(..., min_length=4, max_length=4)
    tipo: str = Field(..., min_length=2, max_length=4)
    correlativo: int = Field(0, ge=0)
    cod_cliente: str = Field(..., min_length=3, max_length=3)
    nombre_propuesta: str = Field(..., min_length=1, max_length=100)
    sponsor: Optional[str] = Field(None, max_length=100)
    tiempo_estimado: Optional[float] = None
    estado: str = Field(..., min_length=1, max_length=10)
    usuario_id: Optional[int] = None

class PropuestaOut(BaseModel):
    id: int
    anio: Optional[str] = None
    tipo: Optional[str] = None
    correlativo: Optional[int] = None
    cod_cliente: Optional[str] = None
    nombre_propuesta: Optional[str] = None
    sponsor: Optional[str] = None
    tiempo_estimado: Optional[float] = None
    estado: Optional[str] = None
    fecha_estado: Optional[date] = None
    usuario_id: Optional[int] = None
    eliminado: Optional[bool] = False

class ProyectoIn(BaseModel):
    propuesta_id: int
    fecha_inicio: date
    fecha_termino: date
    tipo_facturacion: str
    estado: str
    fecha_estado: date
    jp_cliente: Optional[str] = None

class ProyectoOut(ProyectoIn):
    id: int
    anio: Optional[str] = None              
    nombre_propuesta: Optional[str] = None
    eliminado: Optional[bool] = False

class EquipoIn(BaseModel):
    proyecto_id: int
    rol: str
    dedicacion: float
    fecha_desde: datetime
    fecha_hasta: datetime
    comentario: Optional[str]

class EquipoOut(EquipoIn):
    id: int

# ====== CAMBIO: AvanceIn SIN "estado" ======
class AvanceIn(BaseModel):
    proyecto_id: int
    fecha: date
    hito_pago: bool
    comentario: Optional[str]

class AvanceOut(AvanceIn):
    id: int
    estado: str
    usuario_id: Optional[int] = None

class FacturaIn(BaseModel):
    proyecto_id: int
    fecha: datetime
    hito: str
    estado: str
    fecha_estado: datetime

class FacturaOut(FacturaIn):
    id: int


def build_nombre_compuesto(anio: str, tipo: str, correlativo: int, cod: str) -> str:
    t = (tipo or "").strip().upper()
    c = (cod or "").strip().upper()
    corr = int(correlativo or 0)
    return f"PROP_{anio}_{t}_{corr:04d}_{c}"

# ======================
# APP EVENTS
# ======================
@app.on_event("startup")
async def startup():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL no configurada")
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ======================
# AUTH HELPERS
# ======================
async def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    user = await database.fetch_one(
        "SELECT * FROM usuario WHERE username = :u",
        values={"u": username},
    )
    if user is None or not user["activo"]:
        raise HTTPException(status_code=401, detail="Usuario no autorizado")
    return dict(user)

# ======================
# LOGIN / USUARIOS
# ======================
@app.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await database.fetch_one(
        "SELECT * FROM usuario WHERE username = :u",
        values={"u": form_data.username},
    )
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if not bcrypt.checkpw(form_data.password.encode("utf-8"), user["password"].encode("utf-8")):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": user["username"], "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/cambiar_password")
async def cambiar_password(datos: PasswordChange, usuario_actual=Depends(obtener_usuario_actual)):
    hashed = bcrypt.hashpw(datos.nueva_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    await database.execute(
        "UPDATE usuario SET password = :p WHERE username = :u",
        values={"p": hashed, "u": usuario_actual["username"]},
    )
    return {"mensaje": "Contraseña actualizada correctamente"}

@app.post("/usuarios/", response_model=UsuarioOut)
async def crear_usuario(usuario: UsuarioIn):
    hashed = bcrypt.hashpw(usuario.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    q = """
        INSERT INTO usuario (username, password, activo, email, fono)
        VALUES (:username, :password, :activo, :email, :fono)
        RETURNING id, username, password, activo, email, fono
    """
    values = {**usuario.dict(), "password": hashed}
    r = await database.fetch_one(q, values=values)
    return {**dict(r), "fono": r["fono"].strip()}

@app.get("/usuarios/", response_model=list[UsuarioOut])
async def listar_usuarios(usuario_actual=Depends(obtener_usuario_actual)):
    rows = await database.fetch_all("SELECT * FROM usuario")
    return [{**dict(r), "fono": r["fono"].strip()} for r in rows]

@app.delete("/usuarios/{usuario_id}")
async def eliminar_usuario(usuario_id: int, usuario_actual=Depends(obtener_usuario_actual)):
    r = await database.fetch_one("DELETE FROM usuario WHERE id = :id RETURNING id", values={"id": usuario_id})
    if not r:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"mensaje": "Usuario eliminado"}

# ======================
# PROPUESTAS
# ======================
@app.post("/propuestas/", response_model=PropuestaOut)
async def crear_propuesta(p: PropuestaIn):
    p_tipo = (p.tipo or "").strip().upper()
    p_cod  = (p.cod_cliente or "").strip().upper()
    p_estado = (p.estado or "").strip().upper()

    correlativo = p.correlativo
    if correlativo is None or correlativo == 0:
        row_next = await database.fetch_one(
            """
            SELECT COALESCE(MAX(correlativo), 0) + 1 AS next
              FROM propuesta
             WHERE rtrim("año") = :anio AND rtrim(tipo) = :tipo
            """,
            values={"anio": p.anio, "tipo": p_tipo},
        )
        correlativo = int(row_next["next"])

    nombre = build_nombre_compuesto(p.anio, p_tipo, correlativo, p_cod)

    values = {
        "anio": p.anio,
        "tipo": p_tipo,
        "correlativo": correlativo,
        "cod_cliente": p_cod,
        "nombre_propuesta": nombre,             
        "sponsor": p.sponsor,
        "tiempo_estimado": p.tiempo_estimado,
        "estado": p_estado,
        "usuario_id": p.usuario_id,
    }

    q = """
        INSERT INTO propuesta ("año", tipo, correlativo, cod_cliente, nombre_propuesta, sponsor,
                               tiempo_estimado, estado, fecha_estado, usuario_id)
        VALUES (:anio, :tipo, :correlativo, :cod_cliente, :nombre_propuesta, :sponsor,
                :tiempo_estimado, :estado, CURRENT_DATE, :usuario_id)
        RETURNING
            id,
            rtrim("año")       AS anio,
            rtrim(tipo)        AS tipo,
            correlativo,
            rtrim(cod_cliente) AS cod_cliente,
            nombre_propuesta,
            sponsor,
            tiempo_estimado,
            rtrim(estado)      AS estado,
            fecha_estado,
            usuario_id
    """
    row = await database.fetch_one(q, values=values)
    return dict(row)


@app.get("/propuestas/", response_model=list[PropuestaOut])
async def listar_propuestas(incluir_eliminado: bool = Query(False)):
    filtro = "" if incluir_eliminado else "WHERE rtrim(p.estado) <> 'ELIMINADO'"
    rows = await database.fetch_all(f"""
        SELECT
          p.id,
          rtrim(p."año")       AS anio,
          rtrim(p.tipo)        AS tipo,
          p.correlativo,
          rtrim(p.cod_cliente) AS cod_cliente,
          p.nombre_propuesta,
          p.sponsor,
          p.tiempo_estimado,
          rtrim(p.estado)      AS estado,
          p.fecha_estado,
          p.usuario_id,
          CASE WHEN rtrim(p.estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM propuesta p
        {filtro}
        ORDER BY p.id DESC
    """)
    return [dict(r) for r in rows]

@app.patch("/propuestas/{propuesta_id}", response_model=PropuestaOut)
async def patch_propuesta(propuesta_id: int, body: dict = Body(...)):
    allowed = {
        "anio", "tipo", "correlativo", "cod_cliente", "nombre_propuesta",
        "sponsor", "tiempo_estimado", "estado", "usuario_id"
    }
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    if "estado" in data and isinstance(data["estado"], str):
        data["estado"] = data["estado"].strip().upper()

    if "tipo" in data and isinstance(data["tipo"], str):
        data["tipo"] = data["tipo"].strip().upper()
    if "cod_cliente" in data and isinstance(data["cod_cliente"], str):
        data["cod_cliente"] = data["cod_cliente"].strip().upper()

    # Trae valores actuales para poder recalcular
    actual = await database.fetch_one(
        """
        SELECT rtrim("año") AS anio, rtrim(tipo) AS tipo, correlativo, rtrim(cod_cliente) AS cod_cliente
          FROM propuesta
         WHERE id = :id
        """,
        values={"id": propuesta_id},
    )
    if not actual:
        raise HTTPException(status_code=404, detail="Propuesta no encontrada")

    anio_final        = data.get("anio", actual["anio"])
    tipo_final        = data.get("tipo", actual["tipo"])
    correlativo_final = data.get("correlativo", actual["correlativo"])
    cod_final         = data.get("cod_cliente", actual["cod_cliente"])

    # Si cambian piezas del nombre o no lo mandan, lo recalculamos
    tocaron_partes = any(k in data for k in ("anio","tipo","correlativo","cod_cliente"))
    if tocaron_partes or "nombre_propuesta" not in data:
        data["nombre_propuesta"] = build_nombre_compuesto(
            anio_final, tipo_final, int(correlativo_final), cod_final
        )

    set_parts, vals = [], {"id": propuesta_id}
    for k, v in data.items():
        if k == "anio":
            set_parts.append('"año" = :anio')
            vals["anio"] = v
        else:
            set_parts.append(f"{k} = :{k}")
            vals[k] = v

    if "estado" in data and "fecha_estado" not in data:
        set_parts.append("fecha_estado = CURRENT_DATE")

    q = f"""
        UPDATE propuesta
           SET {", ".join(set_parts)}
         WHERE id = :id
        RETURNING
          id, rtrim("año") AS anio, rtrim(tipo) AS tipo, correlativo,
          rtrim(cod_cliente) AS cod_cliente, nombre_propuesta, sponsor,
          tiempo_estimado, rtrim(estado) AS estado, fecha_estado, usuario_id,
          CASE WHEN rtrim(estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
    """
    row = await database.fetch_one(q, values=vals)
    if not row:
        raise HTTPException(status_code=404, detail="Propuesta no encontrada")
    return dict(row)


@app.delete("/propuestas/{propuesta_id}")
async def eliminar_propuesta(propuesta_id: int):
    r = await database.fetch_one("""
        UPDATE propuesta
           SET estado = 'ELIMINADO', fecha_estado = CURRENT_DATE
         WHERE id = :id AND rtrim(estado) <> 'ELIMINADO'
     RETURNING id
    """, values={"id": propuesta_id})
    if not r:
        raise HTTPException(status_code=404, detail="Propuesta no encontrada o ya eliminada")
    return {"mensaje": "Propuesta eliminada"}

# ======================
# PARÁMETROS
# ======================
@app.get("/parametros/{tipo}")
async def listar_parametros(tipo: str):
    rows = await database.fetch_all(
        """
        SELECT rtrim(codigo) AS codigo, valor
          FROM parametro
         WHERE rtrim(tipo) = :tipo
         ORDER BY valor
        """,
        values={"tipo": tipo},
    )
    return [{"codigo": r["codigo"], "valor": r["valor"]} for r in rows]

# ======================
# PROYECTOS
# ======================
@app.post("/proyectos/", response_model=ProyectoOut)
async def crear_proyecto(p: ProyectoIn):
    # Insertamos y obtenemos el id
    ins = await database.fetch_one(
        """
        INSERT INTO proyecto
            (propuesta_id, fecha_inicio, fecha_termino, tipo_facturacion, estado, fecha_estado, jp_cliente)
        VALUES
            (:propuesta_id, :fecha_inicio, :fecha_termino, :tipo_facturacion, :estado, :fecha_estado, :jp_cliente)
        RETURNING id
        """,
        values={**p.dict(), "estado": p.estado.strip().upper()},
    )

    # Devolvemos el proyecto recién creado con anio y nombre_propuesta desde propuesta
    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          p.nombre_propuesta         AS nombre_propuesta,
          pr.fecha_inicio,
          pr.fecha_termino,
          rtrim(pr.tipo_facturacion) AS tipo_facturacion,
          rtrim(pr.estado)           AS estado,
          pr.fecha_estado,
          pr.jp_cliente,
          CASE WHEN rtrim(pr.estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM proyecto pr
        JOIN propuesta p ON p.id = pr.propuesta_id
        WHERE pr.id = :id
        """,
        values={"id": ins["id"]},
    )
    return dict(row)


@app.get("/proyectos/", response_model=list[ProyectoOut])
async def listar_proyectos(
    incluir_eliminado: bool = Query(False),
    solo_mios: bool = Query(False),
    usuario_actual = Depends(obtener_usuario_actual),
):
    filtros = []
    vals: dict = {}

    if not incluir_eliminado:
        filtros.append("rtrim(pr.estado) <> 'ELIMINADO'")

    if solo_mios:
        filtros.append(
            "("
            "COALESCE(pr.usuario_id, 0) = :mi_id "
            "OR LOWER(rtrim(COALESCE(pr.jp_cliente, ''))) = LOWER(:mi_nombre)"
            ")"
        )
        vals["mi_id"] = usuario_actual["id"]
        vals["mi_nombre"] = usuario_actual["username"].strip()

    where_sql = ("WHERE " + " AND ".join(filtros)) if filtros else ""

    q = f"""
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          p.nombre_propuesta         AS nombre_propuesta,
          pr.fecha_inicio,
          pr.fecha_termino,
          rtrim(pr.tipo_facturacion) AS tipo_facturacion,
          rtrim(pr.estado)           AS estado,
          pr.fecha_estado,
          pr.jp_cliente,
          COALESCE(pr.usuario_id, 0) AS usuario_id,
          CASE WHEN rtrim(pr.estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM proyecto pr
        JOIN propuesta p ON p.id = pr.propuesta_id
        {where_sql}
        ORDER BY pr.id DESC
    """
    rows = await database.fetch_all(q, values=vals)
    return [dict(r) for r in rows]


@app.get("/proyectos/{proyecto_id}", response_model=ProyectoOut)
async def obtener_proyecto(proyecto_id: int):
    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          p.nombre_propuesta         AS nombre_propuesta,
          pr.fecha_inicio,
          pr.fecha_termino,
          rtrim(pr.tipo_facturacion) AS tipo_facturacion,
          rtrim(pr.estado)           AS estado,
          pr.fecha_estado,
          pr.jp_cliente,
          CASE WHEN rtrim(pr.estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM proyecto pr
        JOIN propuesta p ON p.id = pr.propuesta_id
        WHERE pr.id = :id
        """,
        values={"id": proyecto_id},
    )
    if not row:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    return dict(row)

@app.patch("/proyectos/{proyecto_id}", response_model=ProyectoOut)
async def patch_proyecto(proyecto_id: int, body: dict = Body(...)):
    allowed = {
        "propuesta_id", "fecha_inicio", "fecha_termino",
        "tipo_facturacion", "estado", "fecha_estado", "jp_cliente"
    }
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    if "estado" in data and isinstance(data["estado"], str):
        data["estado"] = data["estado"].strip().upper()

    set_parts, vals = [], {"id": proyecto_id}
    for k, v in data.items():
        set_parts.append(f"{k} = :{k}")
        vals[k] = v
    if "estado" in data and "fecha_estado" not in data:
        set_parts.append("fecha_estado = CURRENT_DATE")

    # Ejecuta UPDATE
    updated = await database.fetch_one(
        f"""
        UPDATE proyecto
           SET {", ".join(set_parts)}
         WHERE id = :id
        RETURNING id
        """,
        values=vals,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    # Devuelve con JOIN
    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          p.nombre_propuesta         AS nombre_propuesta,
          pr.fecha_inicio,
          pr.fecha_termino,
          rtrim(pr.tipo_facturacion) AS tipo_facturacion,
          rtrim(pr.estado)           AS estado,
          pr.fecha_estado,
          pr.jp_cliente,
          CASE WHEN rtrim(pr.estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM proyecto pr
        JOIN propuesta p ON p.id = pr.propuesta_id
        WHERE pr.id = :id
        """,
        values={"id": proyecto_id},
    )
    return dict(row)


@app.delete("/proyectos/{proyecto_id}")
async def eliminar_proyecto(proyecto_id: int):
    r = await database.fetch_one(
        """
        UPDATE proyecto
           SET estado = 'ELIMINADO', fecha_estado = CURRENT_DATE
         WHERE id = :id AND rtrim(estado) <> 'ELIMINADO'
     RETURNING id
        """,
        values={"id": proyecto_id},
    )
    if not r:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado o ya eliminado")
    return {"mensaje": "Proyecto eliminado"}

# ======================
# AVANCES — Estado SIEMPRE = estado del proyecto
# ======================

@app.post("/avances/", response_model=AvanceOut)
async def crear_avance(a: AvanceIn, usuario_actual=Depends(obtener_usuario_actual)):
    proy = await database.fetch_one(
        """
        SELECT id, fecha_inicio, fecha_termino, rtrim(estado) AS estado
          FROM proyecto
         WHERE id = :id AND rtrim(estado) <> 'ELIMINADO'
        """,
        values={"id": a.proyecto_id},
    )
    if not proy:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    if not (proy["fecha_inicio"] <= a.fecha <= proy["fecha_termino"]):
        raise HTTPException(status_code=400, detail="La fecha del avance debe estar dentro del rango del proyecto")

    if a.hito_pago:
        existe_hito = await database.fetch_one(
            """
            SELECT 1 FROM avance
             WHERE proyecto_id = :p AND fecha = :f AND hito_pago = TRUE
            """,
            values={"p": a.proyecto_id, "f": a.fecha},
        )
        if existe_hito:
            raise HTTPException(status_code=400, detail="Ya existe un hito de pago en esa fecha para este proyecto")

    estado_proyecto = (proy["estado"] or "").strip().upper()

    row = await database.fetch_one(
        """
        INSERT INTO avance (proyecto_id, fecha, estado, hito_pago, comentario, usuario_id)
        VALUES (:proyecto_id, :fecha, :estado, :hito_pago, :comentario, :usuario_id)
        RETURNING id, proyecto_id, fecha, rtrim(estado) AS estado, hito_pago, comentario, usuario_id
        """,
        values={
            "proyecto_id": a.proyecto_id,
            "fecha": a.fecha,
            "estado": estado_proyecto,
            "hito_pago": a.hito_pago,
            "comentario": a.comentario,
            "usuario_id": usuario_actual["id"],
        },
    )
    return dict(row)

@app.get("/avances/", response_model=list[AvanceOut])
async def listar_avances(
    proyecto_id: int | None = Query(None),
    solo_mios: bool = Query(False),
    usuario_actual = Depends(obtener_usuario_actual),
):
    condiciones = []
    valores: dict = {}

    if proyecto_id is not None:
        condiciones.append("a.proyecto_id = :p")
        valores["p"] = proyecto_id

    if solo_mios:
        condiciones.append("a.usuario_id = :u")
        valores["u"] = usuario_actual["id"]

    where_sql = "WHERE " + " AND ".join(condiciones) if condiciones else ""

    rows = await database.fetch_all(
        f"""
        SELECT
            a.id,
            a.proyecto_id,
            a.fecha,
            rtrim(p.estado) AS estado,
            a.hito_pago,
            a.comentario,
            a.usuario_id
          FROM avance a
          JOIN proyecto p ON p.id = a.proyecto_id
        {where_sql}
         ORDER BY a.fecha DESC, a.id DESC
        """,
        values=valores,
    )
    return [dict(r) for r in rows]

@app.delete("/avances/{avance_id}")
async def eliminar_avance(avance_id: int):
    r = await database.fetch_one("DELETE FROM avance WHERE id = :id RETURNING id", values={"id": avance_id})
    if not r:
        raise HTTPException(status_code=404, detail="Avance no encontrado")
    return {"mensaje": "Avance eliminado"}

@app.patch("/avances/{avance_id}", response_model=AvanceOut)
async def patch_avance(avance_id: int, body: dict = Body(...)):
    # Ignoramos 'estado' del body; solo permitimos actualizar fecha/hito_pago/comentario
    allowed = {"fecha", "hito_pago", "comentario"}
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    actual = await database.fetch_one(
        """
        SELECT a.proyecto_id
          FROM avance a
         WHERE a.id = :id
        """,
        values={"id": avance_id},
    )
    if not actual:
        raise HTTPException(status_code=404, detail="Avance no encontrado")

    # Estado actual del proyecto
    estado_proyecto = await database.fetch_one(
        'SELECT rtrim(estado) AS estado FROM proyecto WHERE id = :id',
        values={'id': actual["proyecto_id"]},
    )
    if not estado_proyecto:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    set_parts, vals = [], {"id": avance_id}
    for k, v in data.items():
        set_parts.append(f"{k} = :{k}")
        vals[k] = v

    # Reforzar estado del avance = estado del proyecto
    set_parts.append("estado = :estado")
    vals["estado"] = (estado_proyecto["estado"] or "").strip().upper()

    row = await database.fetch_one(
        f"""
        UPDATE avance
           SET {", ".join(set_parts)}
         WHERE id = :id
        RETURNING id, proyecto_id, fecha, rtrim(estado) AS estado, hito_pago, comentario, usuario_id
        """,
        values=vals,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Avance no encontrado")

    return dict(row)

# ======================
# FACTURAS
# ======================
@app.post("/facturas/", response_model=FacturaOut)
async def crear_factura(f: FacturaIn):
    row = await database.fetch_one(
        """
        INSERT INTO factura (proyecto_id, fecha, hito, estado, fecha_estado)
        VALUES (:proyecto_id, :fecha, :hito, :estado, :fecha_estado)
        RETURNING id, proyecto_id, fecha, hito, estado, fecha_estado
        """,
        values=f.dict(),
    )
    return dict(row)

@app.get("/facturas/", response_model=list[FacturaOut])
async def listar_facturas():
    rows = await database.fetch_all(
        "SELECT id, proyecto_id, fecha, hito, estado, fecha_estado FROM factura ORDER BY fecha DESC, id DESC"
    )
    return [dict(r) for r in rows]

@app.delete("/facturas/{factura_id}")
async def eliminar_factura(factura_id: int):
    r = await database.fetch_one("DELETE FROM factura WHERE id = :id RETURNING id", values={"id": factura_id})
    if not r:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    return {"mensaje": "Factura eliminada"}

# ======================
# DOCS (protegidos)
# ======================
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("sub") is None:
        raise HTTPException(status_code=401, detail="Token inválido")
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Documentación protegida")

@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("sub") is None:
        raise HTTPException(status_code=401, detail="Token inválido")
    return JSONResponse(get_openapi(title=app.title, version=app.version, routes=app.routes))

# ======================
# Login Microsoft (placeholder)
# ======================
@app.get("/login-microsoft")
async def login_microsoft(request: Request):
    redirect_uri = os.getenv("MICROSOFT_REDIRECT_URI")
    return await oauth.microsoft.authorize_redirect(request, redirect_uri)

@app.get("/login-microsoft/callback")
async def login_microsoft_callback(request: Request):
    token = await oauth.microsoft.authorize_access_token(request)
    user_info = await oauth.microsoft.parse_id_token(request, token)
    email = user_info.get("email") or user_info.get("preferred_username")
    if not email or not email.endswith("@entersoft.cl"):
        raise HTTPException(status_code=403, detail="Correo no autorizado")
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_jwt = jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    # Ajusta el redirect según tu front en server/localhost:
    frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:4200/login/callback")
    return RedirectResponse(f"{frontend_callback}?token={token_jwt}")
