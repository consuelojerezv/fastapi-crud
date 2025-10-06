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

database = databases.Database(DATABASE_URL)

app = FastAPI(title="Proyecto API")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

ALLOWED_ORIGINS = [
    "http://186.64.122.150",       # dominio por IP que causa el error
    "http://proyectos.edu",
    "http://www.proyectos.edu",
    "http://localhost:4200",
    "http://127.0.0.1:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
print("🔹 CORS habilitado para:", ALLOWED_ORIGINS)



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
    correlativo: int = Field(0, ge=0)  # ignorado al crear; el back lo calcula
    cod_cliente: str = Field(..., min_length=3, max_length=3)
    nombre_propuesta: str = Field(..., min_length=1, max_length=100)  # descripción libre
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
    nombre_propuesta: Optional[str] = None   # descripción libre
    sponsor: Optional[str] = None
    tiempo_estimado: Optional[float] = None
    estado: Optional[str] = None
    fecha_estado: Optional[date] = None
    usuario_id: Optional[int] = None
    eliminado: Optional[bool] = False
    # virtual (no existe en BD): nombre auto-generado para mostrar
    nombre_auto: Optional[str] = None

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
    nombre_auto: Optional[str] = None  

class EquipoIn(BaseModel):
    proyecto_id: int
    usuario_id: int
    rol: str
    dedicacion: float
    fecha_desde: date
    fecha_hasta: date
    comentario: Optional[str] = None

class EquipoOut(EquipoIn):
    id: int
    usuario_nombre: Optional[str] = None

class AvanceIn(BaseModel):
    proyecto_id: int
    fecha: date
    comentario: Optional[str]
    hito: Optional[int] = Field(None, ge=0, le=4)  # 0..4

class AvanceOut(AvanceIn):
    id: int
    estado: str
    usuario_id: Optional[int] = None

class FacturaIn(BaseModel):
    proyecto_id: int
    fecha: date
    hito: str = Field(..., max_length=10)
    estado: str = Field(..., max_length=10)
    fecha_estado: date

class FacturaOut(FacturaIn):
    id: int
    usuario_id: int | None = None
    anio: str | None = None 
    nombre_propuesta: str | None = None
    nombre_auto: str | None = None


# ==========
# HELPERS
# ==========
def build_nombre_auto(anio: str | None, tipo: str | None, correlativo: int | None, cod: str | None) -> str:
    a = (anio or "").strip()
    t = (tipo or "").strip().upper()
    c = (cod or "").strip().upper()
    corr = int(correlativo or 0)
    return f"PROP_{a}_{t}_{corr:04d}_{c}"

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
    p_tipo   = (p.tipo or "").strip().upper()
    p_cod    = (p.cod_cliente or "").strip().upper()
    p_estado = (p.estado or "").strip().upper()

    async with database.transaction():
        # 🔒 lock por (anio + cliente)
        await _advisory_lock_por_anio_cliente(p.anio, p_cod)

        # correlativo por (año + cliente)
        row_next = await database.fetch_one(
            """
            SELECT COALESCE(MAX(correlativo), 0) + 1 AS next
              FROM propuesta
             WHERE rtrim("año") = :anio
               AND rtrim(cod_cliente) = :cod
            """,
            values={"anio": p.anio, "cod": p_cod},
        )
        correlativo = int(row_next["next"])

        values = {
            "anio": p.anio,
            "tipo": p_tipo,
            "correlativo": correlativo,
            "cod_cliente": p_cod,
            "nombre_propuesta": (p.nombre_propuesta or "").strip(),  # descripción libre
            "sponsor": p.sponsor,
            "tiempo_estimado": p.tiempo_estimado,
            "estado": p_estado,
            "usuario_id": p.usuario_id,
        }

        row = await database.fetch_one(
            """
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
            """,
            values=values,
        )

    d = dict(row)
    d["eliminado"]  = (d["estado"] == "ELIMINADO")
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    return d


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
          p.usuario_id
        FROM propuesta p
        {filtro}
        ORDER BY p.id DESC
    """)
    out = []
    for r in rows:
        d = dict(r)
        d["eliminado"] = (d["estado"] == "ELIMINADO")
        d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
        out.append(d)
    return out

@app.patch("/propuestas/{propuesta_id}", response_model=PropuestaOut)
async def patch_propuesta(propuesta_id: int, body: dict = Body(...)):
    allowed = {
        "anio", "tipo", "correlativo", "cod_cliente", "nombre_propuesta",
        "sponsor", "tiempo_estimado", "estado", "usuario_id"
    }
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    # normalizaciones
    if "estado" in data and isinstance(data["estado"], str):
        data["estado"] = data["estado"].strip().upper()
    if "tipo" in data and isinstance(data["tipo"], str):
        data["tipo"] = data["tipo"].strip().upper()
    if "cod_cliente" in data and isinstance(data["cod_cliente"], str):
        data["cod_cliente"] = data["cod_cliente"].strip().upper()
    if "nombre_propuesta" in data and isinstance(data["nombre_propuesta"], str):
        data["nombre_propuesta"] = data["nombre_propuesta"].strip()

    # Trae actual para comparar (anio/cod_cliente)
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

    nuevo_anio = data.get("anio", actual["anio"])
    nuevo_cod  = data.get("cod_cliente", actual["cod_cliente"])

    async with database.transaction():
        # Si cambian (anio o cod_cliente) y NO mandaron correlativo, recalcúlalo automáticamente
        if (("anio" in data) or ("cod_cliente" in data)) and ("correlativo" not in data):
            await _advisory_lock_por_anio_cliente(nuevo_anio, nuevo_cod)
            row_next = await database.fetch_one(
                """
                SELECT COALESCE(MAX(correlativo), 0) + 1 AS next
                  FROM propuesta
                 WHERE rtrim("año") = :anio
                   AND rtrim(cod_cliente) = :cod
                """,
                values={"anio": nuevo_anio, "cod": nuevo_cod},
            )
            data["correlativo"] = int(row_next["next"])

        # Construye UPDATE dinámico
        set_parts, vals = [], {"id": propuesta_id}
        for k, v in data.items():
            if k == "anio":
                set_parts.append('"año" = :anio'); vals["anio"] = v
            else:
                set_parts.append(f"{k} = :{k}"); vals[k] = v
        if "estado" in data and "fecha_estado" not in data:
            set_parts.append("fecha_estado = CURRENT_DATE")

        row = await database.fetch_one(
            f"""
            UPDATE propuesta
               SET {", ".join(set_parts)}
             WHERE id = :id
            RETURNING
              id, rtrim("año") AS anio, rtrim(tipo) AS tipo, correlativo,
              rtrim(cod_cliente) AS cod_cliente, nombre_propuesta, sponsor,
              tiempo_estimado, rtrim(estado) AS estado, fecha_estado, usuario_id
            """,
            values=vals,
        )

    d = dict(row)
    d["eliminado"]  = (d["estado"] == "ELIMINADO")
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    return d


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

async def _advisory_lock_por_anio_cliente(anio: str, cod: str):
    """Bloquea concurrentemente el cálculo de correlativo por (anio, cod_cliente)."""
    await database.fetch_one(
        """
        SELECT pg_advisory_xact_lock(
            hashtext(CONCAT(:anio, ':', :cod))
        )
        """,
        values={"anio": anio, "cod": cod},
    )

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

    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          rtrim(p.tipo)              AS tipo,   --- para nombre_auto
          p.correlativo             AS correlativo,  --- para nombre_auto
          rtrim(p.cod_cliente)      AS cod_cliente, --- para nombre_auto
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
    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

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
          rtrim(p.tipo)              AS tipo,   
          p.correlativo        AS correlativo,
          rtrim(p.cod_cliente)      AS cod_cliente,
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
    out = []
    for r in rows:
        d = dict(r)
        d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
        for k in ("tipo", "correlativo", "cod_cliente"):
            d.pop(k, None)
        out.append(d)
    return out

@app.get("/proyectos/{proyecto_id}", response_model=ProyectoOut)
async def obtener_proyecto(proyecto_id: int):
    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          rtrim(p.tipo)              AS tipo,
          p.correlativo        AS correlativo,
          rtrim(p.cod_cliente)      AS cod_cliente,
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
    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

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

    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          rtrim(p."año")             AS anio,
          rtrim(p.tipo)              AS tipo,
          p.correlativo        AS correlativo,
          rtrim(p.cod_cliente)      AS cod_cliente,
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
    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

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

# =====================================================
# HITOS & FACTURAS: helper para crear/actualizar factura
# =====================================================
HITO_MAP = {
    0: "ANALI",  # Término Análisis (DDT)
    1: "DESAR",  # Término Desarrollo
    2: "QA",     # Término QA
    3: "GARAN",  # Garantía
    4: "DOCUM",  # Documentación
}

async def _upsert_factura_por_hito(
    proyecto_id: int,
    fecha_avance: date,
    hito_code: int | None,
    usuario_id: int | None,
):
    if hito_code is None:
        return
    if hito_code not in HITO_MAP:
        return

    hito_txt = HITO_MAP[hito_code]

    exist = await database.fetch_one(
        """
        SELECT id FROM factura
         WHERE proyecto_id = :p AND rtrim(hito) = :h
        """,
        values={"p": proyecto_id, "h": hito_txt},
    )
    if exist:
        await database.fetch_one(
            """
            UPDATE factura
               SET fecha = :f,
                   fecha_estado = :f
             WHERE id = :id
         RETURNING id
            """,
            values={"id": exist["id"], "f": fecha_avance},
        )
    else:
        await database.fetch_one(
            """
            INSERT INTO factura (proyecto_id, fecha, hito, estado, fecha_estado, usuario_id)
            VALUES (:p, :f, :h, 'PENDIENTE', :f, :u)
        RETURNING id
            """,
            values={
                "p": proyecto_id,
                "f": fecha_avance,
                "h": hito_txt,
                "u": usuario_id,
            },
        )

# ======================
# AVANCES
# ======================
@app.post("/avances/", response_model=AvanceOut)
async def crear_avance(a: AvanceIn, usuario_actual=Depends(obtener_usuario_actual)):
    proy = await database.fetch_one(
        "SELECT id, fecha_inicio, fecha_termino, rtrim(estado) AS estado "
        "FROM proyecto WHERE id = :id AND rtrim(estado) <> 'ELIMINADO'",
        values={"id": a.proyecto_id},
    )
    if not proy:
        raise HTTPException(404, "Proyecto no encontrado")

    if not (proy["fecha_inicio"] <= a.fecha <= proy["fecha_termino"]):
        raise HTTPException(400, "La fecha del avance debe estar dentro del rango del proyecto")

    estado_proyecto = (proy["estado"] or "").strip().upper()

    row = await database.fetch_one(
        """
        INSERT INTO avance (proyecto_id, fecha, estado, comentario, hito, usuario_id)
        VALUES (:proyecto_id, :fecha, :estado, :comentario, :hito, :usuario_id)
        RETURNING id, proyecto_id, fecha, rtrim(estado) AS estado, comentario, hito, usuario_id
        """,
        values={
            "proyecto_id": a.proyecto_id,
            "fecha": a.fecha,
            "estado": estado_proyecto,  # espejo del proyecto
            "comentario": a.comentario,
            "hito": a.hito,
            "usuario_id": usuario_actual["id"],
        },
    )

    await _upsert_factura_por_hito(a.proyecto_id, a.fecha, a.hito, usuario_actual["id"])

    return dict(row)

@app.get("/avances/", response_model=list[AvanceOut])
async def listar_avances(
    proyecto_id: int | None = Query(None),
    solo_mios: bool = Query(False),
    usuario_actual = Depends(obtener_usuario_actual),
):
    condiciones, valores = [], {}
    if proyecto_id is not None:
        condiciones.append("a.proyecto_id = :p")
        valores["p"] = proyecto_id
    if solo_mios:
        condiciones.append("a.usuario_id = :u")
        valores["u"] = usuario_actual["id"]

    where_sql = "WHERE " + " AND ".join(condiciones) if condiciones else ""
    rows = await database.fetch_all(
        f"""
        SELECT a.id, a.proyecto_id, a.fecha, rtrim(p.estado) AS estado,
               a.comentario, a.hito, a.usuario_id
          FROM avance a
          JOIN proyecto p ON p.id = a.proyecto_id
        {where_sql}
         ORDER BY a.fecha DESC, a.id DESC
        """,
        values=valores,
    )
    return [dict(r) for r in rows]

@app.patch("/avances/{avance_id}", response_model=AvanceOut)
async def patch_avance(avance_id: int, body: dict = Body(...), usuario_actual=Depends(obtener_usuario_actual)):
    allowed = {"fecha", "comentario", "hito"}
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(400, "Nada para actualizar")

    actual = await database.fetch_one(
        "SELECT proyecto_id, fecha, hito FROM avance WHERE id = :id",
        values={"id": avance_id},
    )
    if not actual:
        raise HTTPException(404, "Avance no encontrado")

    # Normaliza fecha si viene como string
    if "fecha" in data and isinstance(data["fecha"], str):
        data["fecha"] = date.fromisoformat(data["fecha"])

    estado_proyecto = await database.fetch_one(
        "SELECT rtrim(estado) AS estado FROM proyecto WHERE id = :id",
        values={"id": actual["proyecto_id"]},
    )
    if not estado_proyecto:
        raise HTTPException(404, "Proyecto no encontrado")

    set_parts = [f"{k} = :{k}" for k in data.keys()]
    vals = {"id": avance_id, **data, "estado": (estado_proyecto["estado"] or "").strip().upper()}
    set_parts.append("estado = :estado")

    row = await database.fetch_one(
        f"""
        UPDATE avance
           SET {", ".join(set_parts)}
         WHERE id = :id
        RETURNING id, proyecto_id, fecha, rtrim(estado) AS estado, comentario, hito, usuario_id
        """,
        values=vals,
    )
    if not row:
        raise HTTPException(404, "Avance no encontrado")

    # Upsert factura si hay/cambió hito o fecha
    nuevo_hito = data.get("hito", row["hito"])
    nueva_fecha = data.get("fecha", row["fecha"])
    await _upsert_factura_por_hito(row["proyecto_id"], nueva_fecha, nuevo_hito, usuario_actual["id"])

    return dict(row)

@app.delete("/avances/{avance_id}")
async def eliminar_avance(avance_id: int):
    r = await database.fetch_one("DELETE FROM avance WHERE id = :id RETURNING id", values={"id": avance_id})
    if not r:
        raise HTTPException(status_code=404, detail="Avance no encontrado")
    return {"mensaje": "Avance eliminado"}

# ======================
# EQUIPOS
# ======================
async def _validar_equipo_basico(e: EquipoIn | dict, equipo_id: int | None = None):
    proy = await database.fetch_one(
        'SELECT id, fecha_inicio, fecha_termino FROM proyecto WHERE id = :id AND rtrim(estado) <> \'ELIMINADO\'',
        values={'id': e["proyecto_id"] if isinstance(e, dict) else e.proyecto_id},
    )
    if not proy:
        raise HTTPException(404, "Proyecto no encontrado")

    fd = e["fecha_desde"] if isinstance(e, dict) else e.fecha_desde
    fh = e["fecha_hasta"] if isinstance(e, dict) else e.fecha_hasta
    if fd > fh:
        raise HTTPException(400, "fecha_desde no puede ser mayor que fecha_hasta")
    if not (proy["fecha_inicio"] <= fd <= proy["fecha_termino"]) or not (proy["fecha_inicio"] <= fh <= proy["fecha_termino"]):
        raise HTTPException(400, "Las fechas deben estar dentro del rango del proyecto")

    usuario_id = e["usuario_id"] if isinstance(e, dict) else e.usuario_id
    proyecto_id = e["proyecto_id"] if isinstance(e, dict) else e.proyecto_id
    dedicacion = e["dedicacion"] if isinstance(e, dict) else e.dedicacion

    row = await database.fetch_one(
        """
        SELECT COALESCE(SUM(dedicacion),0) AS total
          FROM equipo
         WHERE usuario_id = :u
           AND proyecto_id = :p
           AND NOT (fecha_hasta < :desde OR fecha_desde > :hasta)
           AND id <> COALESCE(:id, -1)
        """,
        values={"u": usuario_id, "p": proyecto_id, "desde": fd, "hasta": fh, "id": equipo_id},
    )
    total = float(row["total"] or 0.0)
    if total + float(dedicacion) > 100.0 + 1e-6:
        raise HTTPException(400, f"El usuario ya acumula {total:.0f}% en ese período; no puede superar 100%.")
    return True

@app.post("/equipos/", response_model=EquipoOut)
async def crear_equipo(e: EquipoIn, usuario_actual=Depends(obtener_usuario_actual)):
    if not (0 <= e.dedicacion <= 100):
        raise HTTPException(status_code=400, detail="La dedicación debe ser entre 0 y 100")
    if e.fecha_desde > e.fecha_hasta:
        raise HTTPException(status_code=400, detail="La fecha_desde no puede ser mayor a fecha_hasta")

    proy = await database.fetch_one(
        'SELECT id FROM proyecto WHERE id = :id AND rtrim(estado) <> \'ELIMINADO\'',
        values={'id': e.proyecto_id},
    )
    if not proy:
        raise HTTPException(status_code=404, detail="Proyecto no existe o está eliminado")

    usu = await database.fetch_one('SELECT id FROM usuario WHERE id = :id', values={'id': e.usuario_id})
    if not usu:
        raise HTTPException(status_code=404, detail="Usuario no existe")

    total = await database.fetch_one(
        """
        SELECT COALESCE(SUM(dedicacion), 0) AS total
          FROM equipo
         WHERE proyecto_id = :p
           AND usuario_id  = :u
           AND NOT (:hasta < fecha_desde OR :desde > fecha_hasta)
        """,
        values={'p': e.proyecto_id, 'u': e.usuario_id, 'desde': e.fecha_desde, 'hasta': e.fecha_hasta},
    )
    if float(total["total"]) + e.dedicacion > 100:
        raise HTTPException(status_code=400, detail="La dedicación acumulada superaría 100% en el período")

    row = await database.fetch_one(
        """
        INSERT INTO equipo (proyecto_id, rol, dedicacion, fecha_desde, fecha_hasta, comentario, usuario_id)
        VALUES (:proyecto_id, :rol, :dedicacion, :fecha_desde, :fecha_hasta, :comentario, :usuario_id)
        RETURNING id, proyecto_id, rol, dedicacion, fecha_desde, fecha_hasta, comentario, usuario_id
        """,
        values=e.dict(),
    )
    return dict(row)

@app.get("/equipos/", response_model=list[EquipoOut])
async def listar_equipos(proyecto_id: int = Query(...)):
    rows = await database.fetch_all(
        """
        SELECT e.id, e.proyecto_id, e.usuario_id, u.username AS usuario_nombre,
               rtrim(e.rol) AS rol, e.dedicacion, e.fecha_desde, e.fecha_hasta, e.comentario
          FROM equipo e
          JOIN usuario u ON u.id = e.usuario_id
         WHERE e.proyecto_id = :p
         ORDER BY e.fecha_desde, e.id
        """,
        values={"p": proyecto_id},
    )
    return [dict(r) for r in rows]

@app.patch("/equipos/{equipo_id}", response_model=EquipoOut)
async def patch_equipo(equipo_id: int, body: dict = Body(...)):
    allowed = {"rol","dedicacion","fecha_desde","fecha_hasta","comentario","usuario_id"}
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    actual = await database.fetch_one("SELECT * FROM equipo WHERE id = :id", values={"id": equipo_id})
    if not actual:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")

    rol           = data.get("rol", actual["rol"])
    dedicacion    = float(data.get("dedicacion", actual["dedicacion"]))
    fecha_desde   = data.get("fecha_desde", actual["fecha_desde"])
    fecha_hasta   = data.get("fecha_hasta", actual["fecha_hasta"])
    usuario_id    = data.get("usuario_id", actual["usuario_id"])
    proyecto_id   = actual["proyecto_id"]

    if not (0 <= dedicacion <= 100):
        raise HTTPException(status_code=400, detail="La dedicación debe ser entre 0 y 100")
    if fecha_desde > fecha_hasta:
        raise HTTPException(status_code=400, detail="La fecha_desde no puede ser mayor a fecha_hasta")

    if usuario_id != actual["usuario_id"]:
        exist = await database.fetch_one('SELECT id FROM usuario WHERE id = :id', values={'id': usuario_id})
        if not exist:
            raise HTTPException(status_code=404, detail="Usuario no existe")

    total = await database.fetch_one(
        """
        SELECT COALESCE(SUM(dedicacion), 0) AS total
          FROM equipo
         WHERE proyecto_id = :p
           AND usuario_id  = :u
           AND id <> :id
           AND NOT (:hasta < fecha_desde OR :desde > fecha_hasta)
        """,
        values={'p': proyecto_id, 'u': usuario_id, 'id': equipo_id, 'desde': fecha_desde, 'hasta': fecha_hasta},
    )
    if float(total["total"]) + dedicacion > 100:
        raise HTTPException(status_code=400, detail="La dedicación acumulada superaría 100% en el período")

    row = await database.fetch_one(
        """
        UPDATE equipo
           SET rol = :rol,
               dedicacion = :dedicacion,
               fecha_desde = :desde,
               fecha_hasta = :hasta,
               comentario = :comentario,
               usuario_id = :usuario_id
         WHERE id = :id
        RETURNING id, proyecto_id, rol, dedicacion, fecha_desde, fecha_hasta, comentario, usuario_id
        """,
        values={
            "id": equipo_id, "rol": rol, "dedicacion": dedicacion,
            "desde": fecha_desde, "hasta": fecha_hasta,
            "comentario": data.get("comentario", actual["comentario"]),
            "usuario_id": usuario_id,
        },
    )
    return dict(row)

@app.delete("/equipos/{equipo_id}")
async def eliminar_equipo(equipo_id: int):
    r = await database.fetch_one("DELETE FROM equipo WHERE id = :id RETURNING id", values={"id": equipo_id})
    if not r:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    return {"mensaje": "Equipo eliminado"}

# ======================
# FACTURAS
# ======================
@app.post("/facturas/", response_model=FacturaOut)
async def crear_factura(
    f: FacturaIn,
    usuario_actual = Depends(obtener_usuario_actual)  # si ya lo usas en otros endpoints
):
    # normalizaciones a MAYÚSCULAS (opcional, siguiendo tu estilo)
    hito_upper   = f.hito.strip().upper()
    estado_upper = f.estado.strip().upper()

    ins = await database.fetch_one("""
        INSERT INTO factura
            (proyecto_id, fecha, hito, estado, fecha_estado, usuario_id)
        VALUES
            (:proyecto_id, :fecha, :hito, :estado, :fecha_estado, :usuario_id)
        RETURNING id
    """, values={
        "proyecto_id": f.proyecto_id,
        "fecha": f.fecha,
        "hito": hito_upper,
        "estado": estado_upper,
        "fecha_estado": f.fecha_estado,
        "usuario_id": usuario_actual["id"] if usuario_actual else None
    })

    row = await database.fetch_one("""
        SELECT
          f.id,
          f.proyecto_id,
          f.fecha,
          rtrim(f.hito)   AS hito,
          rtrim(f.estado) AS estado,
          f.fecha_estado,
          f.usuario_id,

          rtrim(p."año")        AS anio,
          p.nombre_propuesta    AS nombre_propuesta,
          rtrim(p.tipo)         AS tipo,
          p.correlativo         AS correlativo,
          rtrim(p.cod_cliente)  AS cod_cliente

        FROM factura f
        JOIN proyecto  pr ON pr.id  = f.proyecto_id
        JOIN propuesta p  ON p.id   = pr.propuesta_id
        WHERE f.id = :id
    """, values={"id": ins["id"]})

    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(
        d.get("anio"), d.get("tipo"), d.get("correlativo"), d.get("cod_cliente")
    )
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

@app.get("/facturas/", response_model=list[FacturaOut])
async def listar_facturas(proyecto_id: int | None = Query(None)):
    where = ""
    vals: dict = {}
    if proyecto_id is not None:
        where = "WHERE f.proyecto_id = :pid"
        vals["pid"] = proyecto_id

    rows = await database.fetch_all(f"""
        SELECT
          f.id,
          f.proyecto_id,
          f.fecha,
          rtrim(f.hito)   AS hito,
          rtrim(f.estado) AS estado,
          f.fecha_estado,
          f.usuario_id,

          -- datos para construir nombre_auto
          rtrim(p."año")        AS anio,
          p.nombre_propuesta    AS nombre_propuesta,
          rtrim(p.tipo)         AS tipo,
          p.correlativo         AS correlativo,
          rtrim(p.cod_cliente)  AS cod_cliente

        FROM factura f
        JOIN proyecto  pr ON pr.id  = f.proyecto_id
        JOIN propuesta p  ON p.id   = pr.propuesta_id
        {where}
        ORDER BY f.fecha DESC, f.id DESC
    """, values=vals)

    out: list[dict] = []
    for r in rows:
        d = dict(r)
        d["nombre_auto"] = build_nombre_auto(
            d.get("anio"), d.get("tipo"), d.get("correlativo"), d.get("cod_cliente")
        )
        # limpiamos helpers internos
        for k in ("tipo", "correlativo", "cod_cliente"):
            d.pop(k, None)
        out.append(d)
    return out

@app.patch("/facturas/{factura_id}", response_model=FacturaOut)
async def patch_factura(factura_id: int, body: dict = Body(...)):
    allowed = {"fecha", "hito", "estado", "fecha_estado"}
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(400, "Nada para actualizar")
    if "hito" in data and isinstance(data["hito"], str):
        data["hito"] = data["hito"].strip().upper()[:10]
    if "estado" in data and isinstance(data["estado"], str):
        data["estado"] = data["estado"].strip().upper()[:10]

    set_parts, vals = [], {"id": factura_id}
    for k, v in data.items():
        set_parts.append(f"{k} = :{k}")
        vals[k] = v

    row = await database.fetch_one(
        f"""UPDATE factura
               SET {", ".join(set_parts)}
             WHERE id = :id
         RETURNING id, proyecto_id, fecha, rtrim(hito) AS hito, rtrim(estado) AS estado,
                   fecha_estado, usuario_id""",
        values=vals
    )
    if not row:
        raise HTTPException(404, "Factura no encontrada")
    return dict(row)

@app.delete("/facturas/{factura_id}")
async def eliminar_factura(factura_id: int):
    r = await database.fetch_one(
        "DELETE FROM factura WHERE id = :id RETURNING id",
        values={"id": factura_id},
    )
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
    frontend_callback = os.getenv("FRONTEND_CALLBACK_URL", "http://localhost:4200/login/callback")
    return RedirectResponse(f"{frontend_callback}?token={token_jwt}")
