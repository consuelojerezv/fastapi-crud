from __future__ import annotations
from typing import Optional, Union, List
from datetime import date, datetime, timedelta
import os
import bcrypt
import databases
from fastapi import FastAPI, HTTPException, Depends, Request, Query, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
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

database = databases.Database(DATABASE_URL)

app = FastAPI(title="Proyecto API")

ALLOWED_ORIGINS = [
    "http://localhost:4200",
    "http://127.0.0.1:4200",
    "http://186.64.122.150:4200",
    "http://186.64.122.150",
    "http://186.64.122.150:8081",
    "http://proyectos.edu",
    "http://proyectos.edu:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Accept"],
    expose_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

EST_PROP_APP2DB = {
    "cotiz": "COT",
    "adju": "ADJ",
    "canc": "CAN",
    "eliminado": "ELI",
    "anul" : "ANUL"
}
EST_PROP_DB2APP = {v: k for k, v in EST_PROP_APP2DB.items()}
# ======================
# OAuth Microsoft (opcional)
# ======================
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

class UsuarioOut(BaseModel):
    id: int
    username: str
    activo: bool
    email: Optional[str] = None
    fono: Optional[str] = None

class UsuarioPatch(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    activo: Optional[bool] = None
    email: Optional[EmailStr] = None
    fono: Optional[str] = Field(None, min_length=8, max_length=15)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class PropuestaIn(BaseModel):
    anio: str
    tipo: str
    correlativo: int = 0
    cod_cliente: str
    nombre_propuesta: str
    sponsor: Optional[str] = None
    tiempo_estimado: Optional[Union[str, float]] = None
    estado: Optional[str] = None
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
    nombre_auto: Optional[str] = None

class PropuestaPatch(BaseModel):
    anio: Optional[str] = None
    tipo: Optional[str] = None
    cod_cliente: Optional[str] = None
    nombre_propuesta: Optional[str] = None
    sponsor: Optional[str] = None
    tiempo_estimado: Optional[Union[str, float]] = None
    estado: Optional[str] = None

class ProyectoIn(BaseModel):
    propuesta_id: int
    fecha_inicio: Optional[date] = None
    fecha_termino: Optional[date] = None
    tipo_facturacion: Optional[str] = None
    fecha_estado: Optional[date] = None
    jp_cliente: Optional[str] = None

class ProyectoOut(BaseModel):
    id: int
    propuesta_id: Optional[int] = None
    fecha_inicio: Optional[date] = None 
    fecha_termino: Optional[date] = None
    tipo_facturacion: Optional[str] = None
    estado: str
    fecha_estado: Optional[date] = None
    jp_cliente: Optional[str] = None
    usuario_id: Optional[int] = None
    eliminado: bool = False
    anio: Optional[str] = None
    nombre_propuesta: Optional[str] = None
    nombre_auto: Optional[str] = None

class EquipoIn(BaseModel):
    proyecto_id: int
    usuario_id: int
    rol: str
    dedicacion: float
    fecha_desde: date
    fecha_hasta: Optional[date] = None
    comentario: Optional[str] = None

class EquipoOut(BaseModel):
    id: int
    proyecto_id: int
    usuario_id: int
    rol: Optional[str] = None       
    dedicacion: float
    fecha_desde: date
    fecha_hasta: Optional[date] = None
    comentario: Optional[str] = None
    usuario_nombre: Optional[str] = None


class AvanceIn(BaseModel):
    proyecto_id: int
    fecha: date
    comentario: Optional[str] = None
    hito: Optional[int] = None         
    estado: Optional[str] = None      

class AvancePatch(BaseModel):
    fecha: Optional[date] = None
    comentario: Optional[str] = None
    hito: Optional[int] = None
    estado: Optional[str] = None

class AvanceOut(BaseModel):
    id: int
    proyecto_id: int
    fecha: date
    comentario: Optional[str]
    estado: str
    usuario_id: Optional[int]
    hito: Optional[int]


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

class ParametroIn(BaseModel):
    tipo: str = Field(..., max_length=32)
    codigo: str = Field(..., max_length=5)
    valor: str = Field(..., max_length=50)

class ParametroOut(ParametroIn):
    id: int

class UsuarioTecnologiaIn(BaseModel):
    usuario_id: int
    tecnologia_id: int 
    nivel: str = Field(..., max_length=10) 
    vigente: bool = True

class UsuarioTecnologiaOut(BaseModel):
    id: int 
    usuario_id: int
    tecnologia_id: int
    nivel: str
    vigente: bool
    tecnologia_nombre: Optional[str] = None 
    username: Optional[str] = None 

class UsuarioTecnologiaPatch(BaseModel):
    nivel: Optional[str] = Field(None, max_length=10)
    vigente: Optional[bool] = None

class UsuarioRolIn(BaseModel):
    usuario_id: int
    rol_id: int

class UsuarioRolOut(BaseModel):
    id: int
    usuario_id: int
    rol_id: int
    rol_nombre: Optional[str] = None
    username: Optional[str] = None

class UsuarioRolVista(BaseModel):
    usuario_rol_id: int
    usuario_id: int
    username: str
    rol_id: int
    nombre_rol: str

class UsuarioTecnologiaVista(BaseModel):
    usuario_tecnologia_id: int
    usuario_id: int
    username: str
    tecnologia_id: int
    nombre_tecnologia: str
    nivel: str
    vigente: bool

class PasswordChangeRequest(BaseModel):
    password_actual: str = Field(..., min_length=6)
    password_nueva: str = Field(..., min_length=8)

class PasswordChange(BaseModel):
    password_actual: str = Field(..., min_length=6)
    nueva_password: str = Field(..., min_length=6)

# ======================
# HELPERS
# ======================
def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def _norm_upper(s: Optional[str]) -> str:
    return (s or "").strip().upper()

def _norm_lower(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _page_params(page: int, page_size: int) -> tuple[int, int]:
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    return (page_size, (page - 1) * page_size)

def build_nombre_auto(anio: str | None, tipo: str | None, correlativo: int | None, cod: str | None) -> str:
    a = (anio or "").strip()
    t = (tipo or "").strip().upper()
    c = (cod or "").strip().upper()
    corr = int(correlativo or 0)
    return f"{a}_{t}_{corr:04d}_{c}"

def parse_tiempo_half_steps(val: Optional[Union[str, float, int]]) -> Optional[float]:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        f = float(val)
    elif isinstance(val, str):
        s = val.strip()
        if s == "":
            return None
        s = s.replace(",", ".")
        f = float(s)
    else:
        raise ValueError("Tipo inválido para tiempo_estimado")
    if round(f * 2) != f * 2:
        raise ValueError("El tiempo estimado debe ir en incrementos de 0.5")
    return f

async def _advisory_lock_por_anio_cliente(anio: str, cod: str):
    key = f"{int(anio):04d}|{cod.strip().upper()}"
    sql = "SELECT pg_advisory_xact_lock(hashtextextended(:k, 0));"
    await database.fetch_one(sql, values={"k": key})

async def _advisory_lock_param(tipo: str, codigo: str):
    key = f"PARAM|{(tipo or '').strip().upper()}|{(codigo or '').strip().upper()}"
    sql = "SELECT pg_advisory_xact_lock(hashtextextended(:k, 0));"
    await database.fetch_one(sql, values={"k": key})

async def _estado_proyecto_valido(codigo: Optional[str]) -> bool:
    if not codigo:
        return False
    cod = (codigo or "").strip().upper()
    if cod == "COT":
        return False
    row = await database.fetch_one("""
        SELECT 1
          FROM parametro
         WHERE UPPER(rtrim(tipo)) = 'PROY_ESTADO'
           AND UPPER(rtrim(codigo)) = :cod
        LIMIT 1
    """, values={"cod": cod})
    return row is not None

async def normalize_proy_estado_to_code(estado: str | None) -> str | None:
    if not estado:
        return None
    s = (estado or "").strip()

    row = await database.fetch_one("""
        SELECT rtrim(codigo) AS codigo
          FROM parametro
         WHERE UPPER(rtrim(tipo)) = 'PROY_ESTADO'
           AND UPPER(rtrim(codigo)) = UPPER(:s)
         LIMIT 1
    """, {"s": s})
    if row:
        return row["codigo"]
    
    row = await database.fetch_one("""
        SELECT rtrim(codigo) AS codigo
          FROM parametro
         WHERE UPPER(rtrim(tipo)) = 'PROY_ESTADO'
           AND UPPER(rtrim(valor)) = UPPER(:s)
         LIMIT 1
    """, {"s": s})
    return row["codigo"] if row else None

def _pad5(n: int) -> str:
    try:
        return f"{int(n):05d}"
    except Exception:
        return str(n)[:5]

async def _parametro_usuario_upsert(user_id: int, username: str):
    tipo = "USUARIO"
    codigo = _pad5(user_id)
    valor = (username or "").strip()

    row = await database.fetch_one("""
        SELECT id
          FROM parametro
         WHERE UPPER(TRIM(tipo))='USUARIO'
           AND TRIM(codigo)=:codigo
        LIMIT 1
    """, {"codigo": codigo})

    if row:
        await database.execute("""
            UPDATE parametro
               SET valor = :valor
             WHERE id = :id
        """, {"valor": valor, "id": row["id"]})
    else:
        await database.execute("""
            INSERT INTO parametro (tipo, codigo, valor)
            VALUES ('USUARIO', :codigo, :valor)
        """, {"codigo": codigo, "valor": valor})

async def _parametro_usuario_delete(user_id: int):
    await database.execute("""
        DELETE FROM parametro
         WHERE UPPER(TRIM(tipo))='USUARIO'
           AND TRIM(codigo)=:codigo
    """, {"codigo": _pad5(user_id)})


# ======================
# APP EVENTS
# ======================
@app.on_event("startup")
async def startup():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL no configurada")
    print("🔹 CORS habilitado para:", ALLOWED_ORIGINS)
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

async def obtener_roles_usuario(usuario_id: int):
    query = """
        SELECT TRIM(nombre_rol) AS nombre_rol
        FROM v_usuario_rol
        WHERE usuario_id = :uid
    """
    rows = await database.fetch_all(query, values={"uid": usuario_id})
    return { (r["nombre_rol"] or "").upper() for r in rows }


async def obtener_usuario_y_roles(
    usuario_actual = Depends(obtener_usuario_actual),
):
    if not usuario_actual:
        raise HTTPException(status_code=401, detail="No autenticado")

    roles = await obtener_roles_usuario(usuario_actual["id"])
    return {"usuario": usuario_actual, "roles": roles}

async def require_user(usuario_actual = Depends(obtener_usuario_actual)):
    return usuario_actual

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

    if not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": user["username"], "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer"}

@app.post("/cambiar_password")
async def cambiar_password(
    datos: PasswordChange,
    usuario_actual = Depends(obtener_usuario_actual)
):
    user = await database.fetch_one(
        "SELECT username, password FROM usuario WHERE username = :u",
        values={"u": usuario_actual["username"]},
    )
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")

    if not verify_password(datos.password_actual, user["password"]):
        raise HTTPException(status_code=401, detail="La contraseña actual no es correcta")

    nuevo_hash = hash_password(datos.nueva_password)

    await database.execute(
        "UPDATE usuario SET password = :p WHERE username = :u",
        values={"p": nuevo_hash, "u": usuario_actual["username"]},
    )

    return {"mensaje": "Contraseña actualizada correctamente"}

@app.post("/usuarios/", response_model=UsuarioOut)
async def crear_usuario(usuario: UsuarioIn, user=Depends(obtener_usuario_actual)):
    hashed = bcrypt.hashpw(usuario.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    async with database.transaction():
        r = await database.fetch_one("""
            INSERT INTO usuario (username, password, activo, email, fono)
            VALUES (:username, :password, :activo, :email, :fono)
            RETURNING id, username, activo, email, TRIM(COALESCE(fono, '')) AS fono
        """, values={**usuario.dict(), "password": hashed})
        await _parametro_usuario_upsert(r["id"], r["username"])
    return dict(r)

@app.get("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def obtener_usuario(usuario_id: int, usuario_actual=Depends(obtener_usuario_actual)):
    r = await database.fetch_one("""
        SELECT id, username, activo, email, TRIM(COALESCE(fono,'')) AS fono
          FROM usuario
         WHERE id = :id
    """, {"id": usuario_id})
    if not r:
        raise HTTPException(404, "Usuario no encontrado")
    return dict(r)


@app.get("/usuarios/", response_model=list[UsuarioOut])
async def listar_usuarios(usuario_actual=Depends(obtener_usuario_actual)):
    rows = await database.fetch_all("""
        SELECT id, username, activo, email, TRIM(COALESCE(fono, '')) AS fono
        FROM usuario
    """)
    return [dict(r) for r in rows]


@app.patch("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def actualizar_usuario(usuario_id: int, body: UsuarioPatch, usuario_actual=Depends(obtener_usuario_actual)):
    actual = await database.fetch_one(
        "SELECT id, username, activo, email, fono FROM usuario WHERE id=:id",
        {"id": usuario_id}
    )
    if not actual:
        raise HTTPException(404, "Usuario no encontrado")

    campos = []
    vals = {"id": usuario_id}
    if body.username is not None:
        campos.append("username = :username")
        vals["username"] = body.username.strip()
    if body.activo is not None:
        campos.append("activo = :activo")
        vals["activo"] = bool(body.activo)
    if body.email is not None:
        campos.append("email = :email")
        vals["email"] = body.email
    if body.fono is not None:
        campos.append("fono = :fono")
        vals["fono"] = body.fono

    if not campos:
        return {
            "id": actual["id"],
            "username": actual["username"],
            "activo": actual["activo"],
            "email": actual["email"],
            "fono": (actual["fono"] or "").strip()
        }

    async with database.transaction():
        r = await database.fetch_one(f"""
            UPDATE usuario
               SET {", ".join(campos)}
             WHERE id = :id
         RETURNING id, username, activo, email, TRIM(COALESCE(fono,'')) AS fono
        """, vals)

        await _parametro_usuario_upsert(r["id"], r["username"])

    return dict(r)


@app.delete("/usuarios/{usuario_id}")
async def eliminar_usuario(usuario_id: int, usuario_actual=Depends(obtener_usuario_actual)):
    async with database.transaction():
        r = await database.fetch_one(
            "DELETE FROM usuario WHERE id = :id RETURNING id",
            {"id": usuario_id}
        )
        if not r:
            raise HTTPException(404, "Usuario no encontrado")
        await _parametro_usuario_delete(usuario_id)
    return {"mensaje": "Usuario eliminado"}


# ======================
# PROPUESTAS
# ======================
@app.post("/propuestas/", response_model=PropuestaOut)
async def crear_propuesta(
    propuesta_in: PropuestaIn,
    seguridad = Depends(obtener_usuario_y_roles),
):
    roles = seguridad["roles"]

    if "JEFE PROYECTO" in roles and "ADMINISTRADOR" not in roles:
        raise HTTPException(
            status_code=403,
            detail="No tiene permisos para crear propuestas",
        )

    p = propuesta_in
    try:
        p_anio = (p.anio or "").strip()
        if len(p_anio) != 4 or not p_anio.isdigit():
            raise HTTPException(400, "El año debe tener 4 dígitos (ej: 2025)")

        p_tipo   = (p.tipo or "").strip().upper()
        p_cod    = (p.cod_cliente or "").strip().upper()
        p_nombre = (p.nombre_propuesta or "").strip()
        p_spons  = (p.sponsor or "").strip()

        # ==========================
        # ESTADO: usar lo que viene del front
        # ==========================
        # p.estado viene como: 'cotiz' | 'adju' | 'canc' | 'eliminado'
        # si no viene nada, dejamos 'cotiz' por defecto
        est_app = _norm_lower(p.estado) or "cotiz"

        if est_app not in EST_PROP_APP2DB:
            raise HTTPException(
                400,
                "Estado inválido. Usa: cotiz | adju | canc | eliminado",
            )

        # valor que se guarda en BD: COT / ADJ / CAN / ELI
        p_estado_db = EST_PROP_APP2DB[est_app]

        # ==========================
        # Validaciones extra
        # ==========================
        if not p_cod:
            raise HTTPException(400, "El código de cliente es obligatorio")
        if not p_spons:
            raise HTTPException(400, "El sponsor es obligatorio")
        if not p_nombre:
            raise HTTPException(400, "El nombre de la propuesta es obligatorio")
        if p.usuario_id is None or p.usuario_id <= 0:
            raise HTTPException(400, "El usuario_id es obligatorio y debe ser mayor que cero")

        try:
            t_est = parse_tiempo_half_steps(p.tiempo_estimado)
        except ValueError as ve:
            raise HTTPException(400, str(ve))
        if t_est is None:
            raise HTTPException(400, "El tiempo estimado es obligatorio")

        async with database.transaction():
            await _advisory_lock_por_anio_cliente(p_anio, p_cod)

            row_next = await database.fetch_one(
                """
                SELECT COALESCE(MAX(correlativo), 0) + 1 AS next
                  FROM propuesta
                 WHERE rtrim("año") = :anio
                   AND rtrim(cod_cliente) = :cod
                """,
                values={"anio": p_anio, "cod": p_cod},
            )
            correlativo = int(row_next["next"])

            row = await database.fetch_one(
                """
                INSERT INTO propuesta
                    ("año", tipo, correlativo, cod_cliente, nombre_propuesta,
                     sponsor, tiempo_estimado, estado, fecha_estado, usuario_id)
                VALUES
                    (:anio, :tipo, :correlativo, :cod, :nombre, :sponsor,
                     :tiempo, :estado, CURRENT_DATE, :usuario_id)
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
                values={
                    "anio": p_anio,
                    "tipo": p_tipo,
                    "correlativo": correlativo,
                    "cod": p_cod,
                    "nombre": p_nombre,
                    "sponsor": p_spons,
                    "tiempo": t_est,
                    "estado": p_estado_db,      # 👈 ahora viene mapeado desde el front
                    "usuario_id": p.usuario_id,
                },
            )

        d = dict(row)
        estado_db = (d.get("estado") or "").strip().upper()
        d["estado"] = EST_PROP_DB2APP.get(estado_db, estado_db.lower())
        d["eliminado"] = (estado_db == "ELI")
        d["nombre_auto"] = build_nombre_auto(
            d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"]
        )
        return d

    except HTTPException:
        raise
    except Exception as e:
        print("crear_propuesta error:", repr(e))
        raise HTTPException(400, f"Error al crear propuesta: {e}")


@app.get("/propuestas/", response_model=list[PropuestaOut])
async def listar_propuestas(incluir_eliminado: bool = False):
    rows = await database.fetch_all(
        """
        SELECT
          p.id,
          RTRIM(p."año")         AS anio,
          RTRIM(p.tipo)          AS tipo,
          p.correlativo,
          RTRIM(p.cod_cliente)   AS cod_cliente,
          p.nombre_propuesta,
          p.sponsor,
          p.tiempo_estimado,
          RTRIM(COALESCE(p.estado,'')) AS estado,
          p.fecha_estado,
          COALESCE(p.usuario_id,0) AS usuario_id
        FROM propuesta p
        WHERE (
            :incluir_eliminado = TRUE
            OR UPPER(TRIM(COALESCE(p.estado,''))) <> 'ELI'
        )
        ORDER BY
          CAST(TRIM(p."año") AS int) DESC,
          p.correlativo DESC
        """,
        values={"incluir_eliminado": incluir_eliminado},
    )

    out = []
    for r in rows:
        d = dict(r)
        estado_db = (d.get("estado") or "").strip().upper()

        # usar SIEMPRE el mismo mapeo que en crear_propuesta
        d["estado"] = EST_PROP_DB2APP.get(estado_db, estado_db.lower())
        d["eliminado"] = (estado_db == "ELI")
        d["nombre_auto"] = build_nombre_auto(
            d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"]
        )
        out.append(d)
    return out



@app.get("/propuestas/elegibles", response_model=list[PropuestaOut])
async def listar_propuestas_elegibles():
    rows = await database.fetch_all(
        """
         SELECT
          p.id,
          RTRIM(p."año")        AS anio,
          RTRIM(p.tipo)         AS tipo,
          p.correlativo         AS correlativo,
          RTRIM(p.cod_cliente)  AS cod_cliente,
          p.nombre_propuesta    AS nombre_propuesta,
          p.sponsor             AS sponsor,
          p.tiempo_estimado     AS tiempo_estimado,
          RTRIM(COALESCE(p.estado, '')) AS estado,
          p.fecha_estado        AS fecha_estado,
          COALESCE(p.usuario_id, 0) AS usuario_id
        FROM propuesta p
        WHERE SUBSTRING(UPPER(TRIM(COALESCE(p.estado,''))) FROM 1 FOR 3) = 'ADJ'
          AND NOT EXISTS (
                SELECT 1
                  FROM proyecto pr
                 WHERE pr.propuesta_id = p.id
                   AND RTRIM(UPPER(COALESCE(pr.estado,''))) <> 'ELIMINADO'
          )
        ORDER BY CAST(TRIM(p."año") AS int) DESC, p.correlativo DESC
        """
    )
    out = []
    for r in rows:
        d = dict(r)
        estado_db = (d.get("estado") or "").strip().upper()
        d["estado"] = EST_PROP_DB2APP.get(estado_db, estado_db.lower())
        d["eliminado"] = (estado_db == "ELI")
        d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
        out.append(d)
    return out

@app.get("/propuestas/{propuesta_id}", response_model=PropuestaOut)
async def obtener_propuesta(propuesta_id: int):
    row = await database.fetch_one(
        """
        SELECT
          p.id,
          RTRIM(p."año")        AS anio,
          RTRIM(p.tipo)         AS tipo,
          p.correlativo         AS correlativo,
          RTRIM(p.cod_cliente)  AS cod_cliente,
          p.nombre_propuesta    AS nombre_propuesta,
          p.sponsor             AS sponsor,
          p.tiempo_estimado     AS tiempo_estimado,
          RTRIM(COALESCE(p.estado,'')) AS estado,
          p.fecha_estado        AS fecha_estado,
          COALESCE(p.usuario_id, 0) AS usuario_id
        FROM propuesta p
        WHERE p.id = :id
        """,
        values={"id": propuesta_id},
    )
    if not row:
        raise HTTPException(404, "Propuesta no encontrada")
    d = dict(row)
    estado_db = (d.get("estado") or "").strip().upper()
    d["estado"] = EST_PROP_DB2APP.get(estado_db, estado_db.lower())
    d["eliminado"] = (estado_db == "ELI")
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    return d


@app.patch("/propuestas/{propuesta_id}", response_model=PropuestaOut)
async def actualizar_propuesta(
    propuesta_id: int,
    cambios: PropuestaPatch,
    seguridad = Depends(obtener_usuario_y_roles),
):
    roles = seguridad["roles"]

    if "JEFE PROYECTO" in roles and "ADMINISTRADOR" not in roles:
        raise HTTPException(
            status_code=403,
            detail="No tiene permisos para editar propuestas",
        )

    body = cambios.dict()
    allowed = {
        "anio", "tipo", "cod_cliente", "nombre_propuesta",
        "sponsor", "tiempo_estimado", "estado"
    }
    data = {k: v for k, v in body.items() if k in allowed}

    # 1) Leer estado actual
    actual = await database.fetch_one(
        """
        SELECT id, RTRIM("año") AS anio, RTRIM(tipo) AS tipo,
               correlativo, RTRIM(cod_cliente) AS cod_cliente,
               RTRIM(COALESCE(estado,'')) AS estado
        FROM propuesta
        WHERE id = :id
        """,
        {"id": propuesta_id},
    )
    if not actual:
        raise HTTPException(404, "Propuesta no encontrada")

    set_parts, vals = [], {"id": propuesta_id}

    # anio
    if "anio" in data and data["anio"] is not None:
        a = str(data["anio"]).strip()
        if len(a) != 4 or not a.isdigit():
            raise HTTPException(400, "El año debe tener 4 dígitos")
        set_parts.append('"año" = :anio')
        vals["anio"] = a

    # tipo
    if "tipo" in data and data["tipo"] is not None:
        set_parts.append("tipo = :tipo")
        vals["tipo"] = str(data["tipo"]).strip().upper()

    # cliente
    if "cod_cliente" in data and data["cod_cliente"] is not None:
        set_parts.append("cod_cliente = :cod_cliente")
        vals["cod_cliente"] = str(data["cod_cliente"]).strip().upper()

    # nombre_propuesta
    if "nombre_propuesta" in data and data["nombre_propuesta"] is not None:
        set_parts.append("nombre_propuesta = :nombre")
        vals["nombre"] = str(data["nombre_propuesta"]).strip()

    # sponsor
    if "sponsor" in data:
        s = data["sponsor"]
        set_parts.append("sponsor = :sponsor")
        vals["sponsor"] = None if s is None else str(s).strip()

    # tiempo_estimado
    if "tiempo_estimado" in data:
        t_est = parse_tiempo_half_steps(data["tiempo_estimado"])
        if t_est is not None and (t_est * 2) % 1 != 0:
            raise HTTPException(400, "tiempo_estimado debe ser múltiplo de 0.5")
        set_parts.append("tiempo_estimado = :tiempo")
        vals["tiempo"] = t_est

    # 🔴 AQUÍ SE MANEJA EL ESTADO
    if "estado" in data and data["estado"] is not None:
        est_app = _norm_lower(str(data["estado"]))  # ej: 'canc'
        if est_app not in EST_PROP_APP2DB:
            raise HTTPException(
                400, "Estado inválido. Usa: cotiz | adju | canc | eliminado"
            )
        est_db = EST_PROP_APP2DB[est_app]          # 'CAN'
        set_parts.append("estado = :estado")
        vals["estado"] = est_db
        set_parts.append("fecha_estado = CURRENT_DATE")

    if not set_parts:
        raise HTTPException(400, "Nada para actualizar")

    # UPDATE
    await database.fetch_one(
        f"""
        UPDATE propuesta
        SET {", ".join(set_parts)}
        WHERE id = :id
        RETURNING id
        """,
        vals,
    )

    # Leer de nuevo con mapeo DB→APP
    row = await database.fetch_one(
        """
        SELECT
          p.id,
          RTRIM("año")              AS anio,
          RTRIM(tipo)               AS tipo,
          p.correlativo             AS correlativo,
          RTRIM(p.cod_cliente)      AS cod_cliente,
          p.nombre_propuesta        AS nombre_propuesta,
          p.sponsor                 AS sponsor,
          p.tiempo_estimado         AS tiempo_estimado,
          RTRIM(COALESCE(p.estado,'')) AS estado,
          p.fecha_estado            AS fecha_estado,
          COALESCE(p.usuario_id, 0) AS usuario_id
        FROM propuesta p
        WHERE p.id = :id
        """,
        {"id": propuesta_id},
    )

    d = dict(row)
    estado_db = (d.get("estado") or "").strip().upper()   # COT / CAN / ELI...
    d["estado"] = EST_PROP_DB2APP.get(estado_db, estado_db.lower())  # cotiz / canc...
    d["eliminado"] = (estado_db == "ELI")
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    return d

@app.delete("/propuestas/{propuesta_id}")
async def eliminar_propuesta(
    propuesta_id: int,
    seguridad = Depends(obtener_usuario_y_roles),
):
    roles = seguridad["roles"]

    if "JEFE PROYECTO" in roles and "ADMINISTRADOR" not in roles:
        raise HTTPException(
            status_code=403,
            detail="No tiene permisos para eliminar propuestas",
        )
    tomada = await database.fetch_one("""
        SELECT 1
          FROM proyecto pr
         WHERE pr.propuesta_id = :pid
           AND COALESCE(RTRIM(UPPER(pr.estado)),'') <> 'ELIMINADO'
         LIMIT 1
    """, values={"pid": propuesta_id})
    if tomada:
        raise HTTPException(409, "No se puede eliminar: la propuesta tiene un proyecto activo")

    r = await database.fetch_one("""
        UPDATE propuesta
           SET estado = 'ELI',
               fecha_estado = CURRENT_DATE
         WHERE id = :id
           AND COALESCE(RTRIM(UPPER(estado)),'') <> 'ELI'
     RETURNING id
    """, values={"id": propuesta_id})
    if not r:
        raise HTTPException(status_code=404, detail="Propuesta no encontrada o ya eliminada")
    return {"mensaje": "Propuesta eliminada correctamente"}

# ======================
# PARÁMETROS
# ======================
async def _parametro_existe(tipo: str, codigo: str, exclude_id: int | None = None) -> bool:
    q = """
        SELECT 1
          FROM parametro
         WHERE UPPER(rtrim(tipo))   = UPPER(:tipo)
           AND UPPER(rtrim(codigo)) = UPPER(:codigo)
    """
    vals = {"tipo": (tipo or "").strip(), "codigo": (codigo or "").strip()}
    if exclude_id is not None:
        q += " AND id <> :id"
        vals["id"] = exclude_id
    row = await database.fetch_one(q, values=vals)
    return row is not None

@app.get("/parametros/{tipo}")
async def listar_parametros(
    tipo: str,
    q: str | None = Query(None, description="buscar en código o valor"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
):
    limit = min(max(1, page_size), 500)
    offset = (max(1, page) - 1) * limit

    base = """
        SELECT id, rtrim(codigo) AS codigo, valor
          FROM parametro
         WHERE UPPER(rtrim(tipo)) = UPPER(:tipo)
    """
    vals = {"tipo": (tipo or "").strip()}
    if q:
        base += " AND (UPPER(rtrim(codigo)) LIKE :w OR UPPER(rtrim(valor)) LIKE :w)"
        vals["w"] = f"%{q.strip().upper()}%"

    base += " ORDER BY valor LIMIT :limit OFFSET :offset"
    rows = await database.fetch_all(base, values={**vals, "limit": limit, "offset": offset})
    return [{"id": r["id"], "codigo": r["codigo"], "valor": r["valor"]} for r in rows]


@app.post("/parametros/", response_model=ParametroOut)
async def crear_parametro(p: ParametroIn, usuario_actual=Depends(obtener_usuario_actual)):
    tipo   = (p.tipo or "").strip()
    codigo = (p.codigo or "").strip().upper()
    valor  = (p.valor or "").strip()

    if not tipo or not codigo or not valor:
        raise HTTPException(400, "tipo, codigo y valor son obligatorios")

    async with database.transaction():
        await _advisory_lock_param(tipo, codigo)
        if await _parametro_existe(tipo, codigo):
            raise HTTPException(409, f"Ya existe un parámetro con tipo '{tipo}' y código '{codigo}'")

        row = await database.fetch_one("""
            INSERT INTO parametro (tipo, codigo, valor, usuario_id)
            VALUES (:tipo, :codigo, :valor, :uid)
            RETURNING id, rtrim(tipo) AS tipo, rtrim(codigo) AS codigo, valor
        """, values={"tipo": tipo, "codigo": codigo, "valor": valor, "uid": usuario_actual["id"]})

    return dict(row)

@app.patch("/parametros/{id}", response_model=ParametroOut)
async def actualizar_parametro(id: int, p: ParametroIn, usuario_actual=Depends(obtener_usuario_actual)):
    tipo_n   = (p.tipo or "").strip()
    codigo_n = (p.codigo or "").strip().upper()
    valor_n  = (p.valor or "").strip()

    if not tipo_n or not codigo_n or not valor_n:
        raise HTTPException(400, "tipo, codigo y valor son obligatorios")

    actual = await database.fetch_one(
        "SELECT rtrim(tipo) AS tipo, rtrim(codigo) AS codigo FROM parametro WHERE id = :id",
        values={"id": id}
    )
    if not actual:
        raise HTTPException(404, "Parámetro no encontrado")

    cambia_pk = (actual["tipo"].strip() != tipo_n) or (actual["codigo"].strip().upper() != codigo_n)

    async with database.transaction():
        if cambia_pk:
            await _advisory_lock_param(tipo_n, codigo_n)
            if await _parametro_existe(tipo_n, codigo_n, exclude_id=id):
                raise HTTPException(409, f"Ya existe un parámetro con tipo '{tipo_n}' y código '{codigo_n}'")
        else:
            if await _parametro_existe(tipo_n, codigo_n, exclude_id=id):
                raise HTTPException(409, f"Ya existe un parámetro con tipo '{tipo_n}' y código '{codigo_n}'")

        row = await database.fetch_one("""
            UPDATE parametro
               SET tipo = :tipo, codigo = :codigo, valor = :valor, usuario_id = :uid
             WHERE id = :id
         RETURNING id, rtrim(tipo) AS tipo, rtrim(codigo) AS codigo, valor
        """, values={"tipo": tipo_n, "codigo": codigo_n, "valor": valor_n, "uid": usuario_actual["id"], "id": id})

    return dict(row)

@app.delete("/parametros/{id}")
async def eliminar_parametro(id: int, usuario_actual=Depends(obtener_usuario_actual)):
    r = await database.fetch_one("DELETE FROM parametro WHERE id = :id RETURNING id", values={"id": id})
    if not r:
        raise HTTPException(404, "Parámetro no encontrado")
    return {"mensaje": "Parámetro eliminado"}

@app.get("/parametros-tipos")
async def listar_tipos_parametros():
    rows = await database.fetch_all("""
        SELECT DISTINCT rtrim(tipo) AS tipo
          FROM parametro
         ORDER BY tipo
    """)
    return [r["tipo"] for r in rows]

# ======================
# PROYECTOS
# ======================
EST_PROY_APP2DB = {
    "noini":     "NOINI",
    "desar":     "DESA",
    "anali":     "ANALI",
    "qa":        "QA",
    "dete":      "DETE",
    "garan":     "GARAN",
    "ter":       "TER",
    "eliminado": "ELI",
}
EST_PROY_DB2APP = {v: k for k, v in EST_PROY_APP2DB.items()}

EST_PROY_CODE_LABEL = {
    "noini": "No iniciado",
    "desar": "Desarrollo",
    "anali": "Análisis",
    "qa":    "QA",
    "garan": "Garantía",
    "ter":   "Terminado",
    "dete":  "Detenido",
    "eliminado": "Eliminado",
}

def db_estado_to_label(db_value: str) -> str:
    db = (db_value or "").strip().upper()
    code = EST_PROY_DB2APP.get(db, db) 
    return EST_PROY_CODE_LABEL.get(code, code)


@app.post("/proyectos/", response_model=ProyectoOut)
async def crear_proyecto(p: ProyectoIn):
    if not p.propuesta_id:
        raise HTTPException(400, "propuesta_id es obligatorio")

    if not p.fecha_inicio or not p.fecha_termino:
        raise HTTPException(400, "fecha_inicio y fecha_termino son obligatorias (YYYY-MM-DD)")

    if p.fecha_inicio > p.fecha_termino:
        raise HTTPException(400, "La fecha_inicio no puede ser mayor que fecha_termino")

    tipo_fact = (p.tipo_facturacion or "").strip().upper()

    try:
        row_tipo = await database.fetch_one(
            """
            SELECT 1
              FROM parametro
             WHERE UPPER(TRIM(tipo))   = 'TIPO_FACT'
               AND UPPER(TRIM(codigo)) = :cod
            """,
            values={"cod": tipo_fact}
        )
        if tipo_fact and not row_tipo:
            raise HTTPException(400, f"tipo_facturacion inválido: {tipo_fact}")
    except HTTPException:
        raise

    prop = await database.fetch_one(
        """
        SELECT
          p.id,
          RTRIM(p."año")       AS anio,
          RTRIM(p.tipo)        AS tipo,
          p.correlativo        AS correlativo,
          RTRIM(p.cod_cliente) AS cod_cliente,
          COALESCE(RTRIM(p.estado),'') AS estado
        FROM propuesta p
        WHERE p.id = :id
        """,
        values={"id": p.propuesta_id},
    )
    if not prop:
        raise HTTPException(404, "Propuesta no encontrada")

    if (prop["estado"] or "").strip().upper() != "ADJ":
        raise HTTPException(400, "La propuesta debe estar ADJ para crear proyecto")

    taken = await database.fetch_one(
        """
        SELECT 1
          FROM proyecto pr
         WHERE pr.propuesta_id = :pid
           AND UPPER(TRIM(pr.estado)) <> 'ELIMINADO'
         LIMIT 1
        """,
        values={"pid": p.propuesta_id},
    )
    if taken:
        raise HTTPException(409, "La propuesta ya está asociada a otro proyecto activo")

    ins = await database.fetch_one(
        """
        INSERT INTO proyecto
            (propuesta_id, fecha_inicio, fecha_termino, tipo_facturacion,
             estado, fecha_estado, jp_cliente)
        VALUES
            (:propuesta_id, :fecha_inicio, :fecha_termino, :tipo_facturacion,
             'NOINI', CURRENT_DATE, :jp_cliente)
        RETURNING id
        """,
        values={
            "propuesta_id": p.propuesta_id,
            "fecha_inicio": p.fecha_inicio,
            "fecha_termino": p.fecha_termino,
            "tipo_facturacion": tipo_fact,
            "jp_cliente": p.jp_cliente,
        },
    )

    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          RTRIM(p."año")             AS anio,
          RTRIM(p.tipo)              AS tipo,
          p.correlativo              AS correlativo,
          RTRIM(p.cod_cliente)       AS cod_cliente,
          p.nombre_propuesta         AS nombre_propuesta,
          pr.fecha_inicio,
          pr.fecha_termino,
          RTRIM(pr.tipo_facturacion) AS tipo_facturacion,
          RTRIM(pr.estado)           AS estado,
          pr.fecha_estado,
          pr.jp_cliente,
          CASE WHEN UPPER(TRIM(pr.estado)) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM proyecto pr
        JOIN propuesta p ON p.id = pr.propuesta_id
        WHERE pr.id = :id
        """,
        values={"id": ins["id"]},
    )
    if not row:
        raise HTTPException(500, "Error al recuperar el proyecto recién creado")

    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)

    return d

@app.get("/proyectos/", response_model=list[ProyectoOut])
async def listar_proyectos(
    incluir_eliminado: bool = False,
    solo_mios: bool = False,
    user: dict = Depends(obtener_usuario_actual),
):
    uid = int(user["id"])

    rows = await database.fetch_all(
        """
        SELECT
          v.proyecto_id                         AS id,
          v.propuesta_id                        AS propuesta_id,
          RTRIM(p."año")                        AS anio,
          p.nombre_propuesta                    AS nombre_propuesta,
          RTRIM(p.tipo)                         AS tipo,
          p.correlativo                         AS correlativo,
          RTRIM(p.cod_cliente)                  AS cod_cliente,
          pr.fecha_inicio,
          pr.fecha_termino,
          RTRIM(pr.tipo_facturacion)            AS tipo_facturacion,
          RTRIM(COALESCE(v.estado,''))          AS estado,
          v.fecha_estado,
          pr.jp_cliente,
          pr.usuario_id,
          CASE WHEN UPPER(TRIM(COALESCE(v.estado,''))) = 'ELIMINADO'
               THEN TRUE ELSE FALSE
          END                                   AS eliminado
        FROM v_proyectos_visibles v
        JOIN proyecto  pr ON pr.id = v.proyecto_id
        JOIN propuesta p  ON p.id = v.propuesta_id
        WHERE v.usuario_id = :uid
          AND (
                :incluir_eliminado = TRUE
             OR UPPER(TRIM(COALESCE(v.estado, ''))) <> 'ELIMINADO'
          )
        ORDER BY
          CAST(TRIM(p."año") AS int) DESC,
          v.proyecto_id DESC
        """,
        values={
            "uid": uid,
            "incluir_eliminado": incluir_eliminado,
        },
    )

    out = []
    for r in rows:
        d = dict(r)
        d["estado"] = (d.get("estado") or "").strip().lower()
        d["nombre_auto"] = build_nombre_auto(
            d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"]
        )
        out.append(d)
    return out


@app.get("/proyectos/{proyecto_id}", response_model=ProyectoOut)
async def obtener_proyecto(proyecto_id: int, user: dict = Depends(obtener_usuario_actual)):
    uid = int(user["id"])

    row = await database.fetch_one(
        """
        SELECT
          pr.id,
          pr.propuesta_id,
          RTRIM(p."año")             AS anio,
          RTRIM(p.tipo)              AS tipo,
          p.correlativo              AS correlativo,
          RTRIM(p.cod_cliente)       AS cod_cliente,
          p.nombre_propuesta         AS nombre_propuesta,
          pr.fecha_inicio,
          pr.fecha_termino,
          RTRIM(pr.tipo_facturacion) AS tipo_facturacion,
          RTRIM(pr.estado)           AS estado,
          pr.fecha_estado,
          pr.jp_cliente,
          CASE WHEN RTRIM(pr.estado) = 'ELIMINADO' THEN TRUE ELSE FALSE END AS eliminado
        FROM proyecto pr
        JOIN propuesta p ON p.id = pr.propuesta_id
        WHERE pr.id = :id
          AND EXISTS (
                SELECT 1
                  FROM v_proyectos_visibles v
                 WHERE v.proyecto_id = pr.id
                   AND v.usuario_id  = :uid
          )
        """,
        values={"id": proyecto_id, "uid": uid},
    )
    if not row:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado o no autorizado")

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

    if "estado" in data:
        data.pop("estado", None)
    if "fecha_estado" in data:
        data.pop("fecha_estado", None)

    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    if "tipo_facturacion" in data and isinstance(data["tipo_facturacion"], str):
        data["tipo_facturacion"] = data["tipo_facturacion"].strip().upper()

    if "propuesta_id" in data:
        nueva_prop = await database.fetch_one(
            "SELECT id, rtrim(estado) AS estado FROM propuesta WHERE id = :id",
            values={"id": data["propuesta_id"]},
        )
        if not nueva_prop:
            raise HTTPException(404, "La propuesta indicada no existe")
        if (nueva_prop["estado"] or "").strip().upper() != "ADJ":
            raise HTTPException(400, "La propuesta asignada debe estar ADJUDICADA")

        usada = await database.fetch_one(
            """
            SELECT 1 FROM proyecto
             WHERE propuesta_id = :pid
               AND id <> :actual_id
               AND RTRIM(UPPER(estado)) <> 'ELIMINADO'
             LIMIT 1
            """,
            values={"pid": data["propuesta_id"], "actual_id": proyecto_id},
        )
        if usada:
            raise HTTPException(409, "Esa propuesta ya está asignada a otro proyecto activo")

    set_parts, vals = [], {"id": proyecto_id}
    for k, v in data.items():
        set_parts.append(f"{k} = :{k}")
        vals[k] = v

    updated = await database.fetch_one(
        f"UPDATE proyecto SET {', '.join(set_parts)} WHERE id = :id RETURNING id",
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
          p.correlativo              AS correlativo,
          rtrim(p.cod_cliente)       AS cod_cliente,
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
# AVANCES
# =====================================================
HITO_MAP = {
    0: "PROD",
    1: "QA",
    2: "GAR",
    3: "GAR",
    4: "PROD",
}

async def _upsert_factura_por_hito(
    proyecto_id: int,
    fecha_avance: date,
    hito_code: int | None,
    usuario_id: int | None,
):
    if hito_code is None or hito_code not in HITO_MAP:
        return
    hito_txt = HITO_MAP[hito_code]

    exist = await database.fetch_one(
        "SELECT id FROM factura WHERE proyecto_id = :p AND rtrim(hito) = :h",
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
            values={"p": proyecto_id, "f": fecha_avance, "h": hito_txt, "u": usuario_id},
        )

async def _sync_estado_proyecto(proyecto_id: int):
    row = await database.fetch_one("""
        SELECT rtrim(UPPER(estado)) AS estado, fecha
          FROM avance
         WHERE proyecto_id = :pid
         ORDER BY fecha DESC, id DESC
         LIMIT 1
    """, values={"pid": proyecto_id})

    if not row:
        return

    estado = (row["estado"] or "").strip().upper()

    valido = await database.fetch_one("""
        SELECT 1 FROM parametro
         WHERE UPPER(rtrim(tipo)) = 'PROY_ESTADO'
           AND UPPER(rtrim(codigo)) = :e
        LIMIT 1
    """, values={"e": estado})

    if not valido:
        estado = "PROD"

    await database.execute("""
        UPDATE proyecto
           SET estado = :estado,
               fecha_estado = :fecha
         WHERE id = :pid
    """, values={"estado": estado, "fecha": row["fecha"], "pid": proyecto_id})

async def is_valid_estado_codigo(codigo: str) -> bool:
    if not codigo:
        return False

    row = await database.fetch_one("""
        SELECT 1
        FROM parametro
        WHERE LOWER(TRIM(tipo)) = 'proy_estado'
          AND UPPER(TRIM(codigo)) = UPPER(:c)
        LIMIT 1
    """, {"c": codigo})
    return bool(row)


async def get_last_avance_id(proyecto_id: int) -> Optional[int]:
    row = await database.fetch_one("""
        SELECT id
        FROM avance
        WHERE proyecto_id = :pid
        ORDER BY fecha DESC, id DESC
        LIMIT 1
    """, {"pid": proyecto_id})
    return row["id"] if row else None

async def sync_proyecto_estado_from_last_avance(proyecto_id: int) -> None:
    last = await database.fetch_one("""
        SELECT estado
        FROM avance
        WHERE proyecto_id = :pid
        ORDER BY fecha DESC, id DESC
        LIMIT 1
    """, {"pid": proyecto_id})
    if not last:
        return
    await database.execute("""
        UPDATE proyecto
        SET estado = :estado, fecha_estado = CURRENT_DATE
        WHERE id = :pid
    """, {"estado": last["estado"], "pid": proyecto_id})


@app.post("/avances/", response_model=AvanceOut)
async def crear_avance(body: AvanceIn, user=Depends(obtener_usuario_actual)):
    if body.estado is not None and not await is_valid_estado_codigo(body.estado):
        raise HTTPException(400, "Estado de avance inválido")

    query = """
        INSERT INTO avance (proyecto_id, fecha, comentario, estado, usuario_id, hito)
        VALUES (:proyecto_id, :fecha, :comentario, COALESCE(:estado, (
                  SELECT estado FROM proyecto WHERE id=:proyecto_id
               )), :usuario_id, :hito)
        RETURNING id
    """
    values = {
        "proyecto_id": body.proyecto_id,
        "fecha": body.fecha,
        "comentario": body.comentario,
        "estado": body.estado,
        "usuario_id": user["id"],
        "hito": body.hito,
    }

    async with database.transaction():
        new_id = await database.fetch_val(query, values)
        await sync_proyecto_estado_from_last_avance(body.proyecto_id)

    row = await database.fetch_one("SELECT * FROM avance WHERE id=:id", {"id": new_id})
    return AvanceOut(**row)



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
        SELECT
          a.id,
          a.proyecto_id,
          a.fecha,
          rtrim(a.estado) AS estado, 
          a.comentario,
          a.hito,
          a.usuario_id
        FROM avance a
        {where_sql}
        ORDER BY a.fecha DESC, a.id DESC
        """,
        values=valores,
    )
    return [dict(r) for r in rows]


@app.patch("/avances/{avance_id}", response_model=AvanceOut)
async def patch_avance(avance_id: int, body: AvancePatch, user=Depends(obtener_usuario_actual)):
    avance = await database.fetch_one("SELECT * FROM avance WHERE id=:id", {"id": avance_id})
    if not avance:
        raise HTTPException(404, "No existe el avance")

    last_id = await get_last_avance_id(avance["proyecto_id"])
    if last_id != avance_id:
        raise HTTPException(400, "Solo se puede modificar el último avance")

    if body.estado is not None and not await is_valid_estado_codigo(body.estado):
        raise HTTPException(400, "Estado de avance inválido")

    sets = []
    params = {"id": avance_id}
    if body.fecha is not None:
        sets.append("fecha = :fecha")
        params["fecha"] = body.fecha
    if body.comentario is not None:
        sets.append("comentario = :comentario")
        params["comentario"] = body.comentario
    if body.hito is not None:
        sets.append("hito = :hito")
        params["hito"] = body.hito
    if body.estado is not None:
        sets.append("estado = :estado")
        params["estado"] = body.estado

    if not sets:
        row = await database.fetch_one("SELECT * FROM avance WHERE id=:id", {"id": avance_id})
        return AvanceOut(**row)

    query = f"UPDATE avance SET {', '.join(sets)} WHERE id = :id"

    async with database.transaction():
        await database.execute(query, params)
        await sync_proyecto_estado_from_last_avance(avance["proyecto_id"])

    row = await database.fetch_one("SELECT * FROM avance WHERE id=:id", {"id": avance_id})
    return AvanceOut(**row)

@app.delete("/avances/{avance_id}")
async def eliminar_avance(avance_id: int):
    a = await database.fetch_one("SELECT id, proyecto_id FROM avance WHERE id = :id", {"id": avance_id})
    if not a:
        raise HTTPException(404, "Avance no encontrado")

    last = await database.fetch_one("""
        SELECT id
        FROM avance
        WHERE proyecto_id = :pid
        ORDER BY fecha DESC, id DESC
        LIMIT 1
    """, {"pid": a["proyecto_id"]})

    if not last or last["id"] != a["id"]:
        raise HTTPException(400, "Solo se puede eliminar el último avance")

    async with database.transaction():
        await database.fetch_one("DELETE FROM avance WHERE id = :id RETURNING id", {"id": avance_id})
        await sync_proyecto_estado_from_last_avance(a["proyecto_id"])

    return {"mensaje": "Avance eliminado"}

# ----------------------------------------------------------
# 🔹 DASHBOARD
# ----------------------------------------------------------
@app.get("/dashboard/kpis")
async def dashboard_kpis():
    COD_GAR = EST_PROY_APP2DB["garan"]
    COD_DET = EST_PROY_APP2DB["dete"]

    q_adjud = """
        SELECT COUNT(*) AS c
        FROM propuesta
        WHERE SUBSTRING(UPPER(TRIM(COALESCE(estado,''))) FROM 1 FOR 3) = 'ADJ'
          AND SUBSTRING(UPPER(TRIM(COALESCE(estado,''))) FROM 1 FOR 3) <> 'ELI'
    """

    q_garan = """
        SELECT COUNT(*) AS c
        FROM proyecto
        WHERE UPPER(TRIM(COALESCE(estado,''))) = :cod_gar
    """

    q_dete = """
        SELECT COUNT(*) AS c
        FROM proyecto
        WHERE UPPER(TRIM(COALESCE(estado,''))) = :cod_det
    """

    q_total = """
        SELECT COUNT(*) AS c
        FROM proyecto
        WHERE UPPER(TRIM(COALESCE(estado,''))) <> 'ELIMINADO'
    """

    q_equipo = """
        SELECT COUNT(*) AS c
        FROM equipo
        WHERE fecha_desde <= CURRENT_DATE
          AND (fecha_hasta IS NULL OR fecha_hasta >= CURRENT_DATE)
    """

    r1 = await database.fetch_one(q_adjud)
    r2 = await database.fetch_one(q_garan, values={"cod_gar": COD_GAR})
    r3 = await database.fetch_one(q_dete,  values={"cod_det": COD_DET})
    r4 = await database.fetch_one(q_total)
    r5 = await database.fetch_one(q_equipo)

    return {
        "propuestas_adjudicadas": int(r1["c"]),
        "proyectos_en_garantia": int(r2["c"]),
        "proyectos_detenidos": int(r3["c"]),
        "proyectos_totales": int(r4["c"]),
        "equipo_activo": int(r5["c"]),
    }


@app.get("/dashboard/equipo-por-proyecto")
async def dashboard_equipo_por_proyecto():
    rows = await database.fetch_all("""
      SELECT pr.id AS proyecto_id,
             COALESCE(pr.jp_cliente,'—')       AS jp_cliente,
             p.nombre_propuesta                AS nombre_propuesta,
             COUNT(DISTINCT e.usuario_id)      AS personas_activas
      FROM proyecto pr
      JOIN propuesta p ON p.id = pr.propuesta_id
      LEFT JOIN equipo e
             ON e.proyecto_id = pr.id
            AND e.fecha_desde <= CURRENT_DATE
            AND (e.fecha_hasta IS NULL OR e.fecha_hasta >= CURRENT_DATE)
      WHERE COALESCE(UPPER(TRIM(pr.estado)),'') <> 'ELIMINADO'
      GROUP BY pr.id, pr.jp_cliente, p.nombre_propuesta
      HAVING COUNT(DISTINCT e.usuario_id) > 0
      ORDER BY personas_activas DESC, pr.id DESC
    """)
    return [dict(r) for r in rows]

EST_PROY_APP_ORDER = [
    "Terminado", "QA", "No iniciado", "Desarrollo",
    "Garantía", "Detenido", "Análisis"
]

@app.get("/dashboard/proyectos-por-estado")
async def dashboard_proyectos_por_estado():
    rows = await database.fetch_all("""
        SELECT UPPER(TRIM(COALESCE(estado,''))) AS est, COUNT(*) AS c
        FROM proyecto
        WHERE UPPER(TRIM(COALESCE(estado,''))) <> 'ELIMINADO'
        GROUP BY UPPER(TRIM(COALESCE(estado,'')))
    """)

    acum = {}
    for r in rows:
        label = db_estado_to_label(r["est"])
        if label != "Eliminado":
            acum[label] = int(r["c"])

    out = []
    for label in EST_PROY_APP_ORDER:
        if label in acum:
            out.append({"estado": label, "cantidad": acum[label]})
    for k, v in acum.items():
        if k not in EST_PROY_APP_ORDER:
            out.append({"estado": k, "cantidad": v})

    return out


# ======================
# EQUIPOS
# ======================
@app.post("/equipos/", response_model=EquipoOut)
async def crear_equipo(e: EquipoIn, usuario_actual=Depends(obtener_usuario_actual)):
    rol = (e.rol or "").strip().upper()
    if rol not in ("JP", "DEV"):
        raise HTTPException(400, "rol inválido (usa JP o DEV)")

    if not (0 <= float(e.dedicacion) <= 100):
        raise HTTPException(400, "La dedicación debe ser entre 0 y 100")

    fecha_desde = e.fecha_desde
    fecha_hasta = e.fecha_hasta

    if fecha_hasta is not None and fecha_desde > fecha_hasta:
        raise HTTPException(400, "La fecha_desde no puede ser mayor a fecha_hasta")

    proy = await database.fetch_one(
        "SELECT id FROM proyecto WHERE id = :id AND UPPER(TRIM(COALESCE(estado,''))) <> 'ELIMINADO'",
        values={"id": e.proyecto_id},
    )
    if not proy:
        raise HTTPException(404, "Proyecto no existe o está eliminado")

    usu = await database.fetch_one("SELECT id FROM usuario WHERE id = :id", values={"id": e.usuario_id})
    if not usu:
        raise HTTPException(404, "Usuario no existe")

    exist_solapa = await database.fetch_one(
        """
        SELECT id
          FROM equipo
         WHERE proyecto_id = :p
           AND usuario_id  = :u
           AND NOT (
                 COALESCE(:hasta, DATE '9999-12-31') < fecha_desde
              OR COALESCE(fecha_hasta, DATE '9999-12-31') < :desde
           )
         LIMIT 1
        """,
        values={"p": e.proyecto_id, "u": e.usuario_id, "desde": fecha_desde, "hasta": fecha_hasta},
    )
    if exist_solapa:
        raise HTTPException(409, "Ya existe participación de este usuario en el proyecto que solapa el período")

    tot = await database.fetch_one(
        """
        SELECT COALESCE(SUM(dedicacion), 0) AS total
          FROM equipo
         WHERE proyecto_id = :p
           AND usuario_id  = :u
           AND NOT (
                COALESCE(:hasta, DATE '9999-12-31') < fecha_desde
             OR COALESCE(fecha_hasta, DATE '9999-12-31') < :desde
           )
        """,
        values={"p": e.proyecto_id, "u": e.usuario_id, "desde": fecha_desde, "hasta": fecha_hasta},
    )
    if float(tot["total"] or 0) + float(e.dedicacion) > 100:
        raise HTTPException(400, "La dedicación acumulada superaría 100% en el período")

    row = await database.fetch_one(
        """
        INSERT INTO equipo (proyecto_id, usuario_id, rol, dedicacion, fecha_desde, fecha_hasta, comentario)
        VALUES (:proyecto_id, :usuario_id, :rol, :dedicacion, :fecha_desde, :fecha_hasta, :comentario)
        RETURNING id, proyecto_id, usuario_id, rol, dedicacion, fecha_desde, fecha_hasta, comentario
        """,
        values={
            "proyecto_id": e.proyecto_id,
            "usuario_id": e.usuario_id,
            "rol": rol,
            "dedicacion": float(e.dedicacion),
            "fecha_desde": fecha_desde,
            "fecha_hasta": fecha_hasta,
            "comentario": e.comentario,
        },
    )
    u = await database.fetch_one("SELECT username FROM usuario WHERE id=:id", {"id": row["usuario_id"]})
    return {**dict(row), "usuario_nombre": u["username"] if u else None}


@app.get("/equipos/", response_model=list[EquipoOut])
async def listar_equipos(proyecto_id: int = Query(...)):
    rows = await database.fetch_all(
        """
        SELECT e.id, e.proyecto_id, e.usuario_id, u.username AS usuario_nombre,
               TRIM(COALESCE(e.rol, '')) AS rol, e.dedicacion,
               e.fecha_desde, e.fecha_hasta, e.comentario
          FROM equipo e
          JOIN usuario u ON u.id = e.usuario_id
         WHERE e.proyecto_id = :p
         ORDER BY (e.fecha_hasta IS NULL) DESC, e.fecha_desde, e.id
        """,
        values={"p": proyecto_id},
    )
    return [dict(r) for r in rows]


@app.patch("/equipos/{equipo_id}", response_model=EquipoOut)
async def patch_equipo(equipo_id: int, body: dict = Body(...)):
    allowed = {"rol", "dedicacion", "fecha_desde", "fecha_hasta", "comentario", "usuario_id"}
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(400, "Nada para actualizar")

    actual = await database.fetch_one("SELECT * FROM equipo WHERE id = :id", {"id": equipo_id})
    if not actual:
        raise HTTPException(404, "Equipo no encontrado")

    rol = (data.get("rol", actual["rol"]) or "").strip().upper()
    if rol not in ("JP", "DEV"):
        raise HTTPException(400, "rol inválido (usa JP o DEV)")

    dedicacion  = float(data.get("dedicacion", actual["dedicacion"]))
    if not (0 <= dedicacion <= 100):
        raise HTTPException(400, "La dedicación debe ser entre 0 y 100")

    def _to_date_or_none(v):
        if v is None or v == "":
            return None
        if isinstance(v, date):
            return v
        return date.fromisoformat(v)

    fecha_desde = _to_date_or_none(data.get("fecha_desde", actual["fecha_desde"]))
    fecha_hasta = _to_date_or_none(data.get("fecha_hasta", actual["fecha_hasta"]))

    if fecha_hasta is not None and fecha_desde > fecha_hasta:
        raise HTTPException(400, "La fecha_desde no puede ser mayor a fecha_hasta")

    usuario_id  = int(data.get("usuario_id", actual["usuario_id"]))
    proyecto_id = int(actual["proyecto_id"])

    proy = await database.fetch_one(
        "SELECT 1 FROM proyecto WHERE id=:id AND UPPER(TRIM(COALESCE(estado,''))) <> 'ELIMINADO'",
        {"id": proyecto_id},
    )
    if not proy:
        raise HTTPException(409, "No se puede modificar: el proyecto está eliminado o no existe")

    exist_solapa = await database.fetch_one(
        """
        SELECT id
          FROM equipo
         WHERE proyecto_id = :p
           AND usuario_id  = :u
           AND id <> :id
           AND NOT (
                 COALESCE(:hasta, DATE '9999-12-31') < fecha_desde
              OR COALESCE(fecha_hasta, DATE '9999-12-31') < :desde
           )
         LIMIT 1
        """,
        {"p": proyecto_id, "u": usuario_id, "id": equipo_id, "desde": fecha_desde, "hasta": fecha_hasta},
    )
    if exist_solapa:
        raise HTTPException(409, "Ya existe participación de este usuario que solapa el período")

    tot = await database.fetch_one(
        """
        SELECT COALESCE(SUM(dedicacion), 0) AS total
          FROM equipo
         WHERE proyecto_id = :p
           AND usuario_id  = :u
           AND id <> :id
           AND NOT (
                COALESCE(:hasta, DATE '9999-12-31') < fecha_desde
             OR COALESCE(fecha_hasta, DATE '9999-12-31') < :desde
           )
        """,
        {"p": proyecto_id, "u": usuario_id, "id": equipo_id, "desde": fecha_desde, "hasta": fecha_hasta},
    )
    if float(tot["total"] or 0) + dedicacion > 100:
        raise HTTPException(400, "La dedicación acumulada superaría 100% en el período")

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
        RETURNING id, proyecto_id, usuario_id, rol, dedicacion, fecha_desde, fecha_hasta, comentario
        """,
        {
            "id": equipo_id,
            "rol": rol,
            "dedicacion": dedicacion,
            "desde": fecha_desde,
            "hasta": fecha_hasta,
            "comentario": data.get("comentario", actual["comentario"]),
            "usuario_id": usuario_id,
        },
    )
    u = await database.fetch_one("SELECT username FROM usuario WHERE id=:id", {"id": row["usuario_id"]})
    return {**dict(row), "usuario_nombre": u["username"] if u else None}

@app.delete("/equipos/{equipo_id}")
async def eliminar_equipo(equipo_id: int):
    r = await database.fetch_one("DELETE FROM equipo WHERE id = :id RETURNING id", values={"id": equipo_id})
    if not r:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    return {"mensaje": "Equipo eliminado"}

# ======================
# FACTURAS (SECCION CORREGIDA)
# ======================
@app.post("/facturas/", response_model=FacturaOut)
async def crear_factura(
    f: FacturaIn, 
    seguridad = Depends(obtener_usuario_y_roles)
):
    usuario_actual = seguridad["usuario"]
    roles = seguridad["roles"]

    if "ADMINISTRADOR" not in roles:
        raise HTTPException(status_code=403, detail="No tiene permisos para crear facturas")

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
        "usuario_id": usuario_actual["id"]
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
async def listar_facturas(
    proyecto_id: int = Query(...),
    seguridad = Depends(obtener_usuario_y_roles),
):
    roles = seguridad["roles"]

    # --- BLOQUEO SUAVE ---
    # Si no es ADMIN ni CONSULTA, devuelve lista vacía para no romper el frontend
    if "ADMINISTRADOR" not in roles and "CONSULTA" not in roles:
        return []

    rows = await database.fetch_all("""
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
          p.correlativo,
          rtrim(p.cod_cliente)  AS cod_cliente
        FROM factura f
        JOIN proyecto  pr ON pr.id = f.proyecto_id
        JOIN propuesta p  ON p.id = pr.propuesta_id
       WHERE f.proyecto_id = :pid
       ORDER BY f.fecha ASC
    """, values={"pid": proyecto_id})

    result: list[dict] = []
    for r in rows:
        d = dict(r)
        d["nombre_auto"] = build_nombre_auto(
            d.get("anio"), d.get("tipo"), d.get("correlativo"), d.get("cod_cliente")
        )
        for k in ("tipo", "correlativo", "cod_cliente"):
            d.pop(k, None)
        result.append(d)
    return result

@app.get("/facturas/{factura_id}", response_model=FacturaOut)
async def obtener_factura(
    factura_id: int,
    seguridad = Depends(obtener_usuario_y_roles),
):
    roles = seguridad["roles"]

    if "ADMINISTRADOR" not in roles and "CONSULTA" not in roles:
        raise HTTPException(
            status_code=403,
            detail="No tiene permisos para ver facturas",
        )

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
    """, values={"id": factura_id})
    if not row:
        raise HTTPException(404, "Factura no encontrada")
    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(d.get("anio"), d.get("tipo"), d.get("correlativo"), d.get("cod_cliente"))
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

@app.patch("/facturas/{factura_id}", response_model=FacturaOut)
async def patch_factura(
    factura_id: int, 
    body: dict = Body(...),
    seguridad = Depends(obtener_usuario_y_roles)
):
    roles = seguridad["roles"]

    if "ADMINISTRADOR" not in roles:
        raise HTTPException(status_code=403, detail="No tiene permisos para editar facturas")

    allowed = {"fecha", "hito", "estado", "fecha_estado"}
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(400, "Nada para actualizar")

    if "hito" in data and isinstance(data["hito"], str):
        data["hito"] = data["hito"].strip().upper()[:10]
    if "estado" in data and isinstance(data["estado"], str):
        data["estado"] = data["estado"].strip().upper()[:10]

    def _to_date(val):
        if isinstance(val, date):
            return val
        if isinstance(val, str) and val:
            return date.fromisoformat(val)
        return val

    if "fecha" in data:
        data["fecha"] = _to_date(data["fecha"])
    if "fecha_estado" in data:
        data["fecha_estado"] = _to_date(data["fecha_estado"])

    set_parts, vals = [], {"id": factura_id}
    for k, v in data.items():
        set_parts.append(f"{k} = :{k}")
        vals[k] = v

    try:
        row = await database.fetch_one(
            f"""
            UPDATE factura
               SET {", ".join(set_parts)}
             WHERE id = :id
         RETURNING id, proyecto_id, fecha, rtrim(hito) AS hito, rtrim(estado) AS estado,
                   fecha_estado, usuario_id
            """,
            values=vals
        )
        if not row:
            raise HTTPException(404, "Factura no encontrada")
    except Exception as e:
        print("patch_factura error:", repr(e))
        raise HTTPException(400, f"Error al actualizar factura: {e}")

    full = await database.fetch_one("""
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
    """, values={"id": row["id"]})

    d = dict(full)
    d["nombre_auto"] = build_nombre_auto(d.get("anio"), d.get("tipo"), d.get("correlativo"), d.get("cod_cliente"))
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

@app.delete("/facturas/{factura_id}")
async def eliminar_factura(
    factura_id: int,
    seguridad = Depends(obtener_usuario_y_roles)
):
    roles = seguridad["roles"]

    # --- BLOQUEO FUERTE ---
    # Aquí sí lanzamos error si intentan borrar sin permiso
    if "ADMINISTRADOR" not in roles:
        raise HTTPException(status_code=403, detail="No tiene permisos para eliminar facturas")

    r = await database.fetch_one(
        "DELETE FROM factura WHERE id = :id RETURNING id",
        values={"id": factura_id},
    )
    if not r:
        raise HTTPException(status_code=404, detail="Factura no encontrada")
    return {"mensaje": "Factura eliminada"}

# ==========================================
#            CRUD: ROL
# ==========================================
@app.get("/roles/catalogo", response_model=List[dict])
async def listar_catalogo_roles(user=Depends(obtener_usuario_actual)):
    query = "SELECT id, nombre_rol FROM public.rol_catalogo ORDER BY nombre_rol"
    rows = await database.fetch_all(query)
    return [dict(r) for r in rows]

@app.post("/roles/catalogo", response_model=dict)
async def crear_rol_catalogo(body: dict, user=Depends(obtener_usuario_actual)):
    nombre = body.get("nombre_rol")
    if not nombre:
        raise HTTPException(400, "nombre_rol es requerido")
    try:
        q = "INSERT INTO public.rol_catalogo (nombre_rol) VALUES (:nombre) RETURNING id, nombre_rol"
        r = await database.fetch_one(q, values={"nombre": nombre})
        return dict(r)
    except Exception as e:
        if "rol_catalogo_nombre_rol_key" in str(e): # Ajusta según tu constraint si es necesario
             raise HTTPException(409, "Ese rol ya existe en el catálogo")
        raise HTTPException(400, f"Error creando rol: {e}")

@app.delete("/roles/catalogo/{id}")
async def eliminar_rol_catalogo(id: int, user=Depends(obtener_usuario_actual)):
    try:
        r = await database.fetch_one(
            "DELETE FROM public.rol_catalogo WHERE id = :id RETURNING id", 
            values={"id": id}
        )
        if not r:
            raise HTTPException(404, "Rol no encontrado en el catálogo")
        return {"mensaje": "Rol eliminado del catálogo"}
    except Exception as e:
        # Si el rol se está usando, la base de datos no dejará borrarlo
        if "violates foreign key constraint" in str(e):
             raise HTTPException(409, "No se puede eliminar: este rol está asignado a usuarios")
        raise HTTPException(400, f"Error eliminando rol: {e}")

@app.post("/usuarios/roles/", response_model=UsuarioRolOut)
async def asignar_rol_a_usuario(body: UsuarioRolIn, user=Depends(obtener_usuario_actual)):
    try:
        query = """
        INSERT INTO public.usuario_rol (usuario_id, rol_id)
        VALUES (:usuario_id, :rol_id)
        RETURNING id, usuario_id, rol_id
        """
        row = await database.fetch_one(query, values=body.dict())
        
        r = await database.fetch_one("SELECT nombre_rol FROM rol_catalogo WHERE id=:id", {"id": row["rol_id"]})
        u = await database.fetch_one("SELECT username FROM usuario WHERE id=:id", {"id": row["usuario_id"]})

        return {
            **dict(row),
            "rol_nombre": r["nombre_rol"] if r else None,
            "username": u["username"] if u else None
        }
    except Exception as e:
        if "usuario_rol_unica" in str(e):
            raise HTTPException(409, "Este usuario ya tiene ese rol asignado")
        raise HTTPException(400, f"Error al asignar rol: {e}")

@app.get("/usuarios/{usuario_id}/roles/", response_model=List[UsuarioRolOut])
async def listar_roles_de_usuario(usuario_id: int, user=Depends(obtener_usuario_actual)):
    query = """
    SELECT
        ur.id,
        ur.usuario_id,
        ur.rol_id,
        r.nombre_rol,
        u.username
    FROM public.usuario_rol ur
    JOIN public.rol_catalogo r ON ur.rol_id = r.id
    JOIN public.usuario u ON ur.usuario_id = u.id
    WHERE ur.usuario_id = :usuario_id
    ORDER BY r.nombre_rol
    """
    rows = await database.fetch_all(query, values={"usuario_id": usuario_id})
    return [dict(r) for r in rows]

@app.get("/vista/usuarios-roles", response_model=List[UsuarioRolOut])
async def vista_usuarios_roles(user=Depends(obtener_usuario_actual)):
    rows = await database.fetch_all("""
        SELECT
            usuario_rol_id AS id,
            usuario_id,
            rol_id,
            nombre_rol    AS rol_nombre,
            username
        FROM v_usuario_rol
        ORDER BY username, nombre_rol
    """)
    return [dict(r) for r in rows]

@app.delete("/usuarios/roles/{id_relacion}")
async def quitar_rol_a_usuario(id_relacion: int, user=Depends(obtener_usuario_actual)):
    row = await database.fetch_one(
        "DELETE FROM public.usuario_rol WHERE id = :id_relacion RETURNING id",
        values={"id_relacion": id_relacion}
    )
    if not row:
        raise HTTPException(404, "Relación de rol no encontrada")
    return {"mensaje": "Rol eliminado del usuario"}

# ==========================================
#         CRUD: TECNOLOGIA
# ==========================================
@app.get("/tecnologias/catalogo", response_model=List[dict])
async def listar_catalogo_tecnologias(user=Depends(obtener_usuario_actual)):
    query = "SELECT id, nombre_tecnologia FROM public.tecnologia_catalogo ORDER BY nombre_tecnologia"
    rows = await database.fetch_all(query)
    return [dict(r) for r in rows]

@app.post("/tecnologias/catalogo", response_model=dict)
async def crear_tecnologia_catalogo(body: dict, user=Depends(obtener_usuario_actual)):
    nombre = body.get("nombre_tecnologia")
    if not nombre:
        raise HTTPException(400, "nombre_tecnologia es requerido")
    try:
        q = "INSERT INTO public.tecnologia_catalogo (nombre_tecnologia) VALUES (:nombre) RETURNING id, nombre_tecnologia"
        r = await database.fetch_one(q, values={"nombre": nombre})
        return dict(r)
    except Exception as e:
        if "tecnologia_catalogo_nombre_tecnologia_key" in str(e):
             raise HTTPException(409, "Esa tecnología ya existe en el catálogo")
        raise HTTPException(400, f"Error creando tecnología: {e}")

@app.patch("/tecnologias/catalogo/{id_catalogo}", response_model=dict)
async def actualizar_tecnologia_catalogo(id_catalogo: int, body: dict, user=Depends(obtener_usuario_actual)):
    nombre = body.get("nombre_tecnologia")
    if not nombre:
        raise HTTPException(400, "nombre_tecnologia es requerido")
    try:
        q = "UPDATE public.tecnologia_catalogo SET nombre_tecnologia = :nombre WHERE id = :id RETURNING id, nombre_tecnologia"
        r = await database.fetch_one(q, values={"nombre": nombre, "id": id_catalogo})
        if not r:
             raise HTTPException(404, "Tecnología no encontrada en el catálogo")
        return dict(r)
    except Exception as e:
        if "tecnologia_catalogo_nombre_tecnologia_key" in str(e):
             raise HTTPException(409, "Ese nombre de tecnología ya existe")
        raise HTTPException(400, f"Error actualizando tecnología: {e}")

@app.delete("/tecnologias/catalogo/{id_catalogo}")
async def eliminar_tecnologia_catalogo(id_catalogo: int, user=Depends(obtener_usuario_actual)):
    try:
        r = await database.fetch_one("DELETE FROM public.tecnologia_catalogo WHERE id = :id RETURNING id", values={"id": id_catalogo})
        if not r:
            raise HTTPException(404, "Tecnología no encontrada en el catálogo")
        return {"ok": True, "mensaje": "Tecnología eliminada del catálogo"}
    except Exception as e:
        if "violates foreign key constraint" in str(e):
             raise HTTPException(409, "No se puede eliminar: esta tecnología está asignada a uno o más usuarios")
        raise HTTPException(400, f"Error eliminando tecnología: {e}")

@app.post("/usuarios/tecnologias/", response_model=UsuarioTecnologiaOut)
async def asignar_tecnologia_a_usuario(body: UsuarioTecnologiaIn, user=Depends(obtener_usuario_actual)):
    user_exists = await database.fetch_one("SELECT 1 FROM usuario WHERE id = :id", {"id": body.usuario_id})
    if not user_exists:
        raise HTTPException(404, "Usuario no encontrado")
        
    tech_exists = await database.fetch_one("SELECT 1 FROM tecnologia_catalogo WHERE id = :id", {"id": body.tecnologia_id})
    if not tech_exists:
        raise HTTPException(404, "Tecnología no encontrada en el catálogo")

    try:
        query = """
        INSERT INTO public.usuario_tecnologia (usuario_id, tecnologia_id, nivel, vigente)
        VALUES (:usuario_id, :tecnologia_id, :nivel, :vigente)
        RETURNING id, usuario_id, tecnologia_id, nivel, vigente
        """
        row = await database.fetch_one(query, values=body.dict())
        
        tech = await database.fetch_one("SELECT nombre_tecnologia FROM tecnologia_catalogo WHERE id=:id", {"id": row["tecnologia_id"]})
        u = await database.fetch_one("SELECT username FROM usuario WHERE id=:id", {"id": row["usuario_id"]})

        return {
            **dict(row),
            "tecnologia_nombre": tech["nombre_tecnologia"] if tech else None,
            "username": u["username"] if u else None
        }

    except Exception as e:
        if "usuario_tecnologia_unica" in str(e):
            raise HTTPException(409, "Este usuario ya tiene esa tecnología asignada")
        raise HTTPException(400, f"Error al asignar tecnología: {e}")


@app.get("/usuarios/{usuario_id}/tecnologias/", response_model=List[UsuarioTecnologiaOut])
async def listar_tecnologias_de_usuario(usuario_id: int, user=Depends(obtener_usuario_actual)):
    query = """
    SELECT
        ut.id,
        ut.usuario_id,
        ut.tecnologia_id,
        ut.nivel,
        ut.vigente,
        t.nombre_tecnologia,
        u.username
    FROM public.usuario_tecnologia ut
    JOIN public.tecnologia_catalogo t ON ut.tecnologia_id = t.id
    JOIN public.usuario u ON ut.usuario_id = u.id
    WHERE ut.usuario_id = :usuario_id
    ORDER BY t.nombre_tecnologia
    """
    rows = await database.fetch_all(query, values={"usuario_id": usuario_id})
    return [dict(r) for r in rows]


@app.patch("/usuarios/tecnologias/{id_relacion}", response_model=UsuarioTecnologiaOut)
async def actualizar_habilidad_usuario(id_relacion: int, body: UsuarioTecnologiaPatch, user=Depends(obtener_usuario_actual)):
    updates = body.dict(exclude_unset=True) 
    if not updates:
        raise HTTPException(400, "Nada para actualizar. Enviar 'nivel' o 'vigente'.")

    set_sql = ", ".join(f"{key} = :{key}" for key in updates.keys())
    
    query = f"""
    UPDATE public.usuario_tecnologia
    SET {set_sql}
    WHERE id = :id_relacion
    RETURNING id, usuario_id, tecnologia_id, nivel, vigente
    """
    
    row = await database.fetch_one(query, values={**updates, "id_relacion": id_relacion})
    if not row:
        raise HTTPException(404, "Relación de habilidad no encontrada")

    tech = await database.fetch_one("SELECT nombre_tecnologia FROM tecnologia_catalogo WHERE id=:id", {"id": row["tecnologia_id"]})
    u = await database.fetch_one("SELECT username FROM usuario WHERE id=:id", {"id": row["usuario_id"]})

    return {
        **dict(row),
        "tecnologia_nombre": tech["nombre_tecnologia"] if tech else None,
        "username": u["username"] if u else None
    }


@app.delete("/usuarios/tecnologias/{id_relacion}")
async def quitar_tecnologia_a_usuario(id_relacion: int, user=Depends(obtener_usuario_actual)):
    row = await database.fetch_one(
        "DELETE FROM public.usuario_tecnologia WHERE id = :id_relacion RETURNING id",
        values={"id_relacion": id_relacion}
    )
    if not row:
        raise HTTPException(404, "Relación de habilidad no encontrada")
    return {"mensaje": "Habilidad eliminada del usuario"}

@app.get("/vista/usuarios/tecnologias", response_model=List[UsuarioTecnologiaVista])
async def vista_usuarios_tecnologias(user=Depends(obtener_usuario_actual)):
    rows = await database.fetch_all("""
        SELECT
            usuario_tecnologia_id AS usuario_tecnologia_id,
            usuario_id,
            username,
            tecnologia_id,
            nombre_tecnologia,
            nivel,
            vigente
        FROM v_usuario_tecnologia
        ORDER BY username, nombre_tecnologia
    """)
    return [dict(r) for r in rows]


@app.get("/usuarios/roles", response_model=List[UsuarioRolOut])
async def usuarios_roles_legacy(user=Depends(obtener_usuario_actual)):
    return await vista_usuarios_roles(user)


@app.get("/usuarios/tecnologias", response_model=List[UsuarioTecnologiaVista])
async def usuarios_tecnologias_legacy(user=Depends(obtener_usuario_actual)):
    return await vista_usuarios_tecnologias(user)

# ======================
# DOCS
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
# Login Microsoft
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

@app.get("/version")
async def obtener_version():
    row = await database.fetch_one("SELECT version()")
    return {"version": row["version"]}