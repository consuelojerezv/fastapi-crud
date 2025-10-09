from __future__ import annotations
from typing import Optional, Union
from datetime import date, datetime, timedelta
import os
import bcrypt
import databases
from fastapi import FastAPI, HTTPException, Depends, Query, Body
from fastapi.responses import JSONResponse, RedirectResponse   
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

database = databases.Database(DATABASE_URL)

app = FastAPI(title="Proyecto API")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

ALLOWED_ORIGINS = [
    # IP directa (http/https y con/sin puerto)
    "http://186.64.122.150",
    "http://186.64.122.150:80",
    "http://186.64.122.150:8081",
    "https://186.64.122.150",
    "https://186.64.122.150:443",
    # dominios
    "http://proyectos.edu",
    "http://www.proyectos.edu",
    "https://proyectos.edu",
    "https://www.proyectos.edu",
    # dev local
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

# ======================
# CATALOG CODES (parametro)
# ======================
PROP_EST_COTIZ = "cotiz"   # Cotizada
PROP_EST_ADJU  = "adju"    # Adjudicada
PROP_EST_CANC  = "canc"    # Cancelada (nuevo)

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
    anio: str
    tipo: str
    correlativo: int = 0
    cod_cliente: str
    nombre_propuesta: str
    sponsor: Optional[str] = None
    tiempo_estimado: Optional[Union[str, float]] = None  
    estado: str
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
    nombre_auto: Optional[str] = None  # virtual

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
    hito: Optional[int] = Field(None, ge=0, le=4)

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

class ParametroIn(BaseModel):
    tipo: str = Field(..., max_length=32)
    codigo: str = Field(..., max_length=5)       
    valor: str = Field(..., max_length=50)

class ParametroOut(ParametroIn):
    id: int

# ==========
# HELPERS
# ==========
def build_nombre_auto(anio: str | None, tipo: str | None, correlativo: int | None, cod: str | None) -> str:
    a = (anio or "").strip()
    t = (tipo or "").strip().upper()
    c = (cod or "").strip().upper()
    corr = int(correlativo or 0)
    return f"PROP_{a}_{t}_{corr:04d}_{c}"

def parse_tiempo_half_steps(val: Optional[Union[str, float, int]]) -> Optional[float]:
    """
    Acepta 0.5, 1, '0,5', '1.0', '', None.
    Valida que sea múltiplo de 0.5 si viene con valor.
    """
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
    """
    Crea una propuesta con correlativo automático por (año, cliente).
    Reglas claves:
      - estado por defecto = COTIZADA (cotiz)
      - tiempo_estimado en múltiplos de 0.5 (acepta '0,5')
      - sponsor, cliente y tiempo son obligatorios
    """
    try:
        # Validaciones mínimas y normalizaciones
        p_anio = (p.anio or "").strip()
        if len(p_anio) != 4 or not p_anio.isdigit():
            raise HTTPException(400, "El año debe tener 4 dígitos (ej: 2025)")

        p_tipo   = (p.tipo or "").strip().upper()
        p_cod    = (p.cod_cliente or "").strip().upper()
        p_nombre = (p.nombre_propuesta or "").strip()
        p_spons  = (p.sponsor or "").strip()
        p_estado = ((p.estado or PROP_EST_COTIZ).strip().lower())  # cat. 'prop_estado'

        # Obligatorios (según requerimiento)
        if not p_cod:
            raise HTTPException(400, "El cliente es obligatorio")
        if not p_spons:
            raise HTTPException(400, "El sponsor es obligatorio")

        # tiempo_estimado: múltiplos de 0.5
        try:
            t_est = parse_tiempo_half_steps(p.tiempo_estimado)
        except ValueError as ve:
            raise HTTPException(400, str(ve))
        if t_est is None:
            raise HTTPException(400, "El tiempo estimado es obligatorio")

        async with database.transaction():
            # Lock estable para no duplicar correlativos simultáneos
            await _advisory_lock_por_anio_cliente(p_anio, p_cod)

            # siguiente correlativo por (año, cliente)
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
                    "estado": p_estado,
                    "usuario_id": p.usuario_id,
                },
            )

        d = dict(row)
        d["eliminado"]   = (d["estado"].upper() == "ELIMINADO")
        d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
        return d

    except HTTPException:
        raise
    except Exception as e:
        print("crear_propuesta error:", repr(e))
        raise HTTPException(400, f"Error al crear propuesta: {e}")

@app.get("/propuestas/elegibles", response_model=list[PropuestaOut])
async def listar_propuestas_elegibles():
    """
    Devuelve propuestas ADJUDICADAS y NO tomadas por otro proyecto,
    y que no estén eliminadas.
    """
    rows = await database.fetch_all(
        """
        SELECT
          p.id,
          RTRIM(p."año")        AS anio,
          RTRIM(p.tipo)         AS tipo,
          p.correlativo         AS correlativo,
          RTRIM(p.cod_cliente)  AS cod_cliente,
          p.nombre_propuesta    AS nombre_propuesta,
          RTRIM(p.estado)       AS estado,
          p.fecha_estado        AS fecha_estado,
          COALESCE(p.usuario_id, 0) AS usuario_id,
          COALESCE(p.eliminado, FALSE) AS eliminado
        FROM propuesta p
        WHERE COALESCE(p.eliminado, FALSE) = FALSE
          AND RTRIM(LOWER(p.estado)) = :adju
          AND NOT EXISTS (
                SELECT 1
                  FROM proyecto pr
                 WHERE pr.propuesta_id = p.id
                   AND RTRIM(UPPER(pr.estado)) <> 'ELIMINADO'
          )
        ORDER BY p.id DESC
        """,
        values={"adju": PROP_EST_ADJU},
    )

    out = []
    for r in rows:
        d = dict(r)
        d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
        out.append(d)
    return out

@app.get("/propuestas/", response_model=list[PropuestaOut])
async def listar_propuestas(
    incluir_eliminado: bool = Query(False),
    solo_disponibles: bool = Query(False),
):
    filtros = []
    vals: dict = {}

    if not incluir_eliminado:
        filtros.append("COALESCE(p.eliminado, FALSE) = FALSE")

    # Si piden solo adjudicadas y libres (sin proyecto asociado)
    if solo_disponibles:
        filtros.append("RTRIM(UPPER(p.estado)) = 'ADJUDICADA'")
        filtros.append(
            "NOT EXISTS (SELECT 1 FROM proyecto pr WHERE pr.propuesta_id = p.id)"
        )

    where_sql = ("WHERE " + " AND ".join(filtros)) if filtros else ""

    q = f"""
        SELECT
          p.id,
          RTRIM(p."año")        AS anio,
          RTRIM(p.tipo)         AS tipo,
          p.correlativo         AS correlativo,
          RTRIM(p.cod_cliente)  AS cod_cliente,
          p.nombre_propuesta    AS nombre_propuesta,
          RTRIM(p.estado)       AS estado,
          p.fecha_estado        AS fecha_estado,
          COALESCE(p.usuario_id, 0) AS usuario_id,
          COALESCE(p.eliminado, FALSE) AS eliminado
        FROM propuesta p
        {where_sql}
        ORDER BY p.id DESC
    """
    rows = await database.fetch_all(q, values=vals)
    out = []
    for r in rows:
        d = dict(r)
        # si quieres enviar nombre_auto desde back (opcional)
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
    if "tiempo_estimado" in data:
        data["tiempo_estimado"] = parse_tiempo_half_steps(data["tiempo_estimado"])

    # Trae actual para comparar
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
    """
    Lock transaccional estable por combinación (año, cliente),
    evitando duplicar correlativos al crear propuestas simultáneas.
    Se usa un solo parámetro de texto para evitar errores de binding y tipos.
    """
    key = f"{int(anio):04d}|{cod.strip().upper()}"
    sql = "SELECT pg_advisory_xact_lock(hashtextextended(:k, 0));"
    await database.fetch_one(sql, values={"k": key})



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

@app.post("/parametros/", response_model=ParametroOut)
async def crear_parametro(p: ParametroIn, usuario_actual=Depends(obtener_usuario_actual)):
    try:
        row = await database.fetch_one("""
            INSERT INTO parametro (tipo, codigo, valor, usuario_id)
            VALUES (:tipo, :codigo, :valor, :uid)
            RETURNING id, rtrim(tipo) AS tipo, rtrim(codigo) AS codigo, valor
        """, values={**p.dict(), "uid": usuario_actual["id"]})
        return dict(row)
    except Exception as e:
        # si tienes unique(tipo,codigo) esto atrapará duplicados
        raise HTTPException(400, detail=f"No se pudo crear el parámetro: {e}")

@app.patch("/parametros/{id}", response_model=ParametroOut)
async def actualizar_parametro(id: int, p: ParametroIn, usuario_actual=Depends(obtener_usuario_actual)):
    row = await database.fetch_one("""
        UPDATE parametro
           SET tipo = :tipo, codigo = :codigo, valor = :valor, usuario_id = :uid
         WHERE id = :id
     RETURNING id, rtrim(tipo) AS tipo, rtrim(codigo) AS codigo, valor
    """, values={**p.dict(), "uid": usuario_actual["id"], "id": id})
    if not row:
        raise HTTPException(404, detail="Parámetro no encontrado")
    return dict(row)

@app.delete("/parametros/{id}")
async def eliminar_parametro(id: int, usuario_actual=Depends(obtener_usuario_actual)):
    row = await database.fetch_one("DELETE FROM parametro WHERE id = :id RETURNING id", values={"id": id})
    if not row:
        raise HTTPException(404, detail="Parámetro no encontrado")
    return {"ok": True}

# ======================
# PROYECTOS
# ======================
HITO_MAP = {0: "ANALI", 1: "DESAR", 2: "QA", 3: "GARAN", 4: "DOCUM"}

@app.post("/proyectos/", response_model=ProyectoOut)
async def crear_proyecto(p: ProyectoIn):
    """
    Crea un proyecto SOLO si su propuesta:
      - existe
      - está ADJUDICADA (prop_estado = 'adju')
      - no tiene otro proyecto activo (no eliminado)
    """
    # 1) Propuesta existe y está adjudicada
    prop = await database.fetch_one(
        """
        SELECT
          p.id,
          RTRIM(p."año")       AS anio,
          RTRIM(p.tipo)        AS tipo,
          p.correlativo        AS correlativo,
          RTRIM(p.cod_cliente) AS cod_cliente,
          RTRIM(p.estado)      AS estado
        FROM propuesta p
        WHERE p.id = :id
        """,
        values={"id": p.propuesta_id},
    )
    if not prop:
        raise HTTPException(404, "Propuesta no encontrada")

    if (prop["estado"] or "").strip().lower() != PROP_EST_ADJU:
        raise HTTPException(400, "La propuesta debe estar ADJUDICADA para crear un proyecto")

    # 2) Asegurar que no esté tomada por otro proyecto
    taken = await database.fetch_one(
        """
        SELECT 1
          FROM proyecto pr
         WHERE pr.propuesta_id = :pid
           AND RTRIM(UPPER(pr.estado)) <> 'ELIMINADO'
         LIMIT 1
        """,
        values={"pid": p.propuesta_id},
    )
    if taken:
        raise HTTPException(409, "La propuesta ya está asociada a otro proyecto activo")

    # 3) Insertar proyecto
    ins = await database.fetch_one(
        """
        INSERT INTO proyecto
            (propuesta_id, fecha_inicio, fecha_termino, tipo_facturacion,
             estado, fecha_estado, jp_cliente)
        VALUES
            (:propuesta_id, :fecha_inicio, :fecha_termino, :tipo_facturacion,
             :estado, :fecha_estado, :jp_cliente)
        RETURNING id
        """,
        values={
            "propuesta_id": p.propuesta_id,
            "fecha_inicio": p.fecha_inicio,
            "fecha_termino": p.fecha_termino,
            "tipo_facturacion": (p.tipo_facturacion or "").strip().upper(),
            "estado": (p.estado or "").strip().upper(),
            "fecha_estado": p.fecha_estado,
            "jp_cliente": p.jp_cliente,
        },
    )

    # 4) Devolver con datos compuestos (nombre_auto, etc.)
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
        filtros.append("("
                       "COALESCE(pr.usuario_id, 0) = :mi_id "
                       "OR LOWER(rtrim(COALESCE(pr.jp_cliente, ''))) = LOWER(:mi_nombre)"
                       ")")
        vals["mi_id"] = usuario_actual["id"]
        vals["mi_nombre"] = usuario_actual["username"].strip()

    where_sql = ("WHERE " + " AND ".join(filtros)) if filtros else ""

    q = f"""
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
    if not row:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"])
    for k in ("tipo", "correlativo", "cod_cliente"):
        d.pop(k, None)
    return d

@app.patch("/proyectos/{proyecto_id}", response_model=ProyectoOut)
async def patch_proyecto(proyecto_id: int, body: dict = Body(...)):
    """
    Actualiza campos del proyecto.
    Validaciones:
      - Si se cambia la propuesta_id → debe ser ADJUDICADA y no tomada.
      - Actualiza fecha_estado automáticamente si cambia el estado.
    """
    allowed = {
        "propuesta_id", "fecha_inicio", "fecha_termino",
        "tipo_facturacion", "estado", "fecha_estado", "jp_cliente"
    }
    data = {k: v for k, v in body.items() if k in allowed}
    if not data:
        raise HTTPException(status_code=400, detail="Nada para actualizar")

    # Normalización básica
    if "estado" in data and isinstance(data["estado"], str):
        data["estado"] = data["estado"].strip().upper()
    if "tipo_facturacion" in data and isinstance(data["tipo_facturacion"], str):
        data["tipo_facturacion"] = data["tipo_facturacion"].strip().upper()

    # Si cambian la propuesta_id, validar
    if "propuesta_id" in data:
        nueva_prop = await database.fetch_one(
            """
            SELECT
              id, rtrim(estado) AS estado
            FROM propuesta
            WHERE id = :id
            """,
            values={"id": data["propuesta_id"]},
        )
        if not nueva_prop:
            raise HTTPException(404, "La propuesta indicada no existe")

        if (nueva_prop["estado"] or "").strip().lower() != PROP_EST_ADJU:
            raise HTTPException(
                400, "La propuesta asignada debe estar ADJUDICADA"
            )

        # Evita usar una propuesta ya tomada por otro proyecto
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
            raise HTTPException(
                409, "Esa propuesta ya está asignada a otro proyecto activo"
            )

    # Construcción del UPDATE
    set_parts, vals = [], {"id": proyecto_id}
    for k, v in data.items():
        set_parts.append(f"{k} = :{k}")
        vals[k] = v

    # Si cambia el estado y no se envía fecha_estado, la define a hoy
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

    # Devuelve el registro actualizado con nombre_auto
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
    if not row:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    d = dict(row)
    d["nombre_auto"] = build_nombre_auto(
        d["anio"], d["tipo"], d["correlativo"], d["cod_cliente"]
    )
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
# AVANCES (y helper de facturas por hito)
# =====================================================
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
            "estado": estado_proyecto,
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
    usuario_actual = Depends(obtener_usuario_actual)
):
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

@app.get("/version")
async def obtener_version():
    row = await database.fetch_one("SELECT version()")
    return {"version": row["version"]}
