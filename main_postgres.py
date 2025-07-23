from fastapi import FastAPI, HTTPException, Depends, status, security
from pydantic import BaseModel, EmailStr, constr
import databases
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi


load_dotenv()
SECRET_KEY = os.getenv ("SECRET_KEY")  # DE ESTA FORMA LLAMO DE FORMA SEGURA EL ARCHIVO QUE CONTIENE LA CLAVE 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
#token al hacer el login
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

DATABASE_URL = os.getenv("DATABASE_URL") #LLAMO LA BASE DE DATOS DE FORMA SEGURA

database = databases.Database(DATABASE_URL)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

oauth = OAuth()

async def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    query = "SELECT * FROM usuario WHERE username = :username"
    user = await database.fetch_one(query, values={"username": username})
    if user is None or not user["activo"]:
        raise credentials_exception
    return user

oauth.register(
    name='microsoft',
    client_id=os.getenv("MICROSOFT_CLIENT_ID"),
    client_secret=os.getenv("MICROSOFT_CLIENT_SECRET"),
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    api_base_url='https://graph.microsoft.com/v1.0/',
    client_kwargs={
        'scope': 'User.Read',
    }
)


# Registro de Google 
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    client_kwargs={
        'scope': 'openid email profile',
    }
)


class UsuarioIn(BaseModel):
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=6)
    activo: bool
    email: EmailStr
    fono: constr(min_length=8, max_length=15)

class UsuarioOut(UsuarioIn):
    id: int

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/usuarios/", response_model=UsuarioOut)
async def crear_usuario(usuario: UsuarioIn):
    hashed_password = bcrypt.hashpw(usuario.password.encode('utf-8'), bcrypt.gensalt())

    query = """
        INSERT INTO usuario (username, password, activo, email, fono)
        VALUES (:username, :password, :activo, :email, :fono)
        RETURNING id, username, password, activo, email, fono
    """
    values = {
        "username": usuario.username,
        "password": hashed_password.decode('utf-8'),
        "activo": usuario.activo,
        "email": usuario.email,
        "fono": usuario.fono
    }

    result = await database.fetch_one(query, values=values)

    # Limpiar espacios de fono antes de devolver
    return {
        **dict(result),
        "fono": result["fono"].strip()
    }

@app.get("/usuarios/", response_model=list[UsuarioOut])
async def listar_usuarios(usuario_actual=Depends(obtener_usuario_actual)):
    query = "SELECT * FROM usuario WHERE eliminado = FALSE"
    rows = await database.fetch_all(query)
    return [{**dict(row), "fono": row["fono"].strip()} for row in rows]

@app.get("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def obtener_usuario(usuario_id: int, usuario_actual=Depends(obtener_usuario_actual)):
    query = "SELECT * FROM usuario WHERE id = :id AND eliminado = FALSE"
    result = await database.fetch_one(query, values={"id": usuario_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {**dict(result), "fono": result["fono"].strip()}

@app.put("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def actualizar_usuario(usuario_id: int, usuario: UsuarioIn, usuario_actual=Depends(obtener_usuario_actual)):
    hashed_password = bcrypt.hashpw(usuario.password.encode('utf-8'), bcrypt.gensalt())
    query = """
        UPDATE usuario
        SET username = :username,
            password = :password,
            activo = :activo,
            email = :email,
            fono = :fono
        WHERE id = :id
        RETURNING id, username, password, activo, email, fono
    """
    values = {
        "id": usuario_id,
        "username": usuario.username,
        "password": hashed_password.decode('utf-8'),
        "activo": usuario.activo,
        "email": usuario.email,
        "fono": usuario.fono
    }

    result = await database.fetch_one(query, values=values)
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {**dict(result), "fono": result["fono"].strip()}

@app.delete("/usuarios/{usuario_id}")
async def eliminar_usuario(usuario_id: int, usuario_actual=Depends(obtener_usuario_actual)):
    query = """
        UPDATE usuario
        SET eliminado = TRUE
        WHERE id = :id AND eliminado = FALSE
        RETURNING id
    """
    result = await database.fetch_one(query, values={"id": usuario_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado o ya estaba eliminado")
    return {"mensaje": "Usuario marcado como eliminado"}


class LoginData(BaseModel):
    username: str
    password: str

class PasswordChange(BaseModel):
    nueva_password: constr(min_length=6)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

async def obtener_usuario_actual(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    query = "SELECT * FROM usuario WHERE username = :username"
    user = await database.fetch_one(query, values={"username": username})
    if user is None:
        raise credentials_exception
    return user

@app.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    query = "SELECT * FROM usuario WHERE username = :username AND eliminado = FALSE"
    user = await database.fetch_one(query, values={"username": form_data.username})
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")

    if not bcrypt.checkpw(form_data.password.encode('utf-8'), user["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user["username"], "exp": expire}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}

@app.post("/cambiar_password")
async def cambiar_password(datos: PasswordChange, usuario_actual=Depends(obtener_usuario_actual)):
    hashed_password = bcrypt.hashpw(datos.nueva_password.encode('utf-8'), bcrypt.gensalt())
    query = """
        UPDATE usuario
        SET password = :password
        WHERE username = :username
    """
    await database.execute(query, values={
        "password": hashed_password.decode('utf-8'),
        "username": usuario_actual["username"]
    })
    return {"mensaje": "Contraseña actualizada correctamente"}


#MICROSOFT
@app.get("/login-microsoft")
async def login_microsoft(request: Request):
    redirect_uri = os.getenv("MICROSOFT_REDIRECT_URI")
    return await oauth.microsoft.authorize_redirect(request, redirect_uri)

@app.get("/login-microsoft/callback")
async def auth_microsoft_callback(request: Request):
    try:
        token = await oauth.microsoft.authorize_access_token(request)
        user_data = await oauth.microsoft.get("me", token=token)
        profile = user_data.json()
        return {"mensaje": "Login exitoso con Microsoft", "usuario": profile}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en login de Microsoft: {str(e)}")


#GOOGLE

@app.get("/login-google")
async def login_google(request: Request):
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/login-google/callback")
async def google_callback(request: Request):
    try:
        # 1. Obtener token
        token = await oauth.google.authorize_access_token(request)
        user_data = await oauth.google.get("userinfo", token=token)
        profile = user_data.json()

        email = profile.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="No se pudo obtener el correo")

        # 2. Buscar en la BD
        query = "SELECT * FROM usuario WHERE email = :email"
        user = await database.fetch_one(query, values={"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no registrado")

        if not user["activo"]:
            raise HTTPException(status_code=403, detail="Usuario inactivo")

        # 3. Crear token
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {"sub": user["username"], "exp": expire}
        token_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {
            "mensaje": "Login con Google exitoso",
            "usuario": {
                "username": user["username"],
                "email": user["email"],
                "fono": user["fono"].strip()
            },
            "access_token": token_jwt,
            "token_type": "bearer"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en login con Google: {str(e)}")


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui(token: str = Depends(oauth2_scheme)):
    # Validar token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    return get_swagger_ui_html(openapi_url="/openapi.json", title="Documentación protegida")

@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(token: str = Depends(oauth2_scheme)):
    # Validar token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    return JSONResponse(get_openapi(title=app.title, version=app.version, routes=app.routes))

