from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, constr
import databases
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os

load_dotenv()




SECRET_KEY = os.getenv ("SECRET_KEY")  # DE ESTA FORMA LLAMO DE FORMA SEGURA EL ARCHIVO QUE CONTIENE LA CLAVE 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


DATABASE_URL = os.getenv("DATABASE_URL") #LLAMO LA BASE DE DATOS DE FORMA SEGURA

database = databases.Database(DATABASE_URL)

app = FastAPI()

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
async def listar_usuarios():
    query = "SELECT * FROM usuario"
    rows = await database.fetch_all(query)
    # Limpiar fono en todos los registros
    return [
        {**dict(row), "fono": row["fono"].strip()} for row in rows
    ]

@app.get("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def obtener_usuario(usuario_id: int):
    query = "SELECT * FROM usuario WHERE id = :id"
    result = await database.fetch_one(query, values={"id": usuario_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {
        **dict(result),
        "fono": result["fono"].strip()
    }

@app.put("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def actualizar_usuario(usuario_id: int, usuario: UsuarioIn):
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
    return {
        **dict(result),
        "fono": result["fono"].strip()
    }

@app.delete("/usuarios/{usuario_id}")
async def eliminar_usuario(usuario_id: int):
    query = "DELETE FROM usuario WHERE id = :id RETURNING id"
    result = await database.fetch_one(query, values={"id": usuario_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"mensaje": "Usuario eliminado correctamente"}

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
    query = "SELECT * FROM usuario WHERE username = :username"
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
