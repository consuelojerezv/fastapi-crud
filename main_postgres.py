from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, constr
import databases
import bcrypt

DATABASE_URL = "postgresql://consu:Consuelo123%23@186.64.122.150:5432/proyectos"

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
