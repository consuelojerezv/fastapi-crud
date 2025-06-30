from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import databases

DATABASE_URL = "postgresql://consu:Consuelo123%23@186.64.122.150:5432/proyectos"

database = databases.Database(DATABASE_URL)

app = FastAPI()

# Modelo de entrada y salida
class UsuarioIn(BaseModel):
    username: str
    password: str
    activo: bool
    email: str
    fono: str

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
    query = """
        INSERT INTO usuario (username, password, activo, email, fono)
        VALUES (:username, :password, :activo, :email, :fono)
        RETURNING id, username, password, activo, email, fono
    """
    result = await database.fetch_one(query, values=usuario.dict())
    return result

@app.get("/usuarios/", response_model=list[UsuarioOut])
async def listar_usuarios():
    query = "SELECT * FROM usuario"
    return await database.fetch_all(query)

@app.get("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def obtener_usuario(usuario_id: int):
    query = "SELECT * FROM usuario WHERE id = :id"
    result = await database.fetch_one(query, values={"id": usuario_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return result

@app.put("/usuarios/{usuario_id}", response_model=UsuarioOut)
async def actualizar_usuario(usuario_id: int, usuario: UsuarioIn):
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
    values = {**usuario.dict(), "id": usuario_id}
    result = await database.fetch_one(query, values=values)
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return result

@app.delete("/usuarios/{usuario_id}")
async def eliminar_usuario(usuario_id: int):
    query = "DELETE FROM usuario WHERE id = :id RETURNING id"
    result = await database.fetch_one(query, values={"id": usuario_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"mensaje": "Usuario eliminado correctamente"}
