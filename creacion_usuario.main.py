from fastapi import FastApi, HTTPException
from pydantic import BaseModel

app = FastApi()

class USUARIO (BaseModel):
    id: int
    nombre: str
    email: str

usuarios = []

@app.post("/usuarios/")
def crear_usuario(usuario:Usuario):
    usuarios.append(usuario)
    return {"mensaje": "Usuario creado correctamente"}

@app.post("/usuarios/")
def listar_usuarios():
    return usuarios

@app.put("/usuarios/{usuario_id}")
def obtener_usuario (usuario_id:int):
    for usuario in usuarios:
        if usuario.id==usuario_id:
            return usuario
        
    raise HTTPException(status_code=404, detail= "Usuario no encontrado")

@app.put("/usuarios/{usuario_id}")
def actualizar_usuario(usuario_id: int, usuario_actualizado: Usuario):
    for index, usuario in enumerate (usuarios):
        if usuario.id ==usuario_id:
            usuarios[index]= usuario_actualizado
            return {"mensaje": "usuario actulizado correctamente"}
    
    raise HTTPException(status_code=404, datail="Usuario no encontrado")

@app.delete("/usuarios/{usuario_id}")
def eliminar_usuario(usuario_id: int):
    for index, usuario  in enumerate(usuarios):
        if usuario.id == usuario_id:
            usuarios.pop(index)
            return{"mensaje": "Usuario eliminado correctamente"}
    
    raise HTTPException(status_code =404, detail="ususario no encontrado")
