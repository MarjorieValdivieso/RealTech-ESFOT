import jwt from "jsonwebtoken"
import { duracionJWT } from "../config/auth.js"

const crearTokenJWT = (id, rol) => {
    if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET no está definido en el .env")
    return jwt.sign({ id, rol }, process.env.JWT_SECRET, { expiresIn: duracionJWT() })
}

export default crearTokenJWT
