import jwt from "jsonwebtoken"
import Usuario from "../models/Usuario.js"

const verificarAutenticacion = async (req, res, next) => {
    const { authorization } = req.headers
    if (!authorization) return res.status(401).json({ msg: "Acceso denegado: token no enviado" })

    const [esquema, token] = authorization.split(" ")
    if (esquema !== "Bearer" || !token)
        return res.status(401).json({ msg: "Formato de token inválido. Usa: Authorization: Bearer <token>" })

    let payload
    try {
        payload = jwt.verify(token, process.env.JWT_SECRET)
    } catch (error) {
        const msg = error.name === "TokenExpiredError"
            ? "La sesión ha expirado, inicia sesión nuevamente"
            : "Token inválido"
        return res.status(401).json({ msg })
    }

    const usuario = await Usuario.findById(payload.id)
        .select("-password -token -intentosFallidos -bloqueadoHasta -createdAt -updatedAt -__v")
    if (!usuario) return res.status(401).json({ msg: "Token inválido: el usuario ya no existe" })
    if (!usuario.status) return res.status(403).json({ msg: "La cuenta está deshabilitada" })
    if (!usuario.confirmEmail) return res.status(403).json({ msg: "Debes confirmar tu cuenta" })

    req.usuarioHeader = usuario
    req.rol = usuario.rol // el rol se toma de la BDD, no del token: los cambios de rol aplican de inmediato
    next()
}

// Restringe el acceso a ciertos roles
const permitirRoles = (...roles) => (req, res, next) => {
    if (!roles.includes(req.rol)) return res.status(403).json({ msg: "No tienes permisos para esta acción" })
    next()
}

export { verificarAutenticacion, permitirRoles }
