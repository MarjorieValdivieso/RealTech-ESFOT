import mongoose from "mongoose"
import bcrypt from "bcryptjs"
import Usuario from "../models/Usuario.js"
import crearTokenJWT from "../helpers/crearJWT.js"
import { maxIntentosLogin } from "../config/auth.js"
import { sendMailToRegister, sendMailToRecoveryPassword } from "../config/nodemailer.js"

const registro = async (req, res) => {
    const { nombre, apellido, email, password } = req.body
    if ([nombre, apellido, email, password].some(v => !v || v.trim() === ""))
        return res.status(400).json({ msg: "Lo sentimos, debes llenar todos los campos obligatorios" })
    if (password.length < 6)
        return res.status(400).json({ msg: "El password debe tener al menos 6 caracteres" })

    const existe = await Usuario.findOne({ email })
    if (existe) return res.status(400).json({ msg: "Lo sentimos, el email ya se encuentra registrado" })

    // El rol se asigna siempre como estudiante en el registro público
    const nuevo = new Usuario({ nombre, apellido, email })
    nuevo.password = await nuevo.encryptPassword(password)
    const token = nuevo.createToken()
    await sendMailToRegister(email, token)
    await nuevo.save()
    res.status(201).json({ msg: "Revisa tu correo electrónico para confirmar tu cuenta" })
}

const confirmarMail = async (req, res) => {
    const { token } = req.params
    const usuario = await Usuario.findOne({ token })
    if (!usuario) return res.status(404).json({ msg: "Token inválido o cuenta ya confirmada" })
    usuario.token = null
    usuario.confirmEmail = true
    await usuario.save()
    res.status(200).json({ msg: "Cuenta confirmada, ya puedes iniciar sesión" })
}

// Hash descartable: se compara siempre un password aunque el correo no exista,
// para que el tiempo de respuesta no revele qué correos están registrados.
const HASH_FALSO = bcrypt.hashSync("realtech-esfot-hash-falso", 10)
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const MSG_CREDENCIALES = "Correo o password incorrectos"

const login = async (req, res) => {
    const { email: emailBody, password } = req.body ?? {}

    // Se exigen strings: evita inyección NoSQL (ej. { "email": { "$ne": null } })
    if (typeof emailBody !== "string" || typeof password !== "string")
        return res.status(400).json({ msg: "Debes enviar correo y password como texto" })

    const email = emailBody.trim().toLowerCase()
    if (!email || !password) return res.status(400).json({ msg: "Debes llenar todos los campos" })
    if (!EMAIL_REGEX.test(email)) return res.status(400).json({ msg: "El formato del correo no es válido" })
    if (password.length > 128) return res.status(400).json({ msg: "El password es demasiado largo" })

    const usuario = await Usuario.findOne({ email })
    if (!usuario) {
        await bcrypt.compare(password, HASH_FALSO)
        return res.status(401).json({ msg: MSG_CREDENCIALES })
    }

    // Cuenta bloqueada: ni siquiera se evalúa el password
    if (usuario.estaBloqueado())
        return res.status(423).json({
            msg: `Cuenta bloqueada temporalmente por demasiados intentos fallidos. Intenta de nuevo en ${usuario.minutosRestantesBloqueo()} minuto(s)`
        })

    const ok = await usuario.matchPassword(password)
    if (!ok) {
        await usuario.registrarIntentoFallido()
        if (usuario.estaBloqueado())
            return res.status(423).json({
                msg: `Demasiados intentos fallidos. Cuenta bloqueada por ${usuario.minutosRestantesBloqueo()} minuto(s)`
            })
        return res.status(401).json({
            msg: MSG_CREDENCIALES,
            intentosRestantes: maxIntentosLogin() - usuario.intentosFallidos
        })
    }

    // Estado de la cuenta: solo se informa cuando el password ya fue correcto
    if (!usuario.status) return res.status(403).json({ msg: "La cuenta está deshabilitada" })
    if (!usuario.confirmEmail) return res.status(403).json({ msg: "Debes confirmar tu cuenta antes de iniciar sesión" })

    await usuario.registrarLoginExitoso()

    const token = crearTokenJWT(usuario._id, usuario.rol)
    const { nombre, apellido, celular, carrera, semestre, nivelComplejidad, rol, _id } = usuario
    res.status(200).json({
        msg: `Bienvenido(a) ${nombre}`,
        token, nombre, apellido, celular, carrera, semestre, nivelComplejidad, rol, _id, email: usuario.email
    })
}

const recuperarPassword = async (req, res) => {
    const { email } = req.body
    if (!email) return res.status(400).json({ msg: "Debes ingresar un correo electrónico" })
    const usuario = await Usuario.findOne({ email })
    if (!usuario) return res.status(404).json({ msg: "El usuario no se encuentra registrado" })

    const token = usuario.createToken()
    await usuario.save()
    await sendMailToRecoveryPassword(email, token)
    res.status(200).json({ msg: "Revisa tu correo electrónico para restablecer tu contraseña" })
}

const comprobarTokenPassword = async (req, res) => {
    const { token } = req.params
    const usuario = await Usuario.findOne({ token })
    if (!usuario) return res.status(404).json({ msg: "Token inválido" })
    res.status(200).json({ msg: "Token confirmado, ya puedes crear tu nuevo password" })
}

const crearNuevoPassword = async (req, res) => {
    const { password, confirmpassword } = req.body
    const { token } = req.params
    if (!password || !confirmpassword) return res.status(400).json({ msg: "Debes llenar todos los campos" })
    if (password !== confirmpassword) return res.status(400).json({ msg: "Los passwords no coinciden" })
    if (password.length < 6) return res.status(400).json({ msg: "El password debe tener al menos 6 caracteres" })

    const usuario = await Usuario.findOne({ token })
    if (!usuario) return res.status(404).json({ msg: "Token inválido" })
    usuario.token = null
    usuario.password = await usuario.encryptPassword(password)
    await usuario.save()
    res.status(200).json({ msg: "Password actualizado, ya puedes iniciar sesión" })
}

const perfil = (req, res) => {
    res.status(200).json(req.usuarioHeader)
}

const actualizarPerfil = async (req, res) => {
    const { id } = req.params
    const { nombre, apellido, celular, carrera, semestre, email } = req.body
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ msg: "ID inválido" })
    if (req.usuarioHeader._id.toString() !== id)
        return res.status(403).json({ msg: "Solo puedes editar tu propio perfil" })

    const usuario = await Usuario.findById(id)
    if (!usuario) return res.status(404).json({ msg: "Usuario no encontrado" })

    if (email && email !== usuario.email) {
        const existe = await Usuario.findOne({ email })
        if (existe) return res.status(400).json({ msg: "El email ya se encuentra registrado" })
        usuario.email = email
    }
    usuario.nombre = nombre ?? usuario.nombre
    usuario.apellido = apellido ?? usuario.apellido
    usuario.celular = celular ?? usuario.celular
    usuario.carrera = carrera ?? usuario.carrera
    usuario.semestre = semestre ?? usuario.semestre
    await usuario.save()
    res.status(200).json(usuario)
}

const actualizarPassword = async (req, res) => {
    const { passwordactual, passwordnuevo } = req.body
    if (!passwordactual || !passwordnuevo) return res.status(400).json({ msg: "Debes llenar todos los campos" })
    if (passwordnuevo.length < 6) return res.status(400).json({ msg: "El password nuevo debe tener al menos 6 caracteres" })

    const usuario = await Usuario.findById(req.usuarioHeader._id)
    const ok = await usuario.matchPassword(passwordactual)
    if (!ok) return res.status(400).json({ msg: "El password actual es incorrecto" })

    usuario.password = await usuario.encryptPassword(passwordnuevo)
    await usuario.save()
    res.status(200).json({ msg: "Password actualizado correctamente" })
}

export {
    registro, confirmarMail, login, recuperarPassword, comprobarTokenPassword,
    crearNuevoPassword, perfil, actualizarPerfil, actualizarPassword
}
