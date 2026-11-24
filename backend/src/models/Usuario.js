import mongoose from "mongoose"
import bcrypt from "bcryptjs"
import { randomBytes } from "node:crypto"
import { maxIntentosLogin, minutosBloqueo } from "../config/auth.js"

const { Schema, model } = mongoose

const usuarioSchema = new Schema({
    nombre: { type: String, required: true, trim: true },
    apellido: { type: String, required: true, trim: true },
    celular: { type: String, trim: true, default: null },
    carrera: { type: String, trim: true, default: null },
    semestre: { type: Number, min: 1, max: 6, default: null },
    email: { type: String, required: true, trim: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    // Nivel de complejidad actual (se ajustará con el motor adaptativo en sprints posteriores)
    nivelComplejidad: {
        type: String,
        enum: ["basico", "intermedio", "avanzado"],
        default: "basico"
    },
    rol: {
        type: String,
        enum: ["estudiante", "docente", "admin"],
        default: "estudiante"
    },
    status: { type: Boolean, default: true },
    token: { type: String, default: null },
    confirmEmail: { type: Boolean, default: false },
    // Seguridad del login (protección contra fuerza bruta)
    intentosFallidos: { type: Number, default: 0 },
    bloqueadoHasta: { type: Date, default: null },
    ultimoLogin: { type: Date, default: null }
}, { timestamps: true })

// Cifrar el password
usuarioSchema.methods.encryptPassword = async function (passwordUser) {
    const salt = await bcrypt.genSalt(10)
    return await bcrypt.hash(passwordUser, salt)
}

// Comparar el password ingresado con el de la BDD
usuarioSchema.methods.matchPassword = async function (passwordUser) {
    return await bcrypt.compare(passwordUser, this.password)
}

// Crear token (OTP) para correos, no es JWT
usuarioSchema.methods.createToken = function () {
    const tokenGenerado = randomBytes(16).toString("hex")
    this.token = tokenGenerado
    return tokenGenerado
}

// ¿La cuenta está bloqueada temporalmente por intentos fallidos?
usuarioSchema.methods.estaBloqueado = function () {
    return Boolean(this.bloqueadoHasta && this.bloqueadoHasta > new Date())
}

// Minutos que faltan para que termine el bloqueo (0 si no está bloqueada)
usuarioSchema.methods.minutosRestantesBloqueo = function () {
    if (!this.estaBloqueado()) return 0
    return Math.ceil((this.bloqueadoHasta - new Date()) / 60000)
}

// Suma un intento fallido y bloquea la cuenta al llegar al límite
usuarioSchema.methods.registrarIntentoFallido = async function () {
    // Si había un bloqueo ya vencido, se parte de cero
    if (this.bloqueadoHasta && this.bloqueadoHasta <= new Date()) {
        this.bloqueadoHasta = null
        this.intentosFallidos = 0
    }
    this.intentosFallidos += 1
    if (this.intentosFallidos >= maxIntentosLogin()) {
        this.bloqueadoHasta = new Date(Date.now() + minutosBloqueo() * 60 * 1000)
        this.intentosFallidos = 0
    }
    await this.save()
}

// Login correcto: limpia contadores y registra la fecha de acceso
usuarioSchema.methods.registrarLoginExitoso = async function () {
    this.intentosFallidos = 0
    this.bloqueadoHasta = null
    this.ultimoLogin = new Date()
    await this.save()
}

export default model("Usuario", usuarioSchema)
