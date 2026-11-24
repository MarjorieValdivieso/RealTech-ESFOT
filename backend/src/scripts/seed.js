// Crea cuentas de admin y docente ya confirmadas (el registro público solo crea estudiantes).
// Uso: npm run seed
import dotenv from "dotenv"
import mongoose from "mongoose"
import Usuario from "../models/Usuario.js"

dotenv.config()

const cuentas = [
    {
        nombre: "Administrador", apellido: "ESFOT", rol: "admin",
        email: process.env.SEED_ADMIN_EMAIL || "admin@epn.edu.ec",
        password: process.env.SEED_ADMIN_PASSWORD || "Admin12345"
    },
    {
        nombre: "Docente", apellido: "ESFOT", rol: "docente",
        email: process.env.SEED_DOCENTE_EMAIL || "docente@epn.edu.ec",
        password: process.env.SEED_DOCENTE_PASSWORD || "Docente12345"
    }
]

try {
    await mongoose.connect(process.env.MONGODB_URI_LOCAL)
    for (const { password, ...datos } of cuentas) {
        if (await Usuario.findOne({ email: datos.email.toLowerCase() })) {
            console.log(`Ya existe: ${datos.email}`)
            continue
        }
        const usuario = new Usuario({ ...datos, confirmEmail: true })
        usuario.password = await usuario.encryptPassword(password)
        await usuario.save()
        console.log(`Creado (${datos.rol}): ${datos.email}`)
    }
} catch (error) {
    console.error(error)
    process.exitCode = 1
} finally {
    await mongoose.disconnect()
}
