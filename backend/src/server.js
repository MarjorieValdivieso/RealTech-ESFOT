// Requerir módulos
import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import routerUsuarios from "./routers/usuario_routes.js"

// Configuraciones
dotenv.config()

// Inicializaciones
const app = express()

// Variables globales
app.set("port", process.env.PORT || 3000)

// Middlewares
app.use(express.json({ limit: "10kb" }))
app.use(cors({ origin: process.env.URL_FRONTEND || "*" }))

// Rutas
app.get("/", (req, res) => res.send("Bienvenido a la API de RealTech-ESFOT"))
app.use("/api", routerUsuarios)

// Ruta no encontrada
app.use((req, res) => res.status(404).json({ msg: "Endpoint no encontrado" }))

// Manejo de errores
app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ msg: "El cuerpo de la petición no es un JSON válido" })
    if (err.type === "entity.too.large") return res.status(413).json({ msg: "La petición es demasiado grande" })
    console.error(err)
    res.status(500).json({ msg: "Error interno del servidor" })
})

export default app
