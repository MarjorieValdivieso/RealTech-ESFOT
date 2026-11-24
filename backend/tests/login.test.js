import { test, describe, before, after, beforeEach, mock } from "node:test"
import assert from "node:assert/strict"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"

process.env.JWT_SECRET = "clave_de_pruebas"
process.env.MAX_LOGIN_ATTEMPTS = "3"
process.env.LOGIN_LOCK_MINUTES = "15"

const { default: app } = await import("../src/server.js")
const { default: Usuario } = await import("../src/models/Usuario.js")

const PASSWORD = "123456"
let servidor, base, usuario, consultas

const post = (ruta, body, headers = {}) =>
    fetch(`${base}${ruta}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: typeof body === "string" ? body : JSON.stringify(body)
    })

// Crea un usuario en memoria (sin BDD) con save() simulado
const crearUsuario = async (extra = {}) => {
    const u = new Usuario({
        nombre: "Ana", apellido: "Pérez", email: "ana@epn.edu.ec",
        password: await bcrypt.hash(PASSWORD, 4),
        confirmEmail: true, ...extra
    })
    u.save = async () => u
    return u
}

before(async () => {
    servidor = app.listen(0)
    base = `http://127.0.0.1:${servidor.address().port}`
})
after(() => servidor.close())

beforeEach(async () => {
    usuario = await crearUsuario()
    consultas = []
    mock.method(Usuario, "findOne", async (filtro) => {
        consultas.push(filtro)
        return filtro.email === usuario.email ? usuario : null
    })
    mock.method(Usuario, "findById", () => ({ select: async () => usuario }))
})

describe("POST /api/login - validaciones", () => {
    test("400 si no se envía cuerpo", async () => {
        const res = await fetch(`${base}/api/login`, { method: "POST" })
        assert.equal(res.status, 400)
    })
    test("400 si faltan campos", async () => {
        const res = await post("/api/login", { email: "ana@epn.edu.ec", password: "" })
        assert.equal(res.status, 400)
    })
    test("400 ante inyección NoSQL (email como objeto)", async () => {
        const res = await post("/api/login", { email: { $ne: null }, password: PASSWORD })
        assert.equal(res.status, 400)
        assert.equal(consultas.length, 0, "no debe consultar la BDD")
    })
    test("400 si el correo tiene formato inválido", async () => {
        const res = await post("/api/login", { email: "no-es-correo", password: PASSWORD })
        assert.equal(res.status, 400)
    })
    test("400 si el JSON está mal formado", async () => {
        const res = await post("/api/login", "{email:")
        assert.equal(res.status, 400)
    })
})

describe("POST /api/login - credenciales", () => {
    test("401 genérico si el correo no existe", async () => {
        const res = await post("/api/login", { email: "nadie@epn.edu.ec", password: PASSWORD })
        assert.equal(res.status, 401)
        assert.equal((await res.json()).msg, "Correo o password incorrectos")
    })
    test("401 con el MISMO mensaje si el password es incorrecto", async () => {
        const res = await post("/api/login", { email: usuario.email, password: "otro-password" })
        const data = await res.json()
        assert.equal(res.status, 401)
        assert.equal(data.msg, "Correo o password incorrectos")
        assert.equal(data.intentosRestantes, 2)
    })
    test("normaliza el correo (espacios y mayúsculas)", async () => {
        const res = await post("/api/login", { email: "  ANA@EPN.EDU.EC ", password: PASSWORD })
        assert.equal(res.status, 200)
        assert.equal(consultas[0].email, "ana@epn.edu.ec")
    })
})

describe("POST /api/login - estado de la cuenta", () => {
    test("403 si no confirmó el correo (con password correcto)", async () => {
        usuario.confirmEmail = false
        const res = await post("/api/login", { email: usuario.email, password: PASSWORD })
        assert.equal(res.status, 403)
    })
    test("403 si la cuenta está deshabilitada", async () => {
        usuario.status = false
        const res = await post("/api/login", { email: usuario.email, password: PASSWORD })
        assert.equal(res.status, 403)
    })
    test("con password incorrecto NO revela que la cuenta no está confirmada", async () => {
        usuario.confirmEmail = false
        const res = await post("/api/login", { email: usuario.email, password: "mal" })
        assert.equal(res.status, 401)
    })
})

describe("POST /api/login - bloqueo por intentos fallidos", () => {
    test("bloquea (423) al llegar al máximo y rechaza incluso el password correcto", async () => {
        for (let i = 0; i < 2; i++) {
            const r = await post("/api/login", { email: usuario.email, password: "mal" })
            assert.equal(r.status, 401)
        }
        const tercero = await post("/api/login", { email: usuario.email, password: "mal" })
        assert.equal(tercero.status, 423)
        assert.ok(usuario.estaBloqueado())

        const correcto = await post("/api/login", { email: usuario.email, password: PASSWORD })
        assert.equal(correcto.status, 423)
    })
    test("un login exitoso reinicia el contador", async () => {
        await post("/api/login", { email: usuario.email, password: "mal" })
        assert.equal(usuario.intentosFallidos, 1)
        const res = await post("/api/login", { email: usuario.email, password: PASSWORD })
        assert.equal(res.status, 200)
        assert.equal(usuario.intentosFallidos, 0)
        assert.ok(usuario.ultimoLogin)
    })
    test("el bloqueo vencido permite volver a iniciar sesión", async () => {
        usuario.bloqueadoHasta = new Date(Date.now() - 1000)
        const res = await post("/api/login", { email: usuario.email, password: PASSWORD })
        assert.equal(res.status, 200)
        assert.equal(usuario.bloqueadoHasta, null)
    })
})

describe("POST /api/login - éxito", () => {
    test("200 con JWT válido y sin datos sensibles", async () => {
        const res = await post("/api/login", { email: usuario.email, password: PASSWORD })
        const data = await res.json()
        assert.equal(res.status, 200)
        const payload = jwt.verify(data.token, process.env.JWT_SECRET)
        assert.equal(payload.id, usuario._id.toString())
        assert.equal(payload.rol, "estudiante")
        assert.equal(data.rol, "estudiante")
        assert.equal(data.nivelComplejidad, "basico")
        for (const campo of ["password", "token_otp", "intentosFallidos", "bloqueadoHasta"])
            assert.equal(campo in data, false, `no debe exponer ${campo}`)
    })
})

describe("Middleware verificarAutenticacion (GET /api/perfil)", () => {
    const perfil = (headers) => fetch(`${base}/api/perfil`, { headers })
    const tokenDe = (u, opciones = {}) =>
        jwt.sign({ id: u._id, rol: u.rol }, process.env.JWT_SECRET, { expiresIn: "1d", ...opciones })

    test("401 sin token", async () => assert.equal((await perfil({})).status, 401))
    test("401 si el esquema no es Bearer", async () =>
        assert.equal((await perfil({ Authorization: tokenDe(usuario) })).status, 401))
    test("401 con token inválido", async () =>
        assert.equal((await perfil({ Authorization: "Bearer abc.def.ghi" })).status, 401))
    test("401 con token expirado y mensaje específico", async () => {
        const res = await perfil({ Authorization: `Bearer ${tokenDe(usuario, { expiresIn: -10 })}` })
        assert.equal(res.status, 401)
        assert.match((await res.json()).msg, /expirado/)
    })
    test("403 si la cuenta fue deshabilitada después del login", async () => {
        usuario.status = false
        const res = await perfil({ Authorization: `Bearer ${tokenDe(usuario)}` })
        assert.equal(res.status, 403)
    })
    test("200 con token válido", async () => {
        const res = await perfil({ Authorization: `Bearer ${tokenDe(usuario)}` })
        const data = await res.json()
        assert.equal(res.status, 200)
        assert.equal(data.email, usuario.email)
    })
})
