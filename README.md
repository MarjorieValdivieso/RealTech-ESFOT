# RealTech-ESFOT

Sistema web de simulación de pruebas técnicas adaptativas para estudiantes de la ESFOT.

## Integrantes

- Marjorie Valdivieso
- Emely Bone
- Maria Jose Paredes

---

## Sprint 0 – Configuraciones iniciales

### Backend

- Instalación de Node.js, MongoDB y Postman.
- Creación del proyecto `backend` con ES Modules y scripts `start` / `dev`.
- Instalación de dependencias: `express`, `mongoose`, `dotenv`, `bcryptjs`, `jsonwebtoken`, `nodemailer`, `cors`.
- Estructura de carpetas: `controllers`, `routers`, `models`, `middlewares`, `helpers`, `config`.
- Archivos `.env`, `.env.example` y `.gitignore`.
- Servidor Express (`server.js`) con `express.json()`, `cors` y manejo de errores.
- Conexión a MongoDB (`database.js`).
- Repositorio en GitHub con ramas por integrante.

```bash
cd backend
npm install
cp .env.example .env
npm run dev
```

### Frontend

- Creación del proyecto `frontend` con Vite + React.
- Instalación de dependencias: `react-router`, `axios`, `react-hook-form`, `react-toastify`, `react-icons`, `tailwindcss`.
- Configuración de Tailwind CSS y ESLint.
- Estructura de carpetas: `pages`, `components`, `layout`, `hooks`, `assets`.
- Configuración de rutas en `App.jsx` (públicas y privadas en `/dashboard`).
- Pantallas base: Home, Login, Register, Forgot, Reset, Confirm, Panel y Profile.

```bash
cd frontend
npm install
npm run dev
```

---

## Sprint 1 – Login a nivel de backend

**Endpoint:** `POST /api/login`

```json
{ "email": "ana@epn.edu.ec", "password": "123456" }
```

Si las credenciales son correctas, devuelve un token JWT y los datos del usuario.

| Código | Significado |
|:------:|-------------|
| 200 | Login correcto |
| 400 | Campos vacíos o con formato inválido |
| 401 | Correo o password incorrectos |
| 403 | Cuenta sin confirmar o deshabilitada |
| 423 | Cuenta bloqueada por demasiados intentos fallidos |

**Lo desarrollado:**

- Validación de campos y normalización del correo.
- Verificación del password cifrado con bcrypt.
- Generación del token JWT con `id` y `rol`.
- Validación de cuenta confirmada y habilitada.
- Bloqueo temporal tras 5 intentos fallidos.
- Middleware `verificarAutenticacion` para proteger rutas con el token.
- Script `npm run seed` para crear cuentas de admin y docente.
- Pruebas automáticas con `npm test`.

**Cómo probar:**

```bash
cd backend
npm install
npm test
```
