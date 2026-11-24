// Parámetros de autenticación. Se leen en tiempo de ejecución (funciones) porque
// los imports de ES Modules se evalúan antes de que dotenv.config() cargue el .env.
const aEnteroPositivo = (valor, porDefecto) => {
    const n = parseInt(valor, 10)
    return Number.isFinite(n) && n > 0 ? n : porDefecto
}

// Intentos fallidos consecutivos antes de bloquear la cuenta
export const maxIntentosLogin = () => aEnteroPositivo(process.env.MAX_LOGIN_ATTEMPTS, 5)

// Minutos que permanece bloqueada la cuenta
export const minutosBloqueo = () => aEnteroPositivo(process.env.LOGIN_LOCK_MINUTES, 15)

// Duración del JWT (formato de jsonwebtoken: "1d", "8h", "30m"...)
export const duracionJWT = () => process.env.JWT_EXPIRES_IN || "1d"
