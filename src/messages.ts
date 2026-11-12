export var messages = {
    backchannelLogoutFailed: "back-channel logout to $1 failed (user $2, sid $3)",
    backchannelLogoutSent: "back-channel logout sent to $1 (user $2, sid $3)",
    cancelButton: "Cancel",
    clientsAreReadOnly: "gate-one does not modify clients: they are registered in the database",
    codeLabel: "Code from the authenticator app",
    cookieKeysEmpty: "AUTH_COOKIE_KEYS has no keys",
    createUserUsage: "usage: npm run create-user -- <username>  (the password is read next)",
    databasePoolError: "error in an idle database connection",
    emailPrompt: "email (optional): ",
    enableTotpUsage: "usage: npm run enable-totp -- <username>",
    envVarMustBePositiveInteger: "the environment variable $1 must be a positive integer",
    expiredCleanupFailed: "could not delete the expired records",
    familyNamePrompt: "family name: ",
    inputEnded: "the input ended before all the data was entered",
    generatedKeyLacksComponents: "the generated key lacks the components expected for $1",
    givenNamePrompt: "given name: ",
    internalError: "internal error",
    invalidCode: "Wrong code.",
    invalidCredentials: "Wrong username or password.",
    invalidEmail: "invalid email: $1",
    listeningOn: "gate-one listening on $1",
    logoutButton: "Sign out",
    logoutExplanation: "The session will be closed in every service that uses it.",
    logoutQuestion: "Sign out?",
    logoutTitle: "Sign out",
    mfaRequiredNotEnabled: "this service requires a second factor and the user does not have one",
    missingEnvVar: "missing environment variable $1",
    missingFields: "Missing data.",
    nameRequired: "the given name and the family name are required",
    nonAsciiCredentials: "the username and the password may only contain printable ASCII characters",
    oidcConfigurationAt: "OIDC configuration at $1",
    oidcPayloadInvalid: "an OIDC record in the database is not a JSON object",
    passwordEmpty: "the password must not be empty",
    passwordLabel: "Password",
    passwordPrompt: "password: ",
    providerInternalError: "provider internal error",
    rememberDeviceLabel: "Do not ask again on this device for 30 days",
    resetTotpUsage: "usage: npm run reset-totp -- <username>",
    resourceNotRegistered: "the requested resource is not registered",
    scramInvalidFormat: "the verifier does not have the format SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>",
    scramInvalidIterations: "the SCRAM-SHA-256 verifier has an invalid iteration count",
    scramInvalidKeyLength: "the SCRAM-SHA-256 verifier has keys of invalid length",
    secondFactorTitle: "Second factor",
    signInAgain: "Please sign in again.",
    signInButton: "Sign in",
    signInTitle: "Sign in",
    signingKeyInvalid: "the signing key $1 in the database does not have the expected format",
    startupFailed: "gate-one could not start",
    tooManyAttempts: "Too many failed attempts. Try again later.",
    totpAlreadyEnabled: "the user $1 already has a second factor; reset it first",
    totpCodePrompt: "code shown by the app: ",
    totpEnabled: "second factor enabled for $1",
    totpKeyInvalid: "AUTH_TOTP_KEY must be 32 bytes in base64 (generate it with: openssl rand -base64 32)",
    totpReset: "second factor removed for $1, with its remembered devices",
    totpScanQr: "Scan this QR code with the authenticator app (Microsoft Authenticator, Google Authenticator, ...):",
    totpSecretUnreadable: "the second factor secret of $1 cannot be decrypted with AUTH_TOTP_KEY",
    unhandledError: "unhandled error in gate-one",
    unknownLanguage: "unknown language $1",
    unsupportedInteraction: "Unsupported interaction: $1",
    userAlreadyExists: "the user $1 already exists",
    userCreated: "user $1 created",
    usernameLabel: "Username",
    userNotFound: "the user $1 does not exist",
    verifyButton: "Verify",
}

export var i18n:{
    messages:{
        en:typeof messages,
        [k:string]:Partial<typeof messages>
    }
} = {
    messages:{
        en:messages,
        es:{
            backchannelLogoutFailed: "falló el back-channel logout a $1 (usuario $2, sid $3)",
            backchannelLogoutSent: "back-channel logout enviado a $1 (usuario $2, sid $3)",
            cancelButton: "Cancelar",
            clientsAreReadOnly: "gate-one no modifica clientes: se registran en la base de datos",
            codeLabel: "Código de la aplicación de autenticación",
            cookieKeysEmpty: "AUTH_COOKIE_KEYS no contiene ninguna clave",
            createUserUsage: "uso: npm run create-user -- <usuario>  (la contraseña se ingresa a continuación)",
            databasePoolError: "error en una conexión inactiva a la base de datos",
            emailPrompt: "email (opcional): ",
            enableTotpUsage: "uso: npm run enable-totp -- <usuario>",
            envVarMustBePositiveInteger: "la variable de entorno $1 debe ser un entero positivo",
            expiredCleanupFailed: "no se pudieron borrar los registros vencidos",
            familyNamePrompt: "apellido: ",
            inputEnded: "la entrada terminó antes de ingresar todos los datos",
            generatedKeyLacksComponents: "la clave generada no tiene los componentes esperados para $1",
            givenNamePrompt: "nombre: ",
            internalError: "error interno",
            invalidCode: "Código incorrecto.",
            invalidCredentials: "Usuario o contraseña incorrectos.",
            invalidEmail: "email inválido: $1",
            listeningOn: "gate-one escuchando en $1",
            logoutButton: "Cerrar sesión",
            logoutExplanation: "Se cerrará en todos los servicios que la usan.",
            logoutQuestion: "¿Cerrar la sesión?",
            logoutTitle: "Cerrar sesión",
            mfaRequiredNotEnabled: "este servicio requiere segundo factor y el usuario no lo tiene activado",
            missingEnvVar: "falta la variable de entorno $1",
            missingFields: "Faltan datos.",
            nameRequired: "el nombre y el apellido son obligatorios",
            nonAsciiCredentials: "el usuario y la contraseña solo pueden tener caracteres ASCII imprimibles",
            oidcConfigurationAt: "configuración OIDC en $1",
            oidcPayloadInvalid: "un registro OIDC de la base de datos no es un objeto JSON",
            passwordEmpty: "la contraseña no puede estar vacía",
            passwordLabel: "Contraseña",
            passwordPrompt: "contraseña: ",
            providerInternalError: "error interno del proveedor",
            rememberDeviceLabel: "No volver a pedirlo en este dispositivo durante 30 días",
            resetTotpUsage: "uso: npm run reset-totp -- <usuario>",
            resourceNotRegistered: "el recurso solicitado no está registrado",
            scramInvalidFormat: "el verificador no tiene el formato SCRAM-SHA-256$<iteraciones>:<sal>$<StoredKey>:<ServerKey>",
            scramInvalidIterations: "el verificador SCRAM-SHA-256 tiene una cantidad de iteraciones inválida",
            scramInvalidKeyLength: "el verificador SCRAM-SHA-256 tiene claves de longitud inválida",
            secondFactorTitle: "Segundo factor",
            signInAgain: "Vuelva a ingresar.",
            signInButton: "Ingresar",
            signInTitle: "Ingreso",
            signingKeyInvalid: "la clave de firma $1 de la base de datos no tiene el formato esperado",
            startupFailed: "no se pudo iniciar el gate-one",
            tooManyAttempts: "Demasiados intentos fallidos. Intente nuevamente más tarde.",
            totpAlreadyEnabled: "el usuario $1 ya tiene segundo factor; primero hay que resetearlo",
            totpCodePrompt: "código que muestra la aplicación: ",
            totpEnabled: "segundo factor activado para $1",
            totpKeyInvalid: "AUTH_TOTP_KEY debe tener 32 bytes en base64 (se genera con: openssl rand -base64 32)",
            totpReset: "segundo factor eliminado para $1, junto con sus dispositivos recordados",
            totpScanQr: "Escanee este código QR con la aplicación de autenticación (Microsoft Authenticator, Google Authenticator, ...):",
            totpSecretUnreadable: "el secreto del segundo factor de $1 no se puede descifrar con AUTH_TOTP_KEY",
            unhandledError: "error no controlado en el gate-one",
            unknownLanguage: "idioma desconocido $1",
            unsupportedInteraction: "Interacción no soportada: $1",
            userAlreadyExists: "el usuario $1 ya existe",
            userCreated: "usuario $1 dado de alta",
            usernameLabel: "Usuario",
            userNotFound: "el usuario $1 no existe",
            verifyButton: "Verificar",
        }
    }
}

export var lang: string = 'en';

/**
 * Unlike an unknown key, an unknown language is a configuration error: it throws instead of
 * silently keeping the current language.
 */
export function setLang(newLang: string): void {
    if (!(newLang in i18n.messages)) {
        throw new Error(formatMessage(messages.unknownLanguage, newLang));
    }
    messages = { ...i18n.messages.en, ...i18n.messages[newLang] };
    lang = newLang;
}

/** Replaces $1, $2, ... with the parameters. */
export function formatMessage(message: string, ...params: string[]): string {
    return message.replace(/\$([1-9])/g, function (placeholder: string, position: string): string {
        var param: string | undefined = params[Number(position) - 1];
        return param === undefined ? placeholder : param;
    });
}
