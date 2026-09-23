export var messages = {
    backchannelLogoutFailed: "back-channel logout to $1 failed (user $2, sid $3)",
    backchannelLogoutSent: "back-channel logout sent to $1 (user $2, sid $3)",
    cancelButton: "Cancel",
    cookieKeysEmpty: "AUTH_COOKIE_KEYS has no keys",
    createUserUsage: "usage: npm run create-user -- <username>  (the password is read next)",
    databasePoolError: "error in an idle database connection",
    envVarMustBePositiveInteger: "the environment variable $1 must be a positive integer",
    expiredCleanupFailed: "could not delete the expired OIDC records",
    generatedKeyLacksComponents: "the generated key lacks the components expected for $1",
    internalError: "internal error",
    invalidCredentials: "Wrong username or password.",
    listeningOn: "gate-one listening on $1",
    logoutButton: "Sign out",
    logoutExplanation: "The session will be closed in every service that uses it.",
    logoutQuestion: "Sign out?",
    logoutTitle: "Sign out",
    missingEnvVar: "missing environment variable $1",
    missingFields: "Missing data.",
    nonAsciiCredentials: "the username and the password may only contain printable ASCII characters",
    oidcConfigurationAt: "OIDC configuration at $1",
    oidcPayloadInvalid: "an OIDC record in the database is not a JSON object",
    passwordEmpty: "the password must not be empty",
    passwordLabel: "Password",
    passwordPrompt: "password: ",
    providerInternalError: "provider internal error",
    resourceNotRegistered: "the requested resource is not registered",
    scramInvalidFormat: "the verifier does not have the format SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>",
    scramInvalidIterations: "the SCRAM-SHA-256 verifier has an invalid iteration count",
    scramInvalidKeyLength: "the SCRAM-SHA-256 verifier has keys of invalid length",
    signInButton: "Sign in",
    signInTitle: "Sign in",
    signingKeyInvalid: "the signing key $1 in the database does not have the expected format",
    startupFailed: "gate-one could not start",
    unhandledError: "unhandled error in gate-one",
    unknownLanguage: "unknown language $1",
    unsupportedInteraction: "Unsupported interaction: $1",
    userAlreadyExists: "the user $1 already exists",
    userCreated: "user $1 created",
    usernameLabel: "Username",
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
            cookieKeysEmpty: "AUTH_COOKIE_KEYS no contiene ninguna clave",
            createUserUsage: "uso: npm run create-user -- <usuario>  (la contraseña se ingresa a continuación)",
            databasePoolError: "error en una conexión inactiva a la base de datos",
            envVarMustBePositiveInteger: "la variable de entorno $1 debe ser un entero positivo",
            expiredCleanupFailed: "no se pudieron borrar los registros OIDC vencidos",
            generatedKeyLacksComponents: "la clave generada no tiene los componentes esperados para $1",
            internalError: "error interno",
            invalidCredentials: "Usuario o contraseña incorrectos.",
            listeningOn: "gate-one escuchando en $1",
            logoutButton: "Cerrar sesión",
            logoutExplanation: "Se cerrará en todos los servicios que la usan.",
            logoutQuestion: "¿Cerrar la sesión?",
            logoutTitle: "Cerrar sesión",
            missingEnvVar: "falta la variable de entorno $1",
            missingFields: "Faltan datos.",
            nonAsciiCredentials: "el usuario y la contraseña solo pueden tener caracteres ASCII imprimibles",
            oidcConfigurationAt: "configuración OIDC en $1",
            oidcPayloadInvalid: "un registro OIDC de la base de datos no es un objeto JSON",
            passwordEmpty: "la contraseña no puede estar vacía",
            passwordLabel: "Contraseña",
            passwordPrompt: "contraseña: ",
            providerInternalError: "error interno del proveedor",
            resourceNotRegistered: "el recurso solicitado no está registrado",
            scramInvalidFormat: "el verificador no tiene el formato SCRAM-SHA-256$<iteraciones>:<sal>$<StoredKey>:<ServerKey>",
            scramInvalidIterations: "el verificador SCRAM-SHA-256 tiene una cantidad de iteraciones inválida",
            scramInvalidKeyLength: "el verificador SCRAM-SHA-256 tiene claves de longitud inválida",
            signInButton: "Ingresar",
            signInTitle: "Ingreso",
            signingKeyInvalid: "la clave de firma $1 de la base de datos no tiene el formato esperado",
            startupFailed: "no se pudo iniciar el gate-one",
            unhandledError: "error no controlado en el gate-one",
            unknownLanguage: "idioma desconocido $1",
            unsupportedInteraction: "Interacción no soportada: $1",
            userAlreadyExists: "el usuario $1 ya existe",
            userCreated: "usuario $1 dado de alta",
            usernameLabel: "Usuario",
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
