export type FuncionFetch = (entrada: string | URL | Request, opciones?: RequestInit) => Promise<Response>;

function urlDeLaEntrada(entrada: string | URL | Request): string {
    if (entrada instanceof Request) return entrada.url;
    if (entrada instanceof URL) return entrada.href;
    return new URL(entrada).href;
}

/**
 * oidc-provider hace sus llamadas salientes con un agente que rechaza direcciones privadas,
 * de loopback y no enrutables públicamente (protección contra SSRF). Esa protección impide
 * avisar por back-channel a servicios de una red interna.
 *
 * Esta función omite la protección únicamente para las URL exactas de la lista, que provienen
 * de la configuración de los clientes registrados. Cualquier otro destino conserva la protección.
 * Las demás opciones que fija oidc-provider (tiempo máximo, encabezados) se mantienen.
 */
export function crearFetchConDestinosInternos(destinosPermitidos: readonly string[]): FuncionFetch {
    var permitidos: Set<string> = new Set<string>(destinosPermitidos.map(function (destino: string): string {
        return new URL(destino).href;
    }));
    return function (entrada: string | URL | Request, opciones?: RequestInit): Promise<Response> {
        if (!permitidos.has(urlDeLaEntrada(entrada))) {
            return fetch(entrada, opciones);
        }
        var opcionesSinProteccion: RequestInit = { ...opciones, dispatcher: undefined };
        return fetch(entrada, opcionesSinProteccion);
    };
}
