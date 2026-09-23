import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import type Provider from 'oidc-provider';
import type { Interaction, InteractionResults } from 'oidc-provider';
import type { Configuracion } from './configuracion.ts';
import { verificarCredenciales } from './usuarios.ts';

type Manejador = (pedido: Request<{ uid: string }, string, unknown>, respuesta: Response) => Promise<void>;

function conCaptura(manejador: Manejador) {
    return function (pedido: Request<{ uid: string }, string, unknown>, respuesta: Response, siguiente: NextFunction): void {
        manejador(pedido, respuesta).catch(function (error: unknown): void {
            siguiente(error);
        });
    };
}

function escaparHtml(texto: string): string {
    return texto
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function campoDeTexto(cuerpo: unknown, nombre: string): string | undefined {
    if (typeof cuerpo !== 'object' || cuerpo === null) {
        return undefined;
    }
    var valor: unknown = Reflect.get(cuerpo, nombre);
    return typeof valor === 'string' ? valor : undefined;
}

function paginaDeLogin(uid: string, usuario: string, mensaje: string | undefined): string {
    var error: string = mensaje == null ? '' : '<p class="error">' + escaparHtml(mensaje) + '</p>';
    return '<!DOCTYPE html>'
        + '<html lang="es"><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width, initial-scale=1">'
        + '<title>Ingreso</title>'
        + '<style>body{font-family:sans-serif;max-width:22rem;margin:4rem auto}'
        + 'label{display:block;margin:0.75rem 0 0.25rem}input{width:100%;padding:0.4rem}'
        + 'button{margin-top:1rem;padding:0.5rem 1rem}.error{color:#b00}</style>'
        + '</head><body><h1>Ingreso</h1>' + error
        + '<form method="post" action="/interaccion/' + escaparHtml(uid) + '/login">'
        + '<label for="usuario">Usuario</label>'
        + '<input id="usuario" name="usuario" autocomplete="username" value="' + escaparHtml(usuario) + '" required>'
        + '<label for="contrasena">Contraseña</label>'
        + '<input id="contrasena" name="contrasena" type="password" autocomplete="current-password" required>'
        + '<button type="submit">Ingresar</button>'
        + '</form></body></html>';
}

function responderHtml(respuesta: Response, codigo: number, html: string): void {
    respuesta.status(codigo);
    respuesta.set('Content-Type', 'text/html; charset=utf-8');
    respuesta.set('Cache-Control', 'no-store');
    respuesta.send(html);
}

export function crearRutasDeInteraccion(proveedor: Provider, configuracion: Configuracion): Router {
    var rutas: Router = express.Router();
    var cuerpoDeFormulario = express.urlencoded({ extended: false });

    rutas.get('/interaccion/:uid', conCaptura(async function (pedido, respuesta): Promise<void> {
        var interaccion: Interaction = await proveedor.interactionDetails(pedido, respuesta);
        if (interaccion.prompt.name !== 'login') {
            responderHtml(respuesta, 400, '<p>Interacción no soportada: ' + escaparHtml(interaccion.prompt.name) + '</p>');
            return;
        }
        responderHtml(respuesta, 200, paginaDeLogin(interaccion.uid, '', undefined));
    }));

    rutas.post('/interaccion/:uid/login', cuerpoDeFormulario, conCaptura(async function (pedido, respuesta): Promise<void> {
        var interaccion: Interaction = await proveedor.interactionDetails(pedido, respuesta);
        var usuario: string | undefined = campoDeTexto(pedido.body, 'usuario');
        var contrasena: string | undefined = campoDeTexto(pedido.body, 'contrasena');
        if (usuario == null || contrasena == null) {
            responderHtml(respuesta, 400, paginaDeLogin(interaccion.uid, '', 'Faltan datos.'));
            return;
        }
        var valido: boolean = await verificarCredenciales(configuracion.archivoDeUsuarios, usuario, contrasena, configuracion.parametrosScram);
        if (!valido) {
            responderHtml(respuesta, 401, paginaDeLogin(interaccion.uid, usuario, 'Usuario o contraseña incorrectos.'));
            return;
        }
        var resultado: InteractionResults = { login: { accountId: usuario } };
        await proveedor.interactionFinished(pedido, respuesta, resultado, { mergeWithLastSubmission: false });
    }));

    return rutas;
}
