import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { Client, JWKS } from 'oidc-provider';
import { obtenerJuegoDeClaves } from './claves.ts';
import { leerConfiguracion, type Configuracion } from './configuracion.ts';
import { crearRutasDeInteraccion } from './interacciones.ts';
import { crearProveedor } from './proveedor.ts';

async function principal(): Promise<void> {
    var configuracion: Configuracion = leerConfiguracion();
    var juegoDeClaves: JWKS = await obtenerJuegoDeClaves(configuracion.archivoDeClaves);
    var proveedor: Provider = crearProveedor(configuracion, juegoDeClaves);

    proveedor.on('server_error', function (_contexto: unknown, error: Error): void {
        console.error('error interno del proveedor', error);
    });
    proveedor.on('backchannel.success', function (_contexto: unknown, cliente: Client, cuenta: string, sesion: string): void {
        console.log('back-channel logout enviado a ' + cliente.clientId + ' (usuario ' + cuenta + ', sid ' + sesion + ')');
    });
    proveedor.on('backchannel.error', function (_contexto: unknown, error: Error, cliente: Client, cuenta: string, sesion: string): void {
        console.error('falló el back-channel logout a ' + cliente.clientId + ' (usuario ' + cuenta + ', sid ' + sesion + ')', error);
    });

    var aplicacion: Express = express();
    aplicacion.use(crearRutasDeInteraccion(proveedor, configuracion));
    aplicacion.use(proveedor.callback());
    aplicacion.use(function (error: unknown, _pedido: Request, respuesta: Response, _siguiente: NextFunction): void {
        console.error('error no controlado en el gate-one', error);
        respuesta.status(500);
        respuesta.set('Content-Type', 'text/plain; charset=utf-8');
        respuesta.send('error interno');
    });

    aplicacion.listen(configuracion.puerto, function (): void {
        console.log('gate-one escuchando en ' + configuracion.emisor);
        console.log('configuración OIDC en ' + configuracion.emisor + '/.well-known/openid-configuration');
    });
}

principal().catch(function (error: unknown): void {
    console.error('no se pudo iniciar el gate-one', error);
    process.exit(1);
});
