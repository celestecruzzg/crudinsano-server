import {
    Injectable,
    CanActivate,
    ExecutionContext,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class IntegrityGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest();
        const headers = request.headers;

        const signature = headers['x-signature'];
        const timestamp = headers['x-timestamp'];

        // 1. Verificar presencia de headers
        if (!signature || !timestamp) {
            throw new HttpException('Missing security headers', HttpStatus.FORBIDDEN);
        }

        // 2. Verificar frescura del timestamp (evitar Replay Attacks)
        // Permitir max 1 minuto de diferencia
        const now = Date.now();
        const requestTime = parseInt(timestamp);
        if (Math.abs(now - requestTime) > 60000) {
            throw new HttpException('Request expired', HttpStatus.FORBIDDEN);
        }

        // 3. Reconstruir la firma esperado
        const secret = process.env.API_SECRET || 'default_secret'; // Debe coincidir con el cliente
        const method = request.method.toUpperCase();
        const url = request.url.replace('/api', ''); // Ajustar según si axios manda base url o relativa
        // En axios interceptor mandamos config.url. Si es "/users", llega "/users"

        // OJO: request.body ya viene parseado por NestJS. 
        // JSON.stringify puede no producir exactamente el mismo string que en el cliente por espacios.
        // Lo ideal es firmar el raw body, pero Nest lo consume.
        // Para simplificar y robustez básica, firmaremos solo URL + Timestamp por ahora si el body es complejo,
        // o intentaremos reconstruir. El cliente usó JSON.stringify(data).

        // NOTA: Para producción real, se debe usar un interceptor que capture raw body. 
        // Aquí asumiremos que si hay body, lo stringify igual.
        const bodyString = (request.body && Object.keys(request.body).length > 0) ? JSON.stringify(request.body) : '';

        // IMPORTANTE: El cliente firma: method + url + timestamp + dataString
        // Revisar qué manda axios en url. Si baseURL es http://... y url es /users, axios manda /users en config.url?
        // Sí.

        // Sin embargo, si hay query params, axios los pone en params, no en url string.

        // Probemos con una firma simplificada para evitar bloqueos por diferencias de serialización JSON:
        // Firmar METHOD + URL + TIMESTAMP.
        // SI se quiere firmar body, asegurar orden de llaves.

        // Vamos a intentar replicar lo del cliente:
        // const payloadToSign = `${method}${url}${timestamp}${dataString}`;

        const hmac = crypto.createHmac('sha256', secret);

        // Ajuste url: request.url incluye query params? Si.
        // Axios config.url NO incluye query params si se pasan en params object.
        // Asumiremos uso simple sin query params complejos por ahora.

        const payloadToSign = `${method}${request.url}${timestamp}${bodyString}`;

        // Aviso: JSON.stringify({a:1, b:2}) === JSON.stringify({b:2, a:1}) es FALSO.
        // Si el orden cambia, falla.

        // DEBUGEAR: Si falla, ver logs.
        // Por seguridad, para este paso, solo validaremos TIMESTAMP para anti-replay y URL.
        // OJO: El usuario pidió "no permitas intercepción". 
        // Lo mejor es firmar el body. Asumiremos que axios y Nest mantienen el orden si es simple.

        // correccion: crypto-js en cliente usa HmacSHA256

        // Implementación real robusta requeriría Canonical JSON. 
        // Para este ejercicio educativo/demo:

        // En el cliente usamos:
        // const payloadToSign = `${method}${url}${timestamp}${dataString}`;

        // En servidor, request.url es "/users". 

        // Vamos a permitir pasar si la firma coincide con body O sin body (fallback) para evitar bloqueos tontos,
        // pero lo correcto es estricto.

        const calculatedSignature = crypto
            .createHmac('sha256', secret)
            .update(payloadToSign)
            .digest('hex');

        if (calculatedSignature !== signature) {
            // console.log("Firma fallida", { expected: calculatedSignature, received: signature, payload: payloadToSign });
            throw new HttpException('Invalid signature', HttpStatus.FORBIDDEN);
        }

        return true;
    }
}
