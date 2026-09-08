# Arquitecturas avanzadas de privacidad de red

{{#include ../banners/hacktricks-training.md}}

La complejidad solo es útil cuando elimina un observador o un modo de fallo específico. Una pila de túneles única, una forma de paquetes personalizada, un user agent poco frecuente o una infraestructura que rota con frecuencia pueden convertirse en una huella más fuerte que una configuración estándar utilizada por miles de personas.

El [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) proporciona el esquema común `Pros`/`Cons`/`Procedure`/`Detection`. Esta página amplía las arquitecturas más complejas y los límites de confianza.

Por tanto, el objetivo avanzado es la **separación del conocimiento**: ningún componente ordinario debería poseer simultáneamente la identidad del usuario, el destino, el texto plano y el historial de actividad a largo plazo. Esto no es invisibilidad, y la colusión, un proceso legal, el compromiso del endpoint o la correlación de tráfico de extremo a extremo aún pueden reconstruir la ruta.

## Selección de arquitectura

| Patrón | Propiedad obtenida | Nueva confianza/fallo | Uso adecuado |
|---|---|---|---|
| Standard Tor Browser | Huella compartida del navegador y ruta con múltiples relays | La baja latencia permite la correlación del tráfico | Navegación web anónima general |
| Tor bridge + pluggable transport | Dificulta el bloqueo/clasificación directa de Tor | El bridge/transport aún puede detectarse; el bridge conoce el origen | Redes censuradas |
| Onion service | Oculta la IP del servicio; evita el exit; autentica la identidad onion | La clave onion y el endpoint del servidor se convierten en activos críticos | Publicación privada, recepción o administración |
| Independent ingress + egress relays | Normalmente ningún relay individual ve el origen y el destino | Los operadores pueden coludirse; el timing atraviesa ambos | Aplicaciones compatibles de alto rendimiento |
| Oblivious HTTP | Separa la IP de origen de la solicitud HTTP stateless cifrada | Requiere compatibilidad de la aplicación, el relay y el gateway | Telemetría, consultas y envíos sin estado de sesión |
| VPN-only workload namespace | Ausencia de una ruta a la red clara aplicada por el kernel | La VPN aún ve ambos extremos; el host/root sigue siendo de confianza | Herramientas de engagement autorizado y egress fijo |
| Disposable remote browser | El destino queda aislado del navegador/endpoint local | El proveedor del Workspace ve la actividad y la identidad de inicio de sesión | Sitios/archivos no confiables e investigación controlada |
| I2P internal service | Túneles overlay entrantes/salientes separados; sin exits oficiales | Ecosistema más pequeño/diferente; comportamiento de peers de larga duración | Servicios nativos de I2P, no como sustituto de la web ordinaria |
| Mixnet/asynchronous delivery | El retraso, el batching y el cover traffic resisten el análisis temporal | Alta latencia, aplicaciones limitadas y menor madurez | Mensajes/tareas que no necesitan interacción |

## Split-knowledge relays

Un patrón de relay con dos operadores puede superar a una VPN individual para una aplicación específica:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay es un ejemplo implementado: Apple opera la entrada, mientras que un proveedor de contenido diferente opera la salida, por lo que normalmente ninguno ve tanto la IP del cliente como el destino de navegación.<sup>[[1]](#references)</sup> Es un servicio de privacidad específico de Safari/DNS, no una red de anonimato para todos los dispositivos, y conserva deliberadamente una región aproximada.

Oblivious HTTP (OHTTP) estandariza un patrón de aplicación más limitado. El relay ve al cliente y el tráfico cifrado hacia el gateway; el gateway descifra el mensaje HTTP, pero ve el relay, no al cliente. RFC 9458 advierte que requiere soporte voluntario del relay/gateway, que es más adecuado para solicitudes sin cookies/autenticación/estado de sesión y que excluye el análisis de tráfico de sus garantías.<sup>[[2]](#references)</sup>

### Lista de comprobación de diseño

1. Define los mensajes exactos de la aplicación que deben protegerse; no hagas proxy silenciosamente de sesiones web autenticadas arbitrarias.
2. Usa organizaciones de entrada y salida operadas de forma independiente, con administración, credenciales, logging y control legal separados cuando sea posible.
3. Cifra la solicitud de la aplicación para el gateway, de modo que la entrada no pueda leerla.
4. Elimina los encabezados de reenvío derivados del cliente, los identificadores TLS y los tokens estables por usuario en la capa adecuada.
5. Evita claves únicas, cookies o campos de payload que permitan al gateway volver a vincular solicitudes pese a la separación del transporte.
6. Agrega, minimiza y establece la expiración de los logs en ambos lados; documenta el riesgo de colusión y divulgación obligatoria.
7. Aplica padding o batching únicamente según un protocolo revisado. Un modelado de tráfico casero puede crear una firma única sin impedir la correlación.
8. Realiza pruebas con solicitudes canary controladas y compara lo que registran el cliente, la entrada, el gateway y el objetivo.

Para la navegación interactiva normal, usa Tor Browser en lugar de inventar un proxy OHTTP privado. OHTTP protege una transacción de aplicación compatible, no una identidad completa del navegador.

## Aplica la ruta por workload

Un kill switch basado únicamente en rutas de host mutables puede fallar durante la renovación de DHCP, la suspensión/reactivación, cambios de IPv6 o un fallo del túnel. Un patrón de Linux más sólido proporciona a un contenedor o network namespace únicamente una interfaz de loopback y una interfaz de túnel. WireGuard documenta que una interfaz puede crearse en un namespace físico, trasladarse a un namespace de workload y conservar su socket UDP cifrado en el namespace original.<sup>[[3]](#references)</sup>

### Patrón de despliegue

1. Construye esto primero en un host desechable/consola local; los errores con los namespaces pueden eliminar el acceso remoto.
2. Coloca la interfaz física Ethernet/Wi-Fi y DHCP/supplicant en un namespace **physical**.
3. Crea allí la interfaz de WireGuard para que su socket de transporte cifrado tenga acceso a la red física.
4. Traslada únicamente la interfaz de WireGuard al namespace **workload** y conviértela en la única ruta predeterminada.
5. Proporciona al workload un resolver específico del namespace que solo sea accesible a través del túnel. Gestiona IPv6 explícitamente.
6. Ejecuta el contenedor del navegador/herramienta en ese namespace sin host networking, capacidades privilegiadas, directorio de navegador compartido ni agente de credenciales personales.
7. Detén el túnel y verifica que el workload no pueda resolver ni conectarse a un endpoint IPv4 o IPv6 controlado.
8. Prueba el roaming del endpoint, la renovación de DHCP, la suspensión/reactivación y la gestión de captive portals fuera del namespace del workload.
9. Registra el hash de configuración del namespace/túnel y la dirección de salida aprobada para la trazabilidad del engagement.

Esto proporciona **aplicación de rutas**, no anonimato frente a la VPN ni al bastion del engagement. Un host/root comprometido puede inspeccionar o cambiar los namespaces.

## Tor bridges y pluggable transports

Los bridges son relays de entrada de Tor no públicos. Los pluggable transports modifican el tráfico del primer salto para dificultar el bloqueo simple o la clasificación del protocolo. No añaden capas de relay anónimas después de la entrada ni derrotan a un observador capaz de realizar una correlación temporal más amplia.

| Transport | Enfoque del primer salto | Compromiso práctico |
|---|---|---|
| **obfs4** | Hace que el tráfico parezca aleatorio y resiste el sondeo activo | Una dirección de bridge conocida aún puede bloquearse |
| **Snowflake** | Usa proxies WebRTC voluntarios de corta duración para alcanzar un bridge | El rendimiento varía; existen patrones de broker/STUN/WebRTC |
| **WebTunnel** | Transporta el tráfico del bridge en un túnel WebSocket similar a HTTPS | Depende de un front web accesible y aún puede clasificarse |

The Tor Project describe Snowflake y WebTunnel como transports para eludir la censura, no como mecanismos de indistinguibilidad perfecta.<sup>[[4]](#references)</sup>

### Flujo de trabajo seguro

1. Empieza con la conexión directa de Tor Browser. Añade un bridge solo cuando el bloqueo o la visibilidad en el modelo de observador local lo justifiquen.
2. Usa transports integrados o líneas de bridge obtenidas a través de canales de The Tor Project. No descargues binarios de transport aleatorios ni listas públicas de bridges desde foros.
3. Prueba la opción compatible menos compleja que conecte de forma fiable; registra por qué se eligió.
4. Mantén Tor Browser estándar en los demás aspectos. Un bridge no hace seguras las extensiones personalizadas, los inicios de sesión en cuentas ni las configuraciones inusuales del navegador.
5. Prueba la reconexión y la corrección del reloj. No cambies repetidamente de transport de una forma que envíe una secuencia distintiva al mismo observador local.
6. Reevalúa la situación si cambia el censor o la política de red; el uso puede ser sensible o estar restringido en algunas ubicaciones.

## Onion services como punto de encuentro privado

Un onion service crea circuitos Tor salientes hacia puntos de introducción y relays de rendezvous, por lo que no necesita un puerto público entrante y no expone la IP de su servidor mediante el protocolo onion. El tráfico entre cliente y servicio permanece dentro de Tor y la dirección onion autentica la clave del servicio.<sup>[[5]](#references)</sup>

Para un portal de recepción legítimo, repositorio privado, interfaz administrativa o buzón de evidencias de un engagement:

1. Ejecuta la aplicación en un host/VM dedicado y enlázala a loopback o a un Unix socket aislado.
2. Instala Tor desde su repositorio oficial y sigue la configuración oficial de onion service v3; no uses nunca instrucciones obsoletas de v2.
3. Protege la clave privada del onion service como una clave TLS/de firma. Haz una copia de seguridad únicamente si necesitas una identidad estable.
4. Añade autorización de cliente del onion service para un grupo cerrado y entrega las credenciales mediante un canal autenticado de forma independiente.<sup>[[6]](#references)</sup>
5. Evita que el origen obtenga fuentes de terceros, analytics, actualizaciones o webhooks que revelen su IP pública o la cuenta del operador.
6. Implementa también autenticación y autorización en la aplicación; poseer la dirección onion no constituye control de acceso.
7. Aplica parches, limita la tasa y monitoriza el servicio sin integrar telemetría de terceros.
8. Desde un contexto de prueba separado, confirma que DNS, email, páginas de error, metadatos de archivos y encabezados de respuesta no divulguen el origen.
9. Para uso de red team, incluye el servicio, propietario, propósito y hora de apagado en el ROE. No lo uses para ocultar C2 fuera de alcance.

## Navegador remoto y workspace desechable

Un navegador remoto traslada el renderizado y el contenido de riesgo lejos del endpoint local y puede presentar una salida cloud específica del engagement. Protege el dispositivo local frente a cierto contenido y persistencia; no hace anónimo al operador frente al proveedor del workspace. AWS, por ejemplo, documenta la recopilación de datos del portal, identidad, políticas, preferencias y logs de sesión aunque la instancia de navegador desechable se descarte al finalizar la sesión.<sup>[[7]](#references)</sup>

Usa un workspace controlado por la organización para cada engagement, restringe las descargas/subidas/portapapeles, desactiva los proveedores de identidad personales, envía su salida fija a través del bastion aprobado y elimina el workspace después de exportar las evidencias. Trata la consola del proveedor, el IdP y al administrador como observadores.

## I2P y overlays internos

I2P crea túneles unidireccionales separados de entrada y salida y no tiene exits oficiales a nivel de red; está destinado principalmente a servicios dentro de I2P.<sup>[[8]](#references)</sup> No es una forma más rápida de usar el Internet público. Los outproxies introducen un punto de confianza, y el modelo de amenazas oficial solicita más investigación y no afirma un anonimato perfecto.

Usa I2P únicamente cuando ambos extremos lo admitan intencionadamente, aísla su router de larga duración de las aplicaciones personales y entiende que los peers/redes locales pueden observar la participación en I2P. No aumentes el número de saltos ni ajustes la selección de peers sin evidencias: las configuraciones inusuales pueden reducir el rendimiento y el anonymity set.

## Operaciones resistentes a la correlación

- Prefiere una configuración de cliente común y compatible frente a un build único.
- Separa las identidades en el endpoint; ninguna topología de routing corrige la reutilización de cuentas, pagos, recuperación o contenido.
- Para tareas no interactivas, prefiere un protocolo asíncrono/mixnet revisado en lugar de añadir manualmente esperas o tráfico falso.
- Evita operar identidades supuestamente separadas siguiendo un patrón sincronizado desde el mismo contexto físico.
- Usa una puerta de exportación unidireccional: el contenido no confiable entra en un renderer desechable; solo sale un resultado revisado y sanitizado.
- Mantén los relojes correctos para la seguridad del protocolo, pero elimina las marcas temporales precisas innecesarias de los artefactos publicados.
- Minimiza la duración de las sesiones y la infraestructura obsoleta sin una rotación rápida de tipo “fast-flux”, que resulta llamativa y perjudica la trazabilidad.

## Técnicas que no pueden utilizar terceros no implicados

Estas son técnicas reales de adversarios, no técnicas imaginarias o irrelevantes. Sus mecanismos y detección se describen en [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) y los [APT case studies](government-and-apt-case-studies.md). Durante un ejercicio autorizado, reproduce su comportamiento observable usando sustitutos propios:

- modela la rotación de exits residenciales/móviles con pools de relays controlados, nunca con mercados cuyo consentimiento no esté claro;
- modela open proxies, routers comprometidos y botnets con VMs/routers propios;
- modela cuentas cloud robadas con un tenant de ejercicio designado y una identidad de víctima sintética;
- modela domain fronting en un reverse proxy propio en lugar de un CDN no dispuesto a colaborar;
- modela Wi-Fi de terceros con dos AP aislados propiedad del laboratorio;
- trata el cifrado personalizado, las cadenas de múltiples VPN y la rotación de identificadores como hipótesis de prueba cuyos artefactos de flujo, cuenta y endpoint sigan siendo detectables.

Para un red team autorizado, cualquier intento de hacer que el tráfico sea menos reconocible debe ser un objetivo explícito de detección en el ROE, contar con un mapa de atribución bajo control del controller e incluir un mecanismo de parada/desconflicción.

## Matriz de verificación

| Prueba | Resultado esperado | Significado del fallo |
|---|---|---|
| Túnel/bridge detenido | El workload no tiene ninguna ruta directa IPv4/IPv6/DNS | La aplicación de rutas está incompleta |
| Log del objetivo inspeccionado | Solo aparece la identidad de salida/aplicación planificada | leak de encabezado, ruta o cuenta |
| Log de entrada inspeccionado | El origen está presente; el objetivo/la solicitud en claro están ausentes | La separación de confianza falló en la entrada |
| Log de salida inspeccionado | El relay/la solicitud están presentes; la identidad del origen está ausente | La separación de confianza falló en la salida |
| Origen onion escaneado externamente | No se puede alcanzar/vincular ningún servicio de origen público | El origen hizo leak o tiene conectividad dual |
| Sesión desechable finalizada | El estado de la instancia desapareció; las evidencias aprobadas se conservaron por separado | Falló el límite de persistencia |
| Consulta del controller ejercida | La actividad se asigna rápidamente al engagement/operador | Falló la trazabilidad del red team |

## References

- [1] [Seguridad de las plataformas de Apple — Seguridad de iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [The Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [The Tor Project — Cómo funcionan los Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [The Tor Project — Configuración avanzada de Onion Service y autorización de clientes](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Cifrado de datos en Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Modelo de amenazas](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
