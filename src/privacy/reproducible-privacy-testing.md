# Pruebas de privacidad reproducibles

{{#include ../banners/hacktricks-training.md}}

Una configuración de privacidad no está terminada cuando se conecta. Está terminada cuando su límite declarado se ha probado durante el uso normal, los fallos, la recuperación y la desinstalación. Realiza las pruebas contra infraestructura que poseas o que estés autorizado a inspeccionar; los sitios públicos de “leak test” se convierten en otro observador.

## Construir un entorno de pruebas pequeño y autorizado

Usa tres roles, idealmente en proveedores/redes independientes:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Registra antes de cada test:

- ID del test, inicio/fin en UTC, operador y autorización;
- versiones y configuración del endpoint/OS/cliente, y hash de configuración;
- observaciones esperadas de IPv4, IPv6, DNS, TLS, cuenta, pago y aspectos físicos;
- qué logs se inspeccionarán y sus relojes/zonas horarias;
- regla de pass/fail y hora de teardown.

Nunca pruebes primero una identidad sensible. Usa una cuenta sintética y valores canario benignos y únicos propiedad del tester.

## Test de la ruta de red

### 1. Captura la línea base

Antes de habilitar la ruta de privacidad, registra las rutas locales y los resolvers:
```bash
ip route
ip -6 route
resolvectl status
```
En macOS usa `route -n get default`, `netstat -rn -f inet6` y `scutil --dns`. Guarda el resultado únicamente en el almacén de evidencias controlado; puede contener identificadores locales.

### 2. Conecta e inspecciona el routing

Habilita el namespace de VPN/Tor/workload y, a continuación, comprueba la ruta seleccionada para las direcciones públicas controladas:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Reemplaza las direcciones de la documentación por las direcciones del servidor de pruebas. Confirma que la interfaz/tabla seleccionada coincide con el diseño.

### 3. Observa desde ambos extremos

Establece la URL del endpoint controlado y, a continuación, solicita una ruta benigna única:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Usa un dominio real controlado por el tester, TLS autenticado y un token de ruta no sensible. Inspecciona el log del servidor para comprobar:

- dirección de origen/ASN y egress esperado;
- IPv4 frente a IPv6;
- comportamiento de Host/SNI visible en el endpoint;
- user agent y headers de la aplicación;
- hora exacta y reutilización de la solicitud.

No añadas `X-Forwarded-For`, headers de depuración únicos ni cookies que contengan identidad a una solicitud supuestamente separada.

### 4. Testea DNS con un canary bajo tu control

Configura una zona de test autoritativa cuyos query logs controles. Consulta una etiqueta aleatoria única a través del compartimento:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Inspecciona el log autoritativo. Normalmente ve el recursive resolver, no necesariamente el cliente. Compara ese resolver con el diseño previsto de DNS de la VPN/Tor/aplicación. No es necesario usar un sitio público aleatorio para comprobar leaks de DNS.

### 5. Test fail-closed behavior

Mantén un bucle de solicitudes benignas dirigido al endpoint bajo tu control y, a continuación, detén el privacy path. La carga de trabajo debe fallar en lugar de cambiar a una interfaz física. Comprueba ambas familias de direcciones y el DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Repite durante:

- crash del proceso del tunnel;
- cambio de Wi-Fi a Ethernet o de hotspot;
- suspensión/reactivación;
- renovación de DHCP;
- estado del captive portal;
- reconexión del provider/expiración de la key.

Para un Linux namespace/container, detén su tunnel y verifica que no tenga otra ruta predeterminada ni otro resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Los nombres y comandos varían según el despliegue. No los pegues en un host remoto de producción sin recuperación mediante la consola.

### 6. Inspeccionar sockets y paquetes locales

Con autorización, comprueba qué proceso/interfaz se comunica realmente:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Reemplaza `TEST_SERVER_IP` con la dirección explícita que te pertenece; evita capturar ampliamente a usuarios no relacionados. La interfaz física debería ver al peer del túnel/bridge, mientras que el tráfico con destino claro solo debería existir en la capa prevista.

## Tor and onion-service test

1. En Tor Browser, visita la comprobación de conexión de Tor Project y confirma el uso de Tor. No lo trates como una prueba de identidad.<sup>[[1]](#references)</sup>
2. Visita el endpoint HTTPS que te pertenece con un canary único y confirma que ve una salida de Tor, ninguna cookie identificativa y el contexto estándar del navegador.
3. Selecciona **New Identity**, vuelve a visitar el endpoint con un canary diferente y verifica que el estado local se haya borrado según lo esperado. El cambio de IP de salida no está garantizado ni es el objetivo de New Identity.
4. Para un onion service, accede a él únicamente mediante Tor Browser. Confirma que el host del servicio no tiene ningún listener público mediante un escaneo externo autorizado y que las respuestas de la aplicación no contienen ningún hostname/IP público.
5. Inspecciona el DNS/HTTP saliente del origen, las plantillas, las páginas de error, el correo electrónico/webhooks y los recursos de terceros. Cualquier fetch directo puede revelar el origen o la cuenta del operador.
6. Si la autorización de cliente está habilitada, confirma que un Tor Browser limpio y sin credenciales no puede conectarse y que uno con credenciales sí puede.
7. Rota una clave de autorización de prueba y confirma que el cliente revocado pierde el acceso sin cambiar la identidad onion.

## Browser-compartment test

Crea una página controlada que registre únicamente los campos necesarios para la prueba, con un periodo de retención breve. Compara los compartimentos personal y de privacidad para:

- cookies/local storage/service workers y cache;
- estado de browser sync/login;
- idioma, zona horaria, dimensiones de pantalla/ventana y fuentes;
- candidatos de WebRTC/red;
- permisos y modificaciones visibles para las extensiones;
- datos de user-agent TLS/HTTP en el servidor.

No intentes hacer que Tor Browser sea «más aleatorio». La condición de aprobación es la similitud con su conjunto de anonimato estándar y la ausencia de estado personal, no la máxima diferencia respecto al navegador personal.

Prueba copiar/pegar, arrastrar/soltar, abrir archivos descargados, las sugerencias del gestor de contraseñas y los botones del proveedor de identidad. Estos son puentes frecuentes entre compartimentos.

## Operating-system isolation test

### Tails

1. Comienza con un archivo/canary benigno en una sesión sin Persistent Storage.
2. Apaga completamente el sistema, reinicia y confirma que ha desaparecido.
3. Habilita una sola categoría de persistencia necesaria, repite la prueba y confirma que no se conserva ningún estado no relacionado del navegador/aplicación.
4. Verifica que Unsafe Browser no pueda utilizarse después del inicio de sesión en el portal para actividades sensibles y que las aplicaciones de Tor se reconecten normalmente.

### Whonix/Qubes

1. Detén el qube Gateway/net y demuestra que el qube Workstation/app no puede acceder a IPv4, IPv6 ni DNS.
2. Intenta únicamente la ruta de portapapeles/archivo entre qubes configurada explícitamente y confirma que no existen otras rutas de carpetas/dispositivos compartidos.
3. Abre un documento de prueba benigno en un qube desechable, ciérralo y confirma que su estado desaparece.
4. Comprueba que el qube vault no tenga NetVM y que no pueda adquirir uno mediante un cambio de plantilla/valor predeterminado.
5. Crea/restaura un snapshot de una VM de prueba e inspecciona si el estado asociado a la identidad reaparece inesperadamente.

## Communications metadata test

Para cada messenger seleccionado:

1. Crea participantes exclusivos para las pruebas en dispositivos controlados.
2. Registra qué requiere el registro: teléfono, cuenta de app store, IP, servicio push, nombre de usuario o invitación.
3. Envía un mensaje benigno mientras inspeccionas las vistas previas de notificaciones, los escritorios vinculados, los dispositivos wearables y las copias de seguridad.
4. Verifica los códigos de safety/security mediante una ruta independiente.
5. Deshabilita los recibos/push o habilita Tor/transportes locales de uno en uno y observa los cambios en la fiabilidad/metadata.
6. Exporta o restaura una copia de seguridad de prueba y documenta exactamente qué perfil, contactos e historial contiene.
7. Pierde/revoca un dispositivo de prueba y confirma que los participantes restantes ven el cambio esperado de clave/dispositivo.

No realices pruebas contactando con personas no involucradas ni generando tráfico abusivo.

## File-sanitization test

1. Calcula el hash y conserva el original en un almacenamiento de evidencias cifrado:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Crea una copia limpia usando el proceso específico del formato descrito en [Comunicaciones y uso compartido que preservan la privacidad](privacy-preserving-communications-and-sharing.md).
3. Compara los inventarios de metadatos:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Renderiza/abre la copia en un contexto desechable. Comprueba el contenido oculto, los archivos adjuntos, los enlaces, los formularios, las capas, las miniaturas y los identificadores visuales.
5. Busca únicamente en la copia preparada cadenas conocidas de canary de autor/correo electrónico/ruta.
6. Calcula el hash del resultado final y haz que una segunda persona verifique el archivo exacto que se va a publicar.

La ausencia en el resultado de ExifTool no demuestra el anonimato; los elementos internos del formato, los píxeles, la prosa y los registros de distribución permanecen.

## Prueba de privacidad de pagos

Usa el importe mínimo permitido o una red de prueba/sandbox oficial:

1. Escribe la vista esperada para el pagador, el beneficiario/comerciante, el emisor/exchange, la red/nodo, el ledger público y el contable/responsable del control.
2. Crea una factura o contexto de comerciante de prueba único, sin una identidad falsa.
3. Paga una vez y recopila tu propio recibo, extracto, panel del comerciante, registro de wallet/nodo y vista de la cadena pública cuando corresponda.
4. Comprueba si el importe, la marca de tiempo, la dirección/token, la cuenta, la IP/dispositivo, la entrega y la ruta de reembolso coinciden con la tabla de observadores.
5. Para Bitcoin, inspecciona la reutilización de direcciones, los inputs seleccionados, el cambio y la consolidación posterior en la vista de coin-control de la wallet.
6. Para protocolos shielded, verifica el pool/ruta real y lo que revela una viewing key; no infieras privacidad a partir del branding de la wallet.
7. Para e-cash/Taler, prueba la copia de seguridad/recuperación, el reembolso y el canje con un valor pequeño; documenta los registros de los límites del mint/exchange/federación.
8. Revoca una tarjeta virtual/credencial de prueba y confirma que la autorización posterior falla, manteniendo clara la gestión legítima del reembolso.
9. Haz la conciliación y conserva cifrada la evidencia fiscal/de autorización requerida.

Nunca crees transferencias circulares, división por umbrales, compras falsas ni reembolsos sospechosos como “prueba de privacidad”.

## Ejercicio autorizado de accountability de red-team

Antes del ejercicio, realiza un tabletop y un ejercicio técnico:

1. Un operador lanza un canary benigno desde cada ruta de origen aprobada.
2. El SOC objetivo registra lo que detecta sin recibir la identidad del operador si se pretende realizar una prueba ciega.
3. El controlador del ejercicio resuelve origen → engagement → operador a partir del mapa bajo escrow y del registro de trabajo firmado.
4. El controlador envía la orden de parada de emergencia; el operador y el responsable de la infraestructura demuestran el apagado dentro del tiempo establecido en las ROE.
5. El equipo de abuso del proveedor recibe el contacto 24/7 correcto y la referencia de autorización.
6. La evidencia muestra el objetivo, la hora, la herramienta/trabajo y el operador sin conservar contenido de payload innecesario.
7. Un segundo operador verifica la revocación de credenciales y la eliminación de recursos.

Suspende la revisión de preparación si el SOC puede ver trivialmente la infraestructura personal/doméstica **o** si el controlador no puede atribuir y detener rápidamente el origen.

## Plantilla de registro de prueba
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Comprobación de conexión](https://check.torproject.org/)
- [2] [WireGuard — Enrutamiento y Namespaces de red](https://www.wireguard.com/netns/)
- [3] [ExifTool — Preguntas frecuentes y guía de metadatos](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Guía técnica para las pruebas y evaluación de la seguridad de la información](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
