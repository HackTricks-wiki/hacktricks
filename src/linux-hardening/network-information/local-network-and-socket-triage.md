# Triaje de red local y sockets

{{#include ../../banners/hacktricks-training.md}}

Tras obtener una shell en un host Linux, los objetivos de red más útiles a menudo no están expuestos externamente. Los servicios limitados a loopback, las redes veth, los sockets Unix, los listeners temporales, las capturas de paquetes y las reglas del firewall local pueden exponer credenciales o superficies de ataque solo locales.

Esta página se centra en técnicas prácticas de post-exploitation local, no en pentesting de redes remotas en general.

## Enumeración de loopback y servicios locales

Empieza por identificar los servicios en escucha, sus direcciones de bind y el proceso propietario, cuando los permisos lo permitan.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Patrones importantes:

- `127.0.0.1:<port>` o `[::1]:<port>`: por defecto, solo se puede acceder desde el host.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: se puede acceder desde todas las interfaces IPv4, salvo que haya filtros.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` o `192.168.0.0/16` en `veth*`, `docker*`, `br-*`, `cni*`: probablemente son redes de contenedores o laboratorios locales.<sup>[[23]](#references)[[24]](#references)</sup>
- Sockets Unix en `/run`, `/var/run`, `/tmp` o directorios de aplicaciones: superficies IPC locales.<sup>[[5]](#references)</sup>

Para el histórico [problema de análisis de sockets de snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), inspecciona el daemon en ejecución, su socket de API local y la revisión del paquete o snap instalado para comprobar si incluye la corrección correspondiente a esa distribución. El error estaba en la validación que hacía snapd de la dirección del socket de un peer, no en `snap-confine`; la presencia de un archivo `snap-confine` con set-user-ID o de una cadena de versión upstream, por sí sola, no permite determinar si el sistema está afectado. Ubuntu publicó correcciones con versiones de paquete específicas para cada versión, y snapd puede haberse actualizado desde un snap independientemente del paquete de la distribución. Confirma la compilación que realmente está en ejecución y la accesibilidad del socket local antes de evaluar el límite de la API privilegiada. La enumeración pasiva no debe enviar una solicitud de socket manipulada ni instalar un snap.

Un listener loopback iniciado mediante [`socat` con `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) puede pasar la entrada de un cliente local a un programa aparte. Correlaciona el comando del listener, la ruta del ejecutable, la identidad efectiva del proceso hijo, la accesibilidad local y la autenticación antes de considerar un servicio personalizado propiedad de root como una posible vía de escalada de privilegios. Un fallo de seguridad de memoria o una ruta insegura de entrada a comando requiere pruebas de ese binario y esa compilación concretos; el número de puerto, el proceso `socat` o el propietario root, por sí solos, no lo demuestran. La enumeración pasiva debe limitarse a los metadatos de procesos, sockets y archivos, sin enviar entradas al servicio.

Un Salt master local puede escuchar en los puertos TCP 4505 y 4506, incluso en loopback o en un puerto del host publicado por un contenedor. Las [notas de la versión 3000.2 de Salt](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) describen un fallo de acceso a métodos sin autenticación, CVE-2020-11651, corregido en las versiones upstream 2019.2.4 y 3000.2. Correlaciona el listener con el proceso `salt-master` real, la interfaz accesible, el paquete instalado y las correcciones del proveedor, y la identidad efectiva del contenedor o del host antes de considerarlo una posible vía de escalada; un puerto o una versión upstream, por sí solos, no son una prueba. Si un master se ejecuta dentro de un contenedor, el impacto en root del host es un límite distinto: confirma que el contenedor tenga montado un socket de la API del runtime del host y que pueda acceder a él. La enumeración pasiva no debe consultar el servidor de solicitudes de Salt ni crear un contenedor para determinar si el sistema está afectado. Consulta la [documentación de puertos de Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) y la [evaluación de la API del runtime](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Mapea los puertos locales con sondeos ligeros.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Usa `nmap` localmente cuando esté disponible.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Subredes ocultas de veth y contenedores

Los entornos en contenedores o de laboratorio suelen exponer servicios solo en una subred de bridge o veth. Enumera las interfaces y rutas antes de asumir que no se puede acceder a un servicio.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Encuentra las posibles subredes locales.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Sondea cuidadosamente una subred descubierta.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

La técnica es útil cuando un panel web, un endpoint de depuración o un servicio auxiliar está oculto a los escaneos externos, pero es accesible desde el host comprometido o la red del contenedor.

## Tokens de servicios de notebooks entre usuarios

Un servicio de notebooks en loopback puede autenticarse con un token de inicio que se muestra en la salida de su proceso. Si esa salida se redirige a un registro que puede leer otra cuenta local, el token puede cruzar el límite entre usuarios y permitir la ejecución de código con la cuenta del servidor de notebooks. Antes de considerar la ruta del registro como una posible vía de escalada, relaciona el propietario del proceso que escucha, el destino y los permisos del registro, la configuración actual del token y los controles de acceso al notebook. Enumera los metadatos de los registros durante la enumeración pasiva; no muestres tokens ni te conectes al servicio solo para clasificar el host.

Un servicio de Jupyter Lab también puede exponer su token en un `ExecStart` de systemd legible o en la línea de comandos del proceso en ejecución (`ps auxww`), en lugar de hacerlo únicamente en los registros de inicio. En el ejemplo reportado, `User=analyst` y `--ServerApp.token` identificaban tanto la credencial como la cuenta detrás de un listener en `127.0.0.1:8888`. Con acceso al host, el token y `ssh -L 8888:127.0.0.1:8888 user@host` permitían acceder al Terminal de Jupyter Lab como ese usuario del servicio. Comprueba conjuntamente el usuario efectivo de la unidad, los argumentos del proceso, el listener y la validez del token; vincularse a loopback por sí solo no constituye un límite de autorización.<sup>[[28]](#references)</sup>

## Pivot local con socat o SSH

Si un servicio está vinculado a loopback, expónlo mediante un canal permitido en lugar de modificar el propio servicio.

Reenvía un servicio HTTP solo local mediante SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Crea un puente para un puerto local con `socat` cuando ya tengas acceso al shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Redirige un socket Unix a TCP para pruebas locales.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Esto no explota nada por sí solo. Hace que una superficie accesible solo localmente esté al alcance de tus herramientas para que puedas interactuar con ella como con un servicio normal.

## Banner Grabbing y protocolos simples

No todos los servicios usan HTTP. Muchos servicios locales filtran suficiente información mediante un banner o un protocolo de una sola línea.

Sondas básicas.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Comprobación HTTP sin navegador.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Para TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

El objetivo es identificar el protocolo, el esquema de autenticación, la versión y si el servicio confía en los clientes locales.

En un listener de aiohttp, revisa la configuración de rutas estáticas y también su versión. CVE-2024-23334 afecta a aiohttp anterior a 3.9.2 cuando una ruta estática tiene habilitado `follow_symlinks=True`: las solicitudes a esa ruta pueden leer archivos fuera del directorio raíz estático. Si el servicio se ejecuta como root, podría exponer archivos legibles por root, siempre que se pueda acceder a la ruta. Un banner de versión o una vinculación a loopback, por sí solos, no confirman que la configuración sea vulnerable ni que se pueda acceder a los archivos.<sup>[[27]](#references)</sup>

## Captura de tráfico loopback

El tráfico local puede exponer encabezados, tokens bearer, credenciales de Basic Auth o secretos específicos de la aplicación.<sup>[[17]](#references)[[25]](#references)</sup> Captura tráfico solo en entornos autorizados.

Captura tráfico HTTP loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Capturar un servicio local específico.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decodifica Basic Auth de un encabezado capturado o registrado.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Cadenas útiles para buscar en capturas de texto:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Registro de claves TLS

Si puedes controlar el entorno del proceso cliente en un laboratorio, `SSLKEYLOGFILE` puede hacer que las sesiones TLS se puedan descifrar en Wireshark o en herramientas compatibles.<sup>[[19]](#references)[[20]](#references)</sup> Esto resulta útil para entender el tráfico HTTPS local sin atacar TLS.

Ejecuta un cliente con el registro de claves habilitado.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Captura el tráfico al mismo tiempo.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Luego carga `/tmp/tls.pcap` y `/tmp/sslkeys.log` en Wireshark. Esto solo funciona si la biblioteca cliente admite el registro de claves al estilo NSS y puedes configurar el entorno antes de establecer la conexión.<sup>[[20]](#references)[[21]](#references)</sup>

## Interacción con Unix Socket y Command Injection

Los Unix sockets son puntos de conexión IPC locales.<sup>[[5]](#references)</sup> Pueden exponer API HTTP, protocolos personalizados o controladores de comandos inseguros.<sup>[[12]](#references)[[14]](#references)</sup>

Un socket propiedad de root con permiso de escritura para el grupo es un límite de autorización, no una vulnerabilidad por sí solo. Compara su grupo y modo con la cuenta actual, identifica el proceso que está escuchando y revisa qué acepta ese proceso de los clientes antes de determinar el riesgo. En particular, un servicio con privilegios que ejecuta el PHP enviado puede cruzar un segundo límite si también confía en una ruta `php.ini` elegida por quien lo invoca o permite que quien lo invoca cambie `disable_functions` o `open_basedir`; inspecciona la configuración efectiva y la ruta de validación del servicio. La [guía de configuración de PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) explica esas directivas. Los metadatos del socket por sí solos no demuestran la ejecución de código.

Busca sockets.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Interactúa con HTTP a través de un socket Unix.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interactúa con un socket raw.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Si la entrada del socket controlada por el usuario se pasa a un shell o a un helper privilegiado, puede convertirse en command injection.<sup>[[26]](#references)</sup> Para ver un ejemplo específico, consulta [Socket Command Injection](socket-command-injection.md).

## Revisión de nftables y cambios autorizados en las reglas

Las reglas del firewall local pueden explicar por qué un servicio es visible localmente pero está bloqueado desde el exterior, o por qué un puerto alto parece inaccesible desde una interfaz.<sup>[[22]](#references)</sup>

Revisa las reglas.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Busca descartes que afecten a un puerto objetivo.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

En un laboratorio autorizado, elimina una regla de bloqueo específica mediante su handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Es preferible eliminar el identificador exacto en lugar de vaciar tablas completas. La técnica consiste en identificar el filtro preciso que causa el comportamiento y cambiar solo esa regla.<sup>[[22]](#references)</sup>

## Flujo de trabajo rápido

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Prioriza los servicios que solo están disponibles localmente, se ejecutan con un usuario con más privilegios, exponen funciones de administración/depuración o confían en clientes de loopback/red de contenedores.

## References

- [1] [ss(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — página del manual de Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: arquitectura de direccionamiento de la versión 6 del protocolo IP](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — página del manual de Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirecciones (Manual de referencia de Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [invocación de timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Técnicas de escaneo de puertos (Guía de referencia de Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Detección de hosts (Guía de referencia de Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Especificación de puertos y orden de escaneo (Guía de referencia de Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — página del manual de Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — página del manual de OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Manual de la herramienta de línea de comandos curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — documentación de OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: el esquema de autenticación HTTP «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [invocación de base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — documentación de OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki de Wireshark](https://wiki.wireshark.org/tls)
- [21] [Guía del usuario de Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Manual de nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Asignación de direcciones para redes privadas (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [El marco de autorización OAuth 2.0: uso de tokens Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: neutralización incorrecta de elementos especiales usados en un comando del sistema operativo](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Aviso del mantenedor de aiohttp: traversal de rutas estáticas con follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — token de Jupyter expuesto mediante systemd y argumentos del proceso](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
