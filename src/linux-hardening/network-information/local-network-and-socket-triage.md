# Triaje de la red local y los sockets

{{#include ../../banners/hacktricks-training.md}}

Después de obtener un shell en un host Linux, los objetivos de red más útiles a menudo no están expuestos externamente. Los servicios limitados al loopback, las redes veth, los sockets Unix, los listeners temporales, las capturas de paquetes y las reglas de firewall locales pueden exponer credenciales o superficies de ataque accesibles únicamente de forma local.

Esta página se centra en técnicas prácticas de post-exploitation local, no en pentesting general de redes remotas.

## Enumeración del loopback y los servicios locales

Comienza identificando los servicios en escucha, sus direcciones de enlace y el proceso propietario cuando los permisos lo permitan.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Patrones importantes:

- `127.0.0.1:<port>` o `[::1]:<port>`: accesibles solo desde el host de forma predeterminada.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: accesible en todas las interfaces IPv4, a menos que se filtre.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` o `192.168.0.0/16` en `veth*`, `docker*`, `br-*`, `cni*`: probablemente redes de contenedores o laboratorios locales.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets en `/run`, `/var/run`, `/tmp` o directorios de aplicaciones: superficies de IPC local.<sup>[[5]](#references)</sup>

Mapea los puertos locales con probes ligeros.<sup>[[6]](#references)[[7]](#references)</sup>
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
## veth ocultas y subredes de contenedores

Los entornos en contenedores o de laboratorio suelen exponer servicios únicamente en una bridge o subred veth. Enumera las interfaces y las rutas antes de asumir que un servicio es inaccesible.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Encuentra las subredes locales probables.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sondea cuidadosamente una subred descubierta.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La técnica es útil cuando un panel web, un endpoint de debug o un servicio auxiliar está oculto para los escaneos externos, pero es accesible desde el host comprometido o la red del contenedor.

## Pivot local con socat o SSH

Si un servicio está vinculado a loopback, expónlo a través de un canal permitido en lugar de modificar el servicio.

Reenvía un servicio HTTP disponible solo localmente con SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Puentea un puerto local con `socat` cuando ya tengas acceso a un shell.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Reenvía un socket Unix a TCP para pruebas locales.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Esto no explota nada por sí mismo. Hace que una superficie accesible únicamente de forma local esté disponible para tus herramientas, de modo que puedas interactuar con ella como con un servicio normal.

## Banner Grabbing y protocolos simples

No todos los servicios son HTTP. Muchos servicios locales leak suficiente información mediante un banner o un protocolo de una sola línea.

Sondeos básicos.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Comprobación de HTTP sin un navegador.<sup>[[13]](#references)[[14]](#references)</sup>
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

## Captura de tráfico de loopback

El tráfico local puede exponer headers, bearer tokens, credenciales de Basic Auth o secretos específicos de la aplicación.<sup>[[17]](#references)[[25]](#references)</sup> Captura únicamente en entornos autorizados.

Captura el tráfico HTTP de loopback.<sup>[[16]](#references)</sup>
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
Cadenas útiles que buscar en capturas de texto:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Si puedes controlar el entorno del proceso del cliente en un lab, `SSLKEYLOGFILE` puede hacer que las sesiones TLS se puedan descifrar en Wireshark o con herramientas compatibles.<sup>[[19]](#references)[[20]](#references)</sup> Esto resulta útil para comprender el tráfico HTTPS local sin atacar TLS directamente.

Ejecuta un cliente con el key logging habilitado.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Captura el tráfico al mismo tiempo.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Luego carga `/tmp/tls.pcap` y `/tmp/sslkeys.log` en Wireshark. Esto solo funciona cuando la biblioteca cliente admite el registro de claves con el estilo de NSS y puedes establecer el entorno antes de realizar la conexión.<sup>[[20]](#references)[[21]](#references)</sup>

## Interacción con Unix Sockets e Inyección de Comandos

Los Unix sockets son endpoints locales de IPC.<sup>[[5]](#references)</sup> Pueden exponer APIs HTTP, protocolos personalizados o controladores de comandos inseguros.<sup>[[12]](#references)[[14]](#references)</sup>

Encuentra sockets.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interactuar con HTTP a través de un socket Unix.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interactuar con un raw socket.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Si la entrada de socket controlada por el usuario se pasa a un shell o a un helper con privilegios, puede convertirse en command injection.<sup>[[26]](#references)</sup> Para ver un ejemplo específico, consulta [Socket Command Injection](socket-command-injection.md).

## Revisión de nftables y cambios de reglas autorizados

Las reglas del firewall local pueden explicar por qué un servicio es visible localmente pero está bloqueado remotamente, o por qué un puerto alto parece inaccesible desde una interfaz.<sup>[[22]](#references)</sup>

Revisar las reglas.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Busca drops que afecten a un puerto de destino.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
En un laboratorio autorizado, elimina una regla de bloqueo específica mediante su handle.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prefiere eliminar el handle exacto en lugar de vaciar tablas completas. La técnica consiste en identificar el filtro preciso que causa el comportamiento y cambiar únicamente esa regla.<sup>[[22]](#references)</sup>

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
Prioriza los servicios que sean exclusivamente locales, se ejecuten con un usuario con más privilegios, expongan funciones de administración/depuración o confíen en clientes de loopback/red de contenedores.

## References

- [1] [ss(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — página del manual de Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: arquitectura de direccionamiento de IP versión 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — página del manual de Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirecciones (manual de referencia de Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [invocación de timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Técnicas de escaneo de puertos (guía de referencia de Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Descubrimiento de hosts (guía de referencia de Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Especificación de puertos y orden de escaneo (guía de referencia de Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — página del manual de Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — página del manual de OpenBSD](https://man.openbsd.org/nc.1)
- [14] [manual de la herramienta de línea de comandos curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — documentación de OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: el esquema de autenticación HTTP «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [invocación de base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — documentación de OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — wiki de Wireshark](https://wiki.wireshark.org/tls)
- [21] [guía del usuario de Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [manual de nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [asignación de direcciones para redes privadas (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [marco de autorización OAuth 2.0: uso de tokens portador (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: neutralización incorrecta de elementos especiales utilizados en un comando del sistema operativo](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
