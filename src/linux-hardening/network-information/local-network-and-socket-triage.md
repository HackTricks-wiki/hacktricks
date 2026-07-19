# Triage de red local y sockets

{{#include ../../banners/hacktricks-training.md}}

Después de obtener un shell en un host Linux, los objetivos de red más útiles a menudo no están expuestos externamente. Los servicios que solo están disponibles mediante loopback, las redes veth, los sockets Unix, los listeners temporales, las capturas de paquetes y las reglas de firewall locales pueden exponer credenciales o superficies de ataque disponibles únicamente de forma local.

Esta página se centra en técnicas prácticas de post-exploitation local, no en pentesting general de redes remotas.

## Enumeración de loopback y servicios locales

Comienza identificando los servicios en escucha, sus direcciones de enlace y el proceso propietario cuando los permisos lo permitan:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Patrones importantes:

- `127.0.0.1:<port>` o `[::1]:<port>`: accesibles solo desde el host de forma predeterminada.
- `0.0.0.0:<port>`: accesibles en todas las interfaces IPv4 salvo que se filtren.
- `172.x`, `10.x` o `192.168.x` en `veth*`, `docker*`, `br-*`, `cni*`: probablemente redes de contenedores o laboratorios locales.
- Sockets Unix en `/run`, `/var/run`, `/tmp` o directorios de aplicaciones: superficies de IPC locales.

Mapea los puertos locales con probes ligeros:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Usa `nmap` localmente cuando esté disponible:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## veth ocultas y subredes de contenedores

Los entornos contenerizados o de laboratorio suelen exponer servicios únicamente en una bridge o subred veth. Enumera las interfaces y las rutas antes de asumir que un servicio es inalcanzable:
```bash
ip -br addr
ip route
ip neigh
```
Encuentra las subredes locales probables:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Sondea cuidadosamente una subred descubierta:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
La técnica es útil cuando un panel web, endpoint de debug o servicio auxiliar está oculto para los escaneos externos, pero es accesible desde el host comprometido o la red del contenedor.

## Pivot Local con socat o SSH

Si un servicio está vinculado a loopback, expóngalo a través de un canal permitido en lugar de modificar el propio servicio.

Reenvía un servicio HTTP local mediante SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Puentea un puerto local con `socat` cuando ya tengas acceso a shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Reenviar un socket Unix a TCP para pruebas locales:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Esto no explota nada por sí mismo. Hace que una superficie accesible únicamente de forma local esté al alcance de tus herramientas, para que puedas interactuar con ella como con un servicio normal.

## Banner Grabbing y protocolos simples

No todos los servicios son HTTP. Muchos servicios locales hacen leak de suficiente información mediante un banner o un protocolo de una sola línea.

Probes básicos:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Comprobación HTTP sin un navegador:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Para TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
El objetivo es identificar el protocolo, el esquema de autenticación, la versión y si el servicio confía en los clientes locales.

## Captura de tráfico de loopback

El tráfico local puede exponer cabeceras, bearer tokens, credenciales de Basic Auth o secretos específicos de la aplicación. Captura únicamente en entornos autorizados.

Captura tráfico HTTP de loopback:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Capturar un servicio local específico:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decodifica Basic Auth desde un header capturado o registrado:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Cadenas útiles que buscar en capturas de texto:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Registro de claves TLS

Si puedes controlar el entorno del proceso cliente en un laboratorio, `SSLKEYLOGFILE` puede hacer que las sesiones TLS sean descifrables en Wireshark o herramientas compatibles. Esto resulta útil para comprender el tráfico HTTPS local sin atacar TLS directamente.

Ejecuta un cliente con el registro de claves habilitado:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Captura el tráfico al mismo tiempo:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Luego carga `/tmp/tls.pcap` y `/tmp/sslkeys.log` en Wireshark. Esto solo funciona cuando la biblioteca cliente admite el registro de claves con el estilo de NSS y puedes establecer el entorno antes de realizar la conexión.

## Interacción con Unix Socket y Command Injection

Los Unix sockets son endpoints locales de IPC. Pueden exponer APIs HTTP, protocolos personalizados o controladores de comandos inseguros.

Encuentra los sockets:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interactuar con HTTP a través de un Unix socket:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interactuar con un raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Si la entrada de socket controlada por el usuario se pasa a un shell o a un helper con privilegios, puede convertirse en command injection. Para ver un ejemplo específico, consulta [Socket Command Injection](socket-command-injection.md).

## Revisión de nftables y cambios de reglas autorizados

Las reglas del firewall local pueden explicar por qué un servicio es visible localmente, pero está bloqueado de forma remota, o por qué un puerto alto parece inaccesible desde una interfaz.

Revisar las reglas:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Busca drops que afecten a un puerto objetivo:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
En un laboratorio autorizado, elimina una regla de bloqueo específica por su handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Prefiere eliminar el handle exacto en lugar de vaciar las tablas completas. La técnica consiste en identificar el filtro preciso que causa el comportamiento y cambiar únicamente esa regla.

## Flujo rápido
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Prioriza los servicios que sean solo locales, se ejecuten con un usuario más privilegiado, expongan funciones de administración/depuración o confíen en clientes de loopback/red de contenedores.
{{#include ../../banners/hacktricks-training.md}}
