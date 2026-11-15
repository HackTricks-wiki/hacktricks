# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

In un attacco Pass-the-Ticket (PtT), un avversario usa un ticket Kerberos rubato per autenticarsi come principal del ticket senza conoscere la password dell'account. Un ticket-granting ticket (TGT) può essere usato per richiedere service ticket, mentre un service ticket rubato è limitato al servizio di destinazione e al relativo periodo di validità.<sup>[[1]](#references)</sup>

Per le tecniche di acquisizione dei ticket, vedi:

- [Raccolta di ticket da Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Raccolta di ticket da Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Conversione tra i formati dei ticket Linux e Windows

Le cache Kerberos sono comunemente presenti come file MIT `ccache` su Linux e file `.kirbi` su Windows. `ticket_converter` converte questi formati usando un ticket di input e un percorso di output.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo offre anche strumenti per i ticket Kerberos su Windows.<sup>[[3]](#references)</sup>

## Usare un ticket

Su Linux, imposta `KRB5CCNAME` sul percorso della cache e indica a un client Impacket di usare Kerberos senza richiedere una password:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Su Windows, Mimikatz o Rubeus possono importare un ticket `.kirbi` nella sessione di accesso corrente. Usa `klist` per esaminare la cache risultante.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

L'importazione di un ticket non concede privilegi ulteriori rispetto a quelli rappresentati dal ticket e dalla policy di autorizzazione del servizio di destinazione. I ticket scaduti, revocati, malformati o con ambito non corretto potrebbero non funzionare.<sup>[[1]](#references)</sup>

Per un contesto più ampio sugli attacchi Kerberos e sulle tecniche correlate di acquisizione dei ticket, consulta la guida agli attacchi Kerberos di Tarlogic.<sup>[[7]](#references)</sup>

### Riutilizzare un ticket esterno in Metasploit

Metasploit non legge automaticamente `KRB5CCNAME` di Impacket per i suoi moduli Kerberos. Fornisci al modulo un **file ccache** tramite l'opzione `::Krb5Ccname` specifica per il protocollo. Imposta `::Rhostname` sul nome host SPN della destinazione e il dominio sul dominio di destinazione; `RHOST` può comunque essere l'IP della destinazione. In questo modo è possibile usare un ticket già acquisito senza inserire la password dell'account.<sup>[[8]](#references)</sup>

Se necessario, converti prima un `.kirbi` in ccache.<sup>[[9]](#references)</sup>

Ad esempio, con un ticket per un account autorizzato a creare servizi sulla destinazione, esegui il [modulo SMB PsExec](../lateral-movement/psexec-and-winexec.md) usando quella cache:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit seleziona prima dalla cache fornita un ticket di servizio corrispondente. Se trova solo un TGT, richiede un ticket di servizio al KDC, quindi anche questo percorso richiede connettività con il DC. Una cache contenente solo ticket di servizio non consente l'accesso a host non correlati. Per gli altri moduli supportati, modifica il prefisso dell'opzione (ad esempio, `Winrm::Krb5Ccname` per [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Esempi di Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Tecniche di attacco Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Autenticazione del servizio](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Conversione di file kirbi e ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Implementazione Kerberos del client SMB di Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
