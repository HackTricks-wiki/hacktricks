# Δυναμικά Αντικείμενα AD (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Βασικοί Μηχανισμοί & Ανίχνευση

- Κάθε αντικείμενο που δημιουργείται με την auxiliary class **`dynamicObject`** αποκτά τα **`entryTTL`** (αντίστροφη μέτρηση σε δευτερόλεπτα) και **`msDS-Entry-Time-To-Die`** (απόλυτη ημερομηνία λήξης). Όταν το **`entryTTL`** φτάσει στο 0, το **Garbage Collector** το διαγράφει χωρίς tombstone/recycle-bin, διαγράφοντας τον δημιουργό και τα timestamps και αποκλείοντας την ανάκτηση.
- Το **`entryTTL`** είναι operational/constructed attribute: ζητήστε το ρητά σε LDAP queries. Το TTL μπορεί να ανανεωθεί είτε με ενημέρωση του **`entryTTL`** πριν από τη λήξη είτε μέσω του LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Τα ελάχιστα/προεπιλεγμένα TTL επιβάλλονται στο **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Η Microsoft τεκμηριώνει τα **86400s** ως το προεπιλεγμένο TTL και τα **900s** ως το προεπιλεγμένο ελάχιστο έγκυρο TTL· και τα δύο υποστηρίζουν τιμές από **1s–1y**. Τα dynamic objects δεν υποστηρίζονται στα **Configuration/Schema partitions**.
- Δεν υπάρχει μετατροπή static→dynamic ούτε φάση tombstone μετά τη λήξη. Οι ομάδες IR δεν μπορούν να βασιστούν σε deleted-object controls ή στο Recycle Bin· πρέπει να καταγράψουν το ενεργό αντικείμενο/metadata πριν το αφαιρέσει το GC.
- Η ανανέωση είναι ευαίσθητη στα replicas: αν το TTL ανανεωθεί πολύ κοντά στη λήξη, ένα άλλο writable replica ή το GC μπορεί να διαγράψει το αντικείμενο τοπικά πριν αναπαραχθεί η ανανέωση. Επομένως, τα πολύ σύντομα TTL λειτουργούν καλύτερα όταν ο attacker γνωρίζει ποιο DC θα εξυπηρετήσει την κατάχρηση, ενώ οι defenders πρέπει να κάνουν query σε **όλα τα naming contexts / replicas** κατά το triage.
- Η διαγραφή μπορεί να καθυστερήσει μερικά λεπτά σε DCs με σύντομο uptime (<24h), αφήνοντας ένα περιορισμένο παράθυρο απόκρισης για query/backup των attributes. Εντοπίστε το με **alerting σε νέα αντικείμενα που περιέχουν `entryTTL`/`msDS-Entry-Time-To-Die`** και συσχετίστε τα με orphan SIDs/broken links.<sup>[[1]](#references)</sup>

## Γρήγορη Enumeration / Live Triage

- Κάντε query σε **όλα τα `namingContexts` από το RootDSE**, όχι μόνο στο domain NC. Η κατάχρηση dynamic objects μπορεί να βρίσκεται στα **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ή σε application partitions.
- Όσο το αντικείμενο παραμένει ενεργό, κάντε αμέσως dump των **replication metadata** και όλων των linked attributes/ACLs. Μετά τη λήξη μπορεί να απομείνουν μόνο **broken `gPLink` values, orphan SIDs ή cached DNS answers**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion με Self-Deleting Computers

- Το προεπιλεγμένο **`ms-DS-MachineAccountQuota` = 10** επιτρέπει σε οποιονδήποτε authenticated user να δημιουργεί computers. Προσθέστε `dynamicObject` κατά τη δημιουργία, ώστε το computer να διαγράφεται μόνο του και να **απελευθερώνει το quota slot**, διαγράφοντας παράλληλα τα ίχνη.
- Τροποποίηση του Powermad μέσα στο `New-MachineAccount` (λίστα objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Αν το ζητούμενο TTL είναι **μικρότερο από το `DynamicObjectMinTTL`**, αναμένεται προσαρμογή ή απόρριψη από τον server, ανάλογα με το creation path. Σε πολλά domains το effective floor είναι **900s**, ενώ το fallback/default παραμένει **86400s**. Το ADUC μπορεί να αποκρύπτει το `entryTTL`, αλλά τα LDP/LDAP queries το αποκαλύπτουν.
- Όσο το object υπάρχει, οι defenders μπορούν ακόμη να ανακτήσουν τον unprivileged creator από το **`msDS-CreatorSID`** στο computer object. Μόλις λήξει το dynamic computer, αυτή η συσχέτιση εξαφανίζεται μαζί με το object.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Δημιουργήστε ένα **dynamic security group** και, στη συνέχεια, ορίστε το **`primaryGroupID`** ενός user στο RID αυτού του group, ώστε να αποκτήσει effective membership που **δεν εμφανίζεται στο `memberOf`**, αλλά αναγνωρίζεται από το Kerberos και τα access tokens.<sup>[[1]](#references)</sup>
- Η λήξη του TTL **διαγράφει το group παρά την προστασία διαγραφής primary group**, αφήνοντας τον user με corrupted `primaryGroupID` που δείχνει σε ανύπαρκτο RID και χωρίς tombstone για τη διερεύνηση του τρόπου με τον οποίο παραχωρήθηκε το privilege.
- Το reporting εξαρτάται από το tool: τα **`Get-ADGroupMember` / `net group`** συνήθως επιλύουν το membership που προκύπτει από το primary group, ενώ τα **`memberOf`** και **`Get-ADGroup -Properties member`** όχι. Για ευρύτερο primaryGroupID tradecraft, δείτε [αυτή την άλλη σελίδα σχετικά με DCShadow και PGID abuse](dcshadow.md).
- Για targets που **δεν προστατεύονται από το AdminSDHolder**, οι attackers μπορούν να συνδυάσουν το dynamic-group trick με ένα **DACL deny για την ανάγνωση του `primaryGroupID`** (ή του `member` attribute του group), ώστε να αποκρύψουν τη σύνδεση από πολλά LDAP/PowerShell workflows ακόμη και πριν λήξει το group.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Προσθέστε ACEs για έναν **short-lived dynamic user/group** στο **`CN=AdminSDHolder,CN=System,...`**. Μετά τη λήξη του TTL, το SID γίνεται **μη επιλύσιμο («Unknown SID»)** στο template ACL και το **SDProp (~60 min)** διαδίδει αυτό το orphan SID σε όλα τα προστατευμένα Tier-0 objects.
- Οι forensic έρευνες χάνουν τη συσχέτιση, επειδή το principal έχει εξαφανιστεί (δεν υπάρχει deleted-object DN). Παρακολουθείτε για **νέα dynamic principals + ξαφνικά orphan SIDs στα AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution με Self-Destructing Evidence

- Δημιουργήστε ένα **dynamic `groupPolicyContainer`** object με κακόβουλο **`gPCFileSysPath`** (π.χ. SMB share à la GPODDITY) και συνδέστε το μέσω **`gPLink`** σε ένα target OU.
- Οι clients εφαρμόζουν την policy και αντλούν content από το attacker SMB. Όταν λήξει το TTL, το GPO object (και το `gPCFileSysPath`) εξαφανίζεται. Παραμένει μόνο ένα **broken `gPLink`** GUID, αφαιρώντας τα LDAP ίχνη του executed payload.
- Αυτό είναι operationally cleaner από το κλασικό **GPODDITY-style** cleanup: αντί να επαναφέρετε μόνοι σας το αρχικό `gPCFileSysPath`, το AD αφαιρεί αυτόματα το malicious GPC μόλις λήξει ο timer.<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- Τα AD DNS records είναι **`dnsNode`** objects στα **DomainDnsZones/ForestDnsZones**. Η δημιουργία τους ως **dynamic objects** επιτρέπει προσωρινό host redirection (credential capture/MITM). Οι clients κάνουν cache τη malicious A/AAAA response. Στη συνέχεια, το record διαγράφεται μόνο του, ώστε η zone να φαίνεται καθαρή (το DNS Manager μπορεί να χρειάζεται zone reload για να ανανεώσει την προβολή).
- Detection: δημιουργήστε alert για **οποιοδήποτε DNS record περιέχει `dynamicObject`/`entryTTL`** μέσω replication/event logs. Τα transient records σπάνια εμφανίζονται στα standard DNS logs.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Το Entra Connect delta sync βασίζεται σε **tombstones** για τον εντοπισμό διαγραφών. Ένας **dynamic on-prem user** μπορεί να συγχρονιστεί στο Entra ID, να λήξει και να διαγραφεί χωρίς tombstone. Το delta sync δεν θα αφαιρέσει τον cloud account, αφήνοντας έναν **orphaned active Entra user** μέχρι να εκτελεστεί **initial/full sync** ή να επιβληθεί manual cloud cleanup.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
