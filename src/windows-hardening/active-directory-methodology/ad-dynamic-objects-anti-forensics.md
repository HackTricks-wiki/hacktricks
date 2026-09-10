# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Βασικές αρχές λειτουργίας και ανίχνευσης

- Κάθε object που δημιουργείται με την auxiliary class **`dynamicObject`** αποκτά **`entryTTL`** (αντίστροφη μέτρηση σε seconds) και **`msDS-Entry-Time-To-Die`** (απόλυτη ημερομηνία λήξης). Όταν το `entryTTL` φτάσει στο 0 **και το object δεν έχει descendants**, ο Garbage Collector το διαγράφει χωρίς tombstone/recycle-bin, διαγράφοντας τον creator και τα timestamps και εμποδίζοντας την ανάκτηση.<sup>[[4]](#references)</sup>
- Το **`entryTTL` είναι operational/constructed attribute**: ζητήστε το ρητά σε LDAP queries. Το TTL μπορεί να ανανεωθεί είτε με ενημέρωση του `entryTTL` πριν από τη λήξη είτε μέσω του LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Τα ελάχιστα/προεπιλεγμένα TTL είναι forest-wide AVAs στο **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` και `DynamicObjectDefaultTTLSeconds=<seconds>`. Η Microsoft τεκμηριώνει τα **86400s** ως το προεπιλεγμένο TTL και τα **900s** ως το προεπιλεγμένο ελάχιστο έγκυρο TTL· το schema range του `entryTTL` είναι **1–31557600s** (ένα second έως ένα έτος).<sup>[[3]](#references)</sup> Τα dynamic objects **δεν υποστηρίζονται στα Configuration/Schema partitions**.
- Δεν υπάρχει **static→dynamic conversion** ούτε tombstone phase μετά τη λήξη. Οι IR teams δεν μπορούν να βασιστούν σε deleted-object controls ή στο Recycle Bin· πρέπει να καταγράψουν το live object/metadata πριν το αφαιρέσει ο GC.
- Το refresh είναι **replica-sensitive**: αν το TTL ανανεωθεί πολύ κοντά στη λήξη, ένα άλλο writable replica ή ο GC μπορεί να διαγράψει το object τοπικά πριν αναπαραχθεί το refresh. Επομένως, τα πολύ σύντομα TTL λειτουργούν καλύτερα όταν ο attacker γνωρίζει ποιο DC θα εξυπηρετήσει το abuse, ενώ οι defenders πρέπει να κάνουν query σε **όλα τα naming contexts / replicas** κατά το triage.
- Η διαγραφή μπορεί να καθυστερήσει μερικά λεπτά σε DCs με σύντομο uptime (<24h), αφήνοντας ένα στενό response window για query/backup των attributes. Εντοπίστε το με **alerting σε νέα objects που περιέχουν `entryTTL`/`msDS-Entry-Time-To-Die`** και συσχετίστε τα με orphan SIDs/broken links.<sup>[[1]](#references)</sup>

### Edge cases του expiry graph και του reference cleanup

- Κάθε descendant κάτω από ένα dynamic object πρέπει να είναι και το ίδιο dynamic. Ένα expired dynamic parent συλλέγεται από τον GC μόνο αφού γίνει leaf· αν ένας descendant έχει μεταγενέστερο `msDS-Entry-Time-To-Die`, το DC μεταθέτει τη λήξη του parent πέρα από τη μέγιστη λήξη descendant. Κατά συνέπεια, ένα writable dynamic subtree μπορεί να **pin/extend ένα parent που φαίνεται έτοιμο να εξαφανιστεί**: κάντε enumerate ολόκληρο το subtree και μην χρησιμοποιείτε το παρατηρούμενο `entryTTL` του parent ως deadline για το cleanup.<sup>[[4]](#references)</sup>
- Το expiry cleanup είναι **schema-link-aware**. Τα replicas αφαιρούν linked attribute values που αναφέρονται στο deleted dynamic object, αλλά διατηρούν nonlinked values. Αναμένετε το συνηθισμένο forward/back-link membership να καθαρίζεται, ενώ integer/SID/string references όπως `primaryGroupID`, SIDs ενσωματωμένα στο `nTSecurityDescriptor` ή κείμενο `gPLink` μπορεί να παραμένουν ως forensic residue.<sup>[[4]](#references)</sup>

## Fast Enumeration / Live Triage

- Κάντε query σε **όλα τα `namingContexts` από το RootDSE**, όχι μόνο στο domain NC. Το dynamic abuse μπορεί να βρίσκεται στα **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ή σε application partitions.
- Όσο το object είναι ακόμη ζωντανό, κάντε αμέσως dump τα **replication metadata** και τυχόν linked attributes/ACLs. Μετά τη λήξη μπορεί να σας μείνουν μόνο **broken `gPLink` values, orphan SIDs ή cached DNS answers**.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Παράκαμψη MAQ με Self-Deleting Computers

- Το προεπιλεγμένο **`ms-DS-MachineAccountQuota` = 10** επιτρέπει σε οποιονδήποτε authenticated user να δημιουργεί computers. Προσθέστε το `dynamicObject` κατά τη δημιουργία, ώστε το computer να διαγράφεται μόνο του και να **απελευθερώνει τη θέση quota**, διαγράφοντας παράλληλα τα ίχνη.
- Τροποποίηση του Powermad μέσα στο `New-MachineAccount` (λίστα objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Αν το ζητούμενο TTL είναι **κάτω από το `DynamicObjectMinTTL`**, αναμένετε προσαρμογή ή απόρριψη από τον server, ανάλογα με τη διαδρομή δημιουργίας. Σε πολλά domains το effective floor είναι **900s** και το fallback/default παραμένει **86400s**. Το ADUC μπορεί να αποκρύπτει το `entryTTL`, αλλά τα LDP/LDAP queries το αποκαλύπτουν.
- Όσο το object υπάρχει, οι defenders μπορούν ακόμη να ανακτήσουν τον unprivileged creator από το **`msDS-CreatorSID`** στο computer object. Μόλις λήξει το dynamic computer, αυτή η απόδοση εξαφανίζεται μαζί με το object.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Δημιουργήστε ένα **dynamic security group** και, στη συνέχεια, ορίστε το **`primaryGroupID`** ενός user στο RID αυτού του group, ώστε να αποκτήσει effective membership που **δεν εμφανίζεται στο `memberOf`**, αλλά λαμβάνεται υπόψη στα Kerberos/access tokens.<sup>[[1]](#references)</sup>
- Η λήξη του TTL **διαγράφει το group παρά την προστασία διαγραφής του primary group**, αφήνοντας τον user με ένα κατεστραμμένο `primaryGroupID` που δείχνει σε ανύπαρκτο RID και χωρίς tombstone για τη διερεύνηση του τρόπου με τον οποίο παραχωρήθηκε το privilege.
- Το reporting εξαρτάται από το tool: τα **`Get-ADGroupMember` / `net group`** συνήθως επιλύουν membership που προέρχεται από primary group, ενώ τα **`memberOf`** και **`Get-ADGroup -Properties member`** όχι. Για ευρύτερο tradecraft σχετικά με το `primaryGroupID`, δείτε [αυτή την άλλη σελίδα σχετικά με DCShadow και PGID abuse](dcshadow.md).
- Για targets που **δεν προστατεύονται από το AdminSDHolder**, οι attackers μπορούν να συνδυάσουν το dynamic-group trick με ένα **DACL deny για την ανάγνωση του `primaryGroupID`** (ή του attribute `member` του group), ώστε να αποκρύψουν τη σύνδεση από πολλά LDAP/PowerShell workflows ακόμη και πριν λήξει το group.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Προσθέστε ACEs για έναν **short-lived dynamic user/group** στο **`CN=AdminSDHolder,CN=System,...`**. Μετά τη λήξη του TTL, το SID γίνεται **μη επιλύσιμο (“Unknown SID”)** στο template ACL και το **SDProp (~60 min)** προωθεί αυτό το orphan SID σε όλα τα protected Tier-0 objects.
- Τα forensics χάνουν την απόδοση, επειδή το principal έχει εξαφανιστεί (χωρίς deleted-object DN). Παρακολουθείτε για **νέα dynamic principals + ξαφνικά orphan SIDs σε AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution με Self-Destructing Evidence

- Δημιουργήστε ένα **dynamic `groupPolicyContainer`** object με κακόβουλο **`gPCFileSysPath`** (π.χ. SMB share à la GPODDITY) και συνδέστε το μέσω **`gPLink`** σε ένα target OU.
- Οι clients επεξεργάζονται την policy και ανακτούν περιεχόμενο από το attacker SMB. Όταν λήξει το TTL, το GPO object (και το `gPCFileSysPath`) εξαφανίζεται· παραμένει μόνο ένα **broken `gPLink`** GUID, αφαιρώντας τα LDAP evidence του payload που εκτελέστηκε.
- Αυτό είναι λειτουργικά καθαρότερο από το κλασικό **GPODDITY-style** cleanup: αντί να επαναφέρετε εσείς το αρχικό `gPCFileSysPath`, το AD αφαιρεί αυτόματα το malicious GPC μόλις λήξει ο timer.<sup>[[1]](#references)</sup> Δείτε το [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) για τις λεπτομέρειες του protocol και των tools, αντί να τις επαναλάβουμε εδώ.

## Ephemeral AD-Integrated DNS Redirection

- Τα AD DNS records είναι **`dnsNode`** objects στα **DomainDnsZones/ForestDnsZones**. Η δημιουργία τους ως **dynamic objects** επιτρέπει προσωρινό host redirection (credential capture/MITM). Οι clients κάνουν cache την κακόβουλη A/AAAA response· το record αργότερα διαγράφεται μόνο του, ώστε το zone να φαίνεται καθαρό (το DNS Manager μπορεί να χρειάζεται zone reload για την ανανέωση της προβολής).
- Detection: δημιουργήστε alert για **οποιοδήποτε DNS record φέρει `dynamicObject`/`entryTTL`** μέσω replication/event logs· τα transient records σπάνια εμφανίζονται στα standard DNS logs.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Σημείωση)

- Το Entra Connect delta sync βασίζεται σε **tombstones** για τον εντοπισμό deletes. Ένας **dynamic on-prem user** μπορεί να συγχρονιστεί στο Entra ID, να λήξει και να διαγραφεί χωρίς tombstone — το delta sync δεν θα αφαιρέσει τον cloud account, αφήνοντας έναν **orphaned active Entra user** μέχρι να εκτελεστεί **initial/full sync** ή να επιβληθεί χειροκίνητο cloud cleanup.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects in Active Directory: Η Stealthy Απειλή](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuration of TTL Limits](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
