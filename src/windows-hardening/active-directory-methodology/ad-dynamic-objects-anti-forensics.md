# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Μηχανική & Βασικά Ανίχνευσης

- Κάθε αντικείμενο που δημιουργείται με την βοηθητική κλάση **`dynamicObject`** αποκτά **`entryTTL`** (αντίστροφη μέτρηση σε δευτερόλεπτα) και **`msDS-Entry-Time-To-Die`** (απόλυτη ημερομηνία λήξης). Όταν το `entryTTL` φτάσει στο 0 ο Garbage Collector το διαγράφει χωρίς tombstone/recycle-bin, σβήνοντας τον δημιουργό/χρονικά στοιχεία και εμποδίζοντας την ανάκτηση.
- Το TTL μπορεί να ανανεωθεί ενημερώνοντας το `entryTTL`; τα ελάχιστα/προεπιλεγμένα επιβάλλονται στο **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (υποστηρίζει 1s–1y αλλά συνήθως έχει προεπιλογή 86,400s/24h). Τα dynamic objects είναι **unsupported in Configuration/Schema partitions**.
- Η διαγραφή μπορεί να καθυστερήσει μερικά λεπτά σε DCs με μικρό uptime (<24h), αφήνοντας στενό παράθυρο για να ερωτηθούν/εφεδρενευθούν attributes. Εντοπισμός: **alerting σε νέα αντικείμενα που φέρουν `entryTTL`/`msDS-Entry-Time-To-Die`** και συσχέτιση με orphan SIDs/broken links.

## MAQ Evasion with Self-Deleting Computers

- Η προεπιλεγμένη **`ms-DS-MachineAccountQuota` = 10** επιτρέπει σε οποιονδήποτε authenticated χρήστη να δημιουργεί computers. Προσθέστε `dynamicObject` κατά τη δημιουργία ώστε ο υπολογιστής να αυτοδιαγραφεί και να **απελευθερώσει τη θέση του quota** ενώ σβήνει τα αποδεικτικά στοιχεία.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Σύντομο TTL (π.χ., 60s) συχνά αποτυγχάνει για standard χρήστες· το AD επιστρέφει στο **`DynamicObjectDefaultTTL`** (π.χ. 86,400s). Το ADUC μπορεί να κρύψει το `entryTTL`, αλλά ερωτήματα LDP/LDAP το αποκαλύπτουν.

## Stealth Primary Group Membership

- Δημιουργήστε μια **dynamic security group**, έπειτα ορίστε το **`primaryGroupID`** ενός χρήστη στο RID αυτής της ομάδας για να αποκτήσετε αποτελεσματική συμμετοχή που **δεν εμφανίζεται στο `memberOf`** αλλά λαμβάνεται υπόψη σε Kerberos/access tokens.
- Η λήξη του TTL **διαγράφει την ομάδα παρά την προστασία primary-group delete protection**, αφήνοντας τον χρήστη με διεφθαρμένο `primaryGroupID` που δείχνει σε ανύπαρκτο RID και χωρίς tombstone για να διερευνηθεί πώς δόθηκε το προνόμιο.

## AdminSDHolder Orphan-SID Pollution

- Προσθέστε ACEs για έναν **βραχυχρόνιο dynamic user/group** στο **`CN=AdminSDHolder,CN=System,...`**. Μετά τη λήξη του TTL το SID γίνεται **μη αναγνώσιμο (“Unknown SID”)** στο template ACL, και το **SDProp (~60 min)** διασπείρει αυτό το orphan SID σε όλα τα προστατευμένα Tier-0 αντικείμενα.
- Η forensics χάνουν την απόδοση ευθυνών γιατί ο principal έχει εξαφανιστεί (χωρίς deleted-object DN). Παρακολουθείστε για **νέους dynamic principals + ξαφνικά orphan SIDs σε AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Δημιουργήστε ένα **dynamic `groupPolicyContainer`** αντικείμενο με κακόβουλο **`gPCFileSysPath`** (π.χ. SMB share à la GPODDITY) και **συνδέστε το μέσω `gPLink`** σε έναν target OU.
- Οι clients επεξεργάζονται την πολιτική και τραβάνε περιεχόμενο από το attacker SMB. Όταν το TTL λήξει, το GPO αντικείμενο (και το `gPCFileSysPath`) εξαφανίζεται· μένει μόνο ένα **broken `gPLink`** GUID, αφαιρώντας LDAP αποδεικτικά της εκτελεσμένης payload.

## Ephemeral AD-Integrated DNS Redirection

- Οι εγγραφές AD DNS είναι αντικείμενα **`dnsNode`** μέσα σε **DomainDnsZones/ForestDnsZones**. Δημιουργώντας τις ως **dynamic objects** επιτρέπεται προσωρινή ανακατεύθυνση host (credential capture/MITM). Οι clients κρατούν στην cache την κακόβουλη A/AAAA απάντηση· η εγγραφή αυτοδιαγράφεται αργότερα και έτσι η zone φαίνεται καθαρή (το DNS Manager μπορεί να χρειαστεί reload της zone για να ανανεώσει την προβολή).
- Ανίχνευση: alert για **οποιαδήποτε DNS εγγραφή που φέρει `dynamicObject`/`entryTTL`** μέσω replication/event logs· οι παροδικές εγγραφές σπάνια εμφανίζονται στα τυπικά DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Το Entra Connect delta sync βασίζεται σε **tombstones** για να εντοπίζει διαγραφές. Ένας **dynamic on-prem user** μπορεί να συγχρονιστεί στο Entra ID, να λήξει και να διαγραφεί χωρίς tombstone—το delta sync δεν θα αφαιρέσει τον cloud λογαριασμό, αφήνοντας έναν **orphaned active Entra user** μέχρι να αναγκαστεί manual **full sync**.

## Αναφορές

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
