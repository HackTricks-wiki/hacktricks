# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Μηχανισμοί & Βασικές Αρχές Ανίχνευσης

- Οποιοδήποτε αντικείμενο δημιουργείται με την βοηθητική κλάση **`dynamicObject`** αποκτά **`entryTTL`** (αντίστροφη μέτρηση σε δευτερόλεπτα) και **`msDS-Entry-Time-To-Die`** (απόλυτη ημερομηνία λήξης). Όταν το `entryTTL` φτάσει στο 0, ο **Garbage Collector το διαγράφει χωρίς tombstone/recycle-bin**, σβήνοντας τον δημιουργό/χρονικές σημάνσεις και εμποδίζοντας την ανάκτηση.
- Το TTL μπορεί να ανανεωθεί ενημερώνοντας το `entryTTL`; επιβάλλονται min/default τιμές στις **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (υποστηρίζει 1s–1y αλλά συνήθως έχει default 86,400s/24h). Τα dynamic objects είναι **unsupported στα Configuration/Schema partitions**.
- Η διαγραφή μπορεί να υστερήσει λίγα λεπτά σε DCs με μικρό uptime (<24h), αφήνοντας στενό παράθυρο για ερωτήματα/backup attributes. Εντοπίστε με **alert για νέα αντικείμενα που φέρουν `entryTTL`/`msDS-Entry-Time-To-Die`** και συσχετισμό με orphan SIDs/σπασμένους συνδέσμους.

## MAQ Evasion with Self-Deleting Computers

- Το default **`ms-DS-MachineAccountQuota` = 10** επιτρέπει σε οποιονδήποτε authenticated user να δημιουργήσει computers. Προσθέστε `dynamicObject` κατά τη δημιουργία για να κάνει το computer self-delete και να **απελευθερώσει το quota slot** ενώ σβήνει τα αποδεικτικά στοιχεία.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Short TTL (π.χ., 60s) συχνά αποτυγχάνει για standard users· το AD fallback σε **`DynamicObjectDefaultTTL`** (παράδειγμα: 86,400s). Το ADUC μπορεί να κρύβει το `entryTTL`, αλλά τα LDP/LDAP queries το αποκαλύπτουν.

## Stealth Primary Group Membership

- Δημιουργήστε μια **dynamic security group**, στη συνέχεια ορίστε το `primaryGroupID` ενός χρήστη στην RID αυτής της group για να αποκτήσει αποτελεσματική membership που **δεν εμφανίζεται στο `memberOf`** αλλά γίνεται σεβαστή σε Kerberos/access tokens.
- Όταν λήξει το TTL **η ομάδα διαγράφεται παρά την προστασία διαγραφής primary-group**, αφήνοντας τον χρήστη με corrupted `primaryGroupID` που δείχνει σε μη υπάρχουσα RID και χωρίς tombstone για διερεύνηση πώς παραχωρήθηκε το προνόμιο.

## AdminSDHolder Orphan-SID Pollution

- Προσθέστε ACEs για έναν **short-lived dynamic user/group** στο **`CN=AdminSDHolder,CN=System,...`**. Μετά τη λήξη του TTL, το SID γίνεται **unresolvable (“Unknown SID”)** στο template ACL, και το **SDProp (~60 min)** διασπείρει αυτό το orphan SID σε όλα τα προστατευμένα Tier-0 αντικείμενα.
- Οι forensics χάνουν attribution επειδή ο principal έχει εξαφανιστεί (χωρίς deleted-object DN). Παρακολουθείστε για **new dynamic principals + ξαφνικά orphan SIDs στο AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Δημιουργήστε ένα **dynamic `groupPolicyContainer`** αντικείμενο με κακόβουλο **`gPCFileSysPath`** (π.χ., SMB share à la GPODDITY) και **link το μέσω `gPLink`** σε ένα στόχο OU.
- Οι clients επεξεργάζονται το policy και κατεβάζουν περιεχόμενο από attacker SMB. Όταν λήξει το TTL, το GPO αντικείμενο (και το `gPCFileSysPath`) εξαφανίζεται· μένει μόνο ένα **broken `gPLink`** GUID, αφαιρώντας το LDAP evidence του εκτελεσθέντος payload.

## Ephemeral AD-Integrated DNS Redirection

- Τα AD DNS records είναι **`dnsNode`** αντικείμενα σε **DomainDnsZones/ForestDnsZones**. Δημιουργώντας τα ως **dynamic objects** επιτρέπεται προσωρινή ανακατεύθυνση host (credential capture/MITM). Οι clients cache-άρουν την κακόβουλη A/AAAA απάντηση· το record αυτοκαταστρέφεται αργότερα ώστε η ζώνη να φαίνεται καθαρή (το DNS Manager μπορεί να χρειαστεί reload ζώνης για ανανέωση της προβολής).
- Ανίχνευση: alert για **οποιοδήποτε DNS record που φέρει `dynamicObject`/`entryTTL`** μέσω replication/event logs· τα transient records σπάνια φαίνονται σε standard DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Το Entra Connect delta sync βασίζεται σε **tombstones** για να εντοπίσει διαγραφές. Ένας **dynamic on-prem user** μπορεί να γίνει sync στο Entra ID, να λήξει και να διαγραφεί χωρίς tombstone—το delta sync δεν θα αφαιρέσει το cloud account, αφήνοντας έναν **orphaned active Entra user** μέχρι να αναγκαστεί manual **full sync**.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
