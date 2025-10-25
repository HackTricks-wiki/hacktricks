# Windows Service Triggers: Ανίχνευση και Κατάχρηση

{{#include ../../banners/hacktricks-training.md}}

Τα Windows Service Triggers επιτρέπουν στον Service Control Manager (SCM) να ξεκινήσει/σταματήσει μια υπηρεσία όταν προκύψει μια συνθήκη (π.χ., γίνει διαθέσιμη μια διεύθυνση IP, επιχειρηθεί σύνδεση σε named pipe, δημοσιευτεί ένα ETW event). Ακόμα κι αν δεν έχετε δικαιώματα SERVICE_START σε μια στοχευόμενη υπηρεσία, ίσως μπορείτε να την ξεκινήσετε προκαλώντας το trigger της να ενεργοποιηθεί.

Αυτή η σελίδα επικεντρώνεται στην φιλική προς τον επιτιθέμενο ανίχνευση και σε μεθόδους με χαμηλό friction για να ενεργοποιήσετε κοινά triggers.

> Συμβουλή: Η εκκίνηση μιας privileged built-in υπηρεσίας (π.χ., RemoteRegistry, WebClient/WebDAV, EFS) μπορεί να εκθέσει νέους RPC/named-pipe listeners και να ξεκλειδώσει περαιτέρω αλυσίδες κατάχρησης.

## Ανίχνευση Service Triggers

- sc.exe (τοπικά)
- Λίστα triggers μιας υπηρεσίας: `sc.exe qtriggerinfo <ServiceName>`
- Registry (τοπικά)
- Τα triggers βρίσκονται κάτω από: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump αναδρομικά: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (τοπικά)
- Κλήση QueryServiceConfig2 με SERVICE_CONFIG_TRIGGER_INFO (8) για ανάκτηση SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (απομακρυσμένα)
- Ο SCM μπορεί να ερωτηθεί απομακρυσμένα για να ανακτήσει info triggers χρησιμοποιώντας MS‑SCMR. Το Titanis της TrustedSec το εκθέτει: `Scm.exe qtriggers`.
- Impacket ορίζει τις δομές στο msrpc MS-SCMR· μπορείτε να υλοποιήσετε απομακρυσμένο query χρησιμοποιώντας αυτές.

## Τύποι Triggers Υψηλής Αξίας και Πώς να τους Ενεργοποιήσετε

### Network Endpoint Triggers

Αυτά ξεκινούν μια υπηρεσία όταν ένας client επιχειρεί να μιλήσει σε ένα IPC endpoint. Χρήσιμο για low-priv users γιατί ο SCM θα auto-start την υπηρεσία πριν ο client σας καταφέρει πραγματικά να συνδεθεί.

- Named pipe trigger
- Συμπεριφορά: Μια προσπάθεια σύνδεσης client στο \\.\pipe\<PipeName> προκαλεί τον SCM να ξεκινήσει την υπηρεσία ώστε να αρχίσει να ακούει.
- Ενεργοποίηση (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Δείτε επίσης: Named Pipe Client Impersonation για κατάχρηση μετά την εκκίνηση.

- RPC endpoint trigger (Endpoint Mapper)
- Συμπεριφορά: Η ερώτηση στον Endpoint Mapper (EPM, TCP/135) για ένα interface UUID συνδεδεμένο με μια υπηρεσία προκαλεί τον SCM να την ξεκινήσει ώστε να καταχωρήσει το endpoint της.
- Ενεργοποίηση (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Μια υπηρεσία μπορεί να εγγράψει trigger δεσμευμένο σε έναν ETW provider/event. Αν δεν υπάρχουν επιπλέον φίλτρα (keyword/level/binary/string), οποιοδήποτε event από αυτόν τον provider θα ξεκινήσει την υπηρεσία.

- Παράδειγμα (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Εμφάνιση trigger: `sc.exe qtriggerinfo webclient`
- Επαλήθευση ότι ο provider είναι εγγεγραμμένος: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Η εκπομπή ταιριαστών events συνήθως απαιτεί κώδικα που κάνει logging στον provider· αν δεν υπάρχουν φίλτρα, οποιοδήποτε event αρκεί.

### Group Policy Triggers

Υποτύποι: Machine/User. Σε domain-joined hosts όπου υπάρχει η αντίστοιχη πολιτική, το trigger τρέχει στο boot. Το `gpupdate` από μόνο του δεν θα προκαλέσει trigger χωρίς αλλαγές, αλλά:

- Ενεργοποίηση: `gpupdate /force`
- Αν υπάρχει ο σχετικός τύπος policy, αυτό προκαλεί αξιόπιστα το trigger να πυροδοτήσει και να ξεκινήσει την υπηρεσία.

### IP Address Available

Εκτοξεύεται όταν αποκτηθεί η πρώτη IP (ή χαθεί η τελευταία). Συχνά ενεργοποιείται κατά το boot.

- Ενεργοποίηση: Απενεργοποιήστε/ενεργοποιήστε τη συνδεσιμότητα για re-trigger, π.χ.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Ξεκινά μια υπηρεσία όταν φτάσει μια συμβατή device interface. Αν δεν έχει καθοριστεί data item, οποιαδήποτε συσκευή που ταιριάζει στο trigger subtype GUID θα πυροδοτήσει το trigger. Αξιολογείται στο boot και κατά το hot‑plug.

- Ενεργοποίηση: Συνδέστε/εισάγετε μια συσκευή (φυσική ή virtual) που ταιριάζει στην κλάση/hardware ID που καθορίζεται από το trigger subtype.

### Domain Join State

Παρά τη συγκεχυμένη διατύπωση στο MSDN, αυτό αξιολογεί την κατάσταση domain στο boot:
- DOMAIN_JOIN_GUID → ξεκινά την υπηρεσία αν είναι domain-joined
- DOMAIN_LEAVE_GUID → ξεκινά την υπηρεσία μόνο αν ΔΕΝ είναι domain-joined

### System State Change – WNF (μη τεκμηριωμένο)

Κάποιες υπηρεσίες χρησιμοποιούν undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7). Η ενεργοποίηση απαιτεί τη δημοσίευση της σχετικής WNF state· οι λεπτομέρειες εξαρτώνται από το state name. Ιστορικό έρευνας: Windows Notification Facility internals.

### Aggregate Service Triggers (μη τεκμηριωμένο)

Παρατηρήθηκε στα Windows 11 για κάποιες υπηρεσίες (π.χ., CDPSvc). Η συγκεντρωτική διαμόρφωση αποθηκεύεται σε:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Η τιμή Trigger μιας υπηρεσίας είναι ένας GUID· το υποκλειδί με αυτόν τον GUID ορίζει το aggregated event. Η ενεργοποίηση οποιουδήποτε συστατικού event ξεκινά την υπηρεσία.

### Firewall Port Event (ιδιορρυθμίες και κίνδυνος DoS)

Ένα trigger περιορισμένο σε συγκεκριμένη θύρα/protocol έχει παρατηρηθεί να ξεκινά με οποιαδήποτε αλλαγή κανόνα firewall (disable/delete/add), όχι μόνο με την καθορισμένη θύρα. Χειρότερα, η ρύθμιση μιας θύρας χωρίς protocol μπορεί να καταστρέψει το BFE startup σε επανεκκινήσεις, προκαλώντας καταρρεύσεις πολλών υπηρεσιών και διατάραξη της διαχείρισης firewall. Χρησιμοποιήστε με ακραία προσοχή.

## Πρακτική Ροή Εργασίας

1) Ανιχνεύστε triggers σε ενδιαφέρουσες υπηρεσίες (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Αν υπάρχει Network Endpoint trigger:
- Named pipe → προσπαθήστε να ανοίξετε client σε \\.\pipe\<PipeName>
- RPC endpoint → εκτελέστε Endpoint Mapper lookup για το interface UUID

3) Αν υπάρχει ETW trigger:
- Ελέγξτε provider και φίλτρα με `sc.exe qtriggerinfo`; αν δεν υπάρχουν φίλτρα, οποιοδήποτε event από αυτόν τον provider θα ξεκινήσει την υπηρεσία

4) Για Group Policy/IP/Device/Domain triggers:
- Χρησιμοποιήστε περιβαλλοντικούς μοχλούς: `gpupdate /force`, toggle NICs, hot‑plug συσκευές, κ.λπ.

## Σχετικό

- Μετά την εκκίνηση μιας privileged υπηρεσίας μέσω Named Pipe trigger, ίσως μπορείτε να την impersonate:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Σύντομη επανάληψη εντολών

- Λίστα triggers (τοπικά): `sc.exe qtriggerinfo <Service>`
- Εμφάνιση registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC απομακρυσμένα (Titanis): `Scm.exe qtriggers`
- Έλεγχος ETW provider (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Σημειώσεις Ανίχνευσης και Σκληραγώγησης

- Δημιουργήστε baseline και audit του TriggerInfo ανά υπηρεσία. Επίσης ελέγξτε HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents για aggregate triggers.
- Παρακολουθείτε για ύποπτες EPM αναζητήσεις για privileged service UUIDs και προσπάθειες σύνδεσης σε named-pipe που προηγούνται της εκκίνησης υπηρεσιών.
- Περιορίστε ποιος μπορεί να τροποποιεί service triggers· αντιμετωπίστε ως ύποπτο οποιοδήποτε απροσδόκητο BFE failure μετά από αλλαγές triggers.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
