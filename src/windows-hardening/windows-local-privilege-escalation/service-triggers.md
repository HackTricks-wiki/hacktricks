# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Τα Windows Service Triggers επιτρέπουν στο Service Control Manager (SCM) να εκκινεί/διακόπτει μια υπηρεσία όταν προκύπτει μια συνθήκη (π.χ. όταν γίνει διαθέσιμη μια διεύθυνση IP, επιχειρηθεί σύνδεση σε named pipe ή δημοσιευτεί ένα ETW event). Ακόμη και όταν δεν έχετε δικαιώματα SERVICE_START σε μια υπηρεσία-στόχο, ενδέχεται να μπορείτε να την εκκινήσετε προκαλώντας την ενεργοποίηση του trigger της.<sup>[[1]](#references)</sup>

Αυτή η σελίδα επικεντρώνεται σε enumeration φιλικό προς τον attacker και σε εύκολους τρόπους ενεργοποίησης συνηθισμένων triggers.

> Tip: Η εκκίνηση μιας προνομιούχας built-in υπηρεσίας (π.χ. RemoteRegistry, WebClient/WebDAV, EFS) μπορεί να εκθέσει νέους RPC/named-pipe listeners και να ξεκλειδώσει περαιτέρω abuse chains.

## Enumerating Service Triggers

- sc.exe (local)
- List a service's triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Τα triggers βρίσκονται στο: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursively: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Καλέστε το QueryServiceConfig2 με SERVICE_CONFIG_TRIGGER_INFO (8) για να ανακτήσετε το SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC over MS-SCMR (remote)
- Το SCM μπορεί να υποβληθεί σε remote query για την ανάκτηση trigger info μέσω MS-SCMR. Το TrustedSec’s Titanis το εκθέτει: `Scm.exe qtriggers`.
- Το Impacket ορίζει τις structures στο msrpc MS-SCMR· μπορείτε να υλοποιήσετε remote query χρησιμοποιώντας τες.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- Γρήγορη καταχώριση κάθε υπηρεσίας που εκθέτει ένα `TriggerInfo` key:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Το module `NtObjectManager` του James Forshaw εκθέτει το `Get-Win32ServiceTrigger` για parsing των trigger metadata χωρίς scraping της εξόδου του `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Αυτά εκκινούν μια υπηρεσία όταν ένας client επιχειρεί να επικοινωνήσει με ένα IPC endpoint. Είναι χρήσιμα για low-priv users, επειδή το SCM θα κάνει auto-start την υπηρεσία πριν ο client σας μπορέσει πραγματικά να συνδεθεί.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Behavior: Μια προσπάθεια σύνδεσης client στο \\.\pipe\<PipeName> προκαλεί το SCM να εκκινήσει την υπηρεσία, ώστε να αρχίσει να ακούει.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: Τα named-pipe triggers υποστηρίζονται από το `npsvctrig.sys`, ένα filesystem minifilter που παρακολουθεί opens σε καταχωρισμένα trigger pipe names. Γι’ αυτό η προσπάθεια open μπορεί να εκκινήσει την υπηρεσία ακόμη και πριν η ίδια η υπηρεσία δημιουργήσει ή αρχίσει να ακούει στο pipe.<sup>[[5]](#references)</sup>
- See also: Named Pipe Client Impersonation για post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Η αναζήτηση στο Endpoint Mapper (EPM, TCP/135) για ένα interface UUID που σχετίζεται με μια υπηρεσία προκαλεί το SCM να την εκκινήσει, ώστε να καταχωρίσει το endpoint της.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Μια υπηρεσία μπορεί να καταχωρίσει ένα trigger συνδεδεμένο με έναν ETW provider/event. Αν δεν έχουν ρυθμιστεί πρόσθετα filters (keyword/level/binary/string), οποιοδήποτε event από αυτόν τον provider θα εκκινήσει την υπηρεσία.<sup>[[1]](#references)</sup>

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Η εκπομπή matching events συνήθως απαιτεί κώδικα που κάνει logging σε αυτόν τον provider· αν δεν υπάρχουν filters, αρκεί οποιοδήποτε event.
- Minimal C shape for firing the provider (when no additional ETW filters are configured):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Σε domain-joined hosts όπου υπάρχει η αντίστοιχη policy, το trigger εκτελείται κατά το boot. Το `gpupdate` από μόνο του δεν θα το ενεργοποιήσει χωρίς αλλαγές, αλλά:<sup>[[1]](#references)</sup>

- Activation: `gpupdate /force`
- Αν υπάρχει ο σχετικός τύπος policy, αυτό προκαλεί αξιόπιστα την ενεργοποίηση του trigger και την εκκίνηση της υπηρεσίας.

### IP Address Available

Ενεργοποιείται όταν αποκτηθεί η πρώτη IP (ή χαθεί η τελευταία). Συχνά ενεργοποιείται κατά το boot.<sup>[[1]](#references)</sup>

- Activation: Κάντε toggle τη συνδεσιμότητα για να το ενεργοποιήσετε ξανά, π.χ.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Εκκινεί μια υπηρεσία όταν εμφανιστεί ένα matching device interface. Αν δεν έχει καθοριστεί data item, οποιαδήποτε συσκευή που αντιστοιχεί στο trigger subtype GUID θα ενεργοποιήσει το trigger. Αξιολογείται κατά το boot και κατά το hot-plug.<sup>[[1]](#references)</sup>

- Activation: Συνδέστε/εισάγετε μια συσκευή (physical ή virtual) που αντιστοιχεί στο class/hardware ID που καθορίζεται από το trigger subtype.

### Domain Join State

Παρά τη συγκεχυμένη διατύπωση του MSDN, αυτό αξιολογεί την κατάσταση domain κατά το boot:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → εκκίνηση της υπηρεσίας αν το σύστημα είναι domain-joined
- DOMAIN_LEAVE_GUID → εκκίνηση της υπηρεσίας μόνο αν το σύστημα ΔΕΝ είναι domain-joined

### System State Change – WNF (undocumented)

Ορισμένες υπηρεσίες χρησιμοποιούν undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7). Η ενεργοποίηση απαιτεί τη δημοσίευση του σχετικού WNF state· οι λεπτομέρειες εξαρτώνται από το state name. Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Έχουν παρατηρηθεί στα Windows 11 για ορισμένες υπηρεσίες (π.χ. CDPSvc). Η aggregated configuration αποθηκεύεται στο:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Η τιμή Trigger μιας υπηρεσίας είναι ένα GUID· το subkey με αυτό το GUID ορίζει το aggregated event. Η ενεργοποίηση οποιουδήποτε constituent event εκκινεί την υπηρεσία.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Έχει παρατηρηθεί ότι ένα trigger που περιορίζεται σε συγκεκριμένο port/protocol ενεργοποιείται με οποιαδήποτε αλλαγή firewall rule (disable/delete/add), όχι μόνο για το καθορισμένο port. Ακόμη χειρότερα, η ρύθμιση port χωρίς protocol μπορεί να καταστρέψει το BFE startup σε διαδοχικά reboots, προκαλώντας cascading failures σε πολλές υπηρεσίες και διακόπτοντας τη διαχείριση του firewall. Χρησιμοποιήστε το με εξαιρετική προσοχή.<sup>[[1]](#references)</sup>

## Practical Workflow

1) Enumerate triggers σε ενδιαφέρουσες υπηρεσίες (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Αν υπάρχει Network Endpoint trigger:
- Named pipe → επιχειρήστε client open στο \\.\pipe\<PipeName>
- RPC endpoint → εκτελέστε Endpoint Mapper lookup για το interface UUID

3) Αν υπάρχει ETW trigger:
- Ελέγξτε τον provider και τα filters με `sc.exe qtriggerinfo`· αν δεν υπάρχουν filters, οποιοδήποτε event από αυτόν τον provider θα εκκινήσει την υπηρεσία

4) Για Group Policy/IP/Device/Domain triggers:
- Χρησιμοποιήστε environmental levers: `gpupdate /force`, κάντε toggle τα NICs, συνδέστε συσκευές μέσω hot-plug κ.λπ.

## Related

- Μετά την εκκίνηση μιας προνομιούχας υπηρεσίας μέσω Named Pipe trigger, ενδέχεται να μπορείτε να την κάνετε impersonate:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Ελέγξτε πρώτα τον start type της υπηρεσίας με `sc.exe qc <Service>`. Αν είναι `DISABLED`, η ενεργοποίηση του trigger δεν αρκεί· πρέπει πρώτα να βρείτε τρόπο να αλλάξετε τη configuration.
- Οι trigger-start υπηρεσίες μπορεί να σταματήσουν ξανά αφού μείνουν idle. Αν το follow-on action σας εξαρτάται από έναν short-lived listener (RPC/named pipe/WebDAV), ενεργοποιήστε το trigger και καταναλώστε το αμέσως.
- Το `sc.exe qtriggerinfo` δεν κατανοεί πλήρως κάθε undocumented trigger type. Για aggregate triggers σε νεότερα Windows builds, επιβεβαιώστε το backing GUID και τα constituent events στο `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Δημιουργήστε baseline και κάντε audit στο TriggerInfo όλων των υπηρεσιών. Ελέγξτε επίσης το HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents για aggregate triggers.
- Παρακολουθείτε ύποπτα EPM lookups για privileged service UUIDs και προσπάθειες σύνδεσης σε named pipes που προηγούνται της εκκίνησης υπηρεσιών.
- Περιορίστε ποιοι μπορούν να τροποποιούν service triggers· αντιμετωπίστε μη αναμενόμενα BFE failures μετά από αλλαγές σε triggers ως ύποπτα.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
