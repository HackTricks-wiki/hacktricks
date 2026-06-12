# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Τα Windows Service Triggers επιτρέπουν στο Service Control Manager (SCM) να ξεκινά/σταματά ένα service όταν συμβεί μια συνθήκη (π.χ. μια IP address γίνει διαθέσιμη, επιχειρείται σύνδεση σε named pipe, δημοσιεύεται ένα ETW event). Ακόμα κι αν δεν έχεις SERVICE_START rights σε ένα target service, μπορεί να καταφέρεις να το ξεκινήσεις προκαλώντας το trigger του να ενεργοποιηθεί.

Αυτή η σελίδα εστιάζει σε attacker-friendly enumeration και σε low-friction τρόπους ενεργοποίησης κοινών triggers.

> Tip: Η εκκίνηση ενός privileged built-in service (π.χ. RemoteRegistry, WebClient/WebDAV, EFS) μπορεί να εκθέσει νέα RPC/named-pipe listeners και να ξεκλειδώσει επιπλέον abuse chains.

## Enumerating Service Triggers

- sc.exe (local)
- Λίστα των triggers ενός service: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Τα triggers βρίσκονται κάτω από: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Αναδρομικό dump: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Κάλεσε QueryServiceConfig2 με SERVICE_CONFIG_TRIGGER_INFO (8) για να ανακτήσεις SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] και SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- Το SCM μπορεί να ερωτηθεί απομακρυσμένα για να επιστρέψει trigger info χρησιμοποιώντας MS‑SCMR. Το Titanis του TrustedSec το εκθέτει αυτό: `Scm.exe qtriggers`.
- Το Impacket ορίζει τις δομές στο msrpc MS-SCMR· μπορείς να υλοποιήσεις ένα remote query χρησιμοποιώντας τες.
- PowerShell (bulk enumeration)
- Γρήγορη λίστα όλων των services που εκθέτουν `TriggerInfo` key:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Το module `NtObjectManager` του James Forshaw εκθέτει το `Get-Win32ServiceTrigger` για parsing του trigger metadata χωρίς scraping του output του `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Αυτά ξεκινούν ένα service όταν ένας client προσπαθεί να μιλήσει σε ένα IPC endpoint. Χρήσιμα για low-priv users επειδή το SCM θα auto-start το service πριν ο client σου μπορέσει πραγματικά να συνδεθεί.

- Named pipe trigger
- Behavior: Μια προσπάθεια σύνδεσης client στο \\.\pipe\<PipeName> κάνει το SCM να ξεκινήσει το service ώστε να αρχίσει να ακούει.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: τα named-pipe triggers υποστηρίζονται από το `npsvctrig.sys`, ένα filesystem minifilter που παρακολουθεί opens προς registered trigger pipe names. Γι’ αυτό η προσπάθεια open μπορεί να ξεκινήσει το service ακόμα και πριν το ίδιο το service δημιουργήσει/listen στο pipe.
- See also: Named Pipe Client Impersonation για post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Η ερώτηση προς το Endpoint Mapper (EPM, TCP/135) για ένα interface UUID συσχετισμένο με ένα service κάνει το SCM να το ξεκινήσει ώστε να μπορέσει να δηλώσει το endpoint του.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Ένα service μπορεί να εγγράψει ένα trigger δεμένο σε ένα ETW provider/event. Αν δεν έχουν ρυθμιστεί επιπλέον filters (keyword/level/binary/string), οποιοδήποτε event από αυτόν τον provider θα ξεκινήσει το service.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Η αποστολή matching events συνήθως απαιτεί code που κάνει log προς αυτόν τον provider· αν δεν υπάρχουν filters, οποιοδήποτε event αρκεί.
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

Subtypes: Machine/User. Σε domain-joined hosts όπου υπάρχει η αντίστοιχη policy, το trigger εκτελείται στο boot. Το `gpupdate` μόνο του δεν θα το ενεργοποιήσει χωρίς αλλαγές, αλλά:

- Activation: `gpupdate /force`
- Αν υπάρχει ο σχετικός policy type, αυτό προκαλεί αξιόπιστα το trigger να ενεργοποιηθεί και να ξεκινήσει το service.

### IP Address Available

Ενεργοποιείται όταν αποκτηθεί η πρώτη IP (ή χαθεί η τελευταία). Συχνά ενεργοποιείται στο boot.

- Activation: Εναλλαγή connectivity για να ξαναενεργοποιηθεί, π.χ.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Ξεκινά ένα service όταν εμφανιστεί ένα matching device interface. Αν δεν έχει καθοριστεί data item, οποιοδήποτε device που ταιριάζει με το trigger subtype GUID θα ενεργοποιήσει το trigger. Αξιολογείται στο boot και κατά το hot-plug.

- Activation: Σύνδεσε/εισάγαγε μια συσκευή (physical ή virtual) που ταιριάζει με το class/hardware ID που καθορίζεται από το trigger subtype.

### Domain Join State

Παρά τη μπερδεμένη διατύπωση του MSDN, αυτό αξιολογεί το domain state στο boot:
- DOMAIN_JOIN_GUID → ξεκινά το service αν είναι domain-joined
- DOMAIN_LEAVE_GUID → ξεκινά το service μόνο αν ΔΕΝ είναι domain-joined

### System State Change – WNF (undocumented)

Κάποια services χρησιμοποιούν undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7). Η ενεργοποίηση απαιτεί publishing του σχετικού WNF state· οι λεπτομέρειες εξαρτώνται από το state name. Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Έχουν παρατηρηθεί στο Windows 11 για κάποια services (π.χ. CDPSvc). Η aggregated configuration αποθηκεύεται στο:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Το Trigger value ενός service είναι ένα GUID· το subkey με αυτό το GUID ορίζει το aggregated event. Η ενεργοποίηση οποιουδήποτε constituent event ξεκινά το service.

### Firewall Port Event (quirks and DoS risk)

Ένα trigger scoped σε συγκεκριμένο port/protocol έχει παρατηρηθεί να ενεργοποιείται με οποιαδήποτε firewall rule change (disable/delete/add), όχι μόνο στο καθορισμένο port. Ακόμα χειρότερα, η ρύθμιση ενός port χωρίς protocol μπορεί να αλλοιώσει το BFE startup across reboots, προκαλώντας αλυσιδωτές αποτυχίες πολλών services και σπάζοντας τη διαχείριση firewall. Χειρίσου το με εξαιρετική προσοχή.

## Practical Workflow

1) Enumerate triggers σε ενδιαφέροντα services (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Αν υπάρχει Network Endpoint trigger:
- Named pipe → προσπάθησε client open στο \\.\pipe\<PipeName>
- RPC endpoint → κάνε Endpoint Mapper lookup για το interface UUID

3) Αν υπάρχει ETW trigger:
- Έλεγξε provider και filters με `sc.exe qtriggerinfo`; αν δεν υπάρχουν filters, οποιοδήποτε event από αυτόν τον provider θα ξεκινήσει το service

4) Για Group Policy/IP/Device/Domain triggers:
- Χρησιμοποίησε environmental levers: `gpupdate /force`, toggle NICs, hot-plug devices, κ.λπ.

## Related

- Αφού ξεκινήσεις ένα privileged service μέσω Named Pipe trigger, ίσως μπορέσεις να το impersonate:

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

- Έλεγξε πρώτα το service start type με `sc.exe qc <Service>`. Αν είναι `DISABLED`, η ενεργοποίηση του trigger δεν αρκεί· πρέπει πρώτα να βρεις τρόπο να αλλάξεις τη configuration.
- Τα trigger-start services μπορεί να σταματήσουν ξανά αφού γίνουν idle. Αν η επόμενη ενέργειά σου εξαρτάται από short-lived listener (RPC/named pipe/WebDAV), ενεργοποίησέ το και κατανάλωσέ το αμέσως.
- Το `sc.exe qtriggerinfo` δεν καταλαβαίνει πλήρως κάθε undocumented trigger type. Για aggregate triggers σε νεότερα Windows builds, επιβεβαίωσε το backing GUID και τα constituent events στο `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Κάνε baseline και audit του TriggerInfo across services. Επίσης έλεγξε το HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents για aggregate triggers.
- Παρακολούθησε για suspicious EPM lookups σε privileged service UUIDs και για named-pipe connection attempts που προηγούνται από service starts.
- Περιόρισε ποιος μπορεί να τροποποιεί service triggers· θεώρησε ύποπτα τα απρόσμενα BFE failures μετά από trigger changes.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
