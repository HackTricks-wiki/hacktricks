# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers pozwalają Service Control Manager (SCM) na uruchomienie/zatrzymanie usługi, gdy wystąpi określony warunek (np. dostępność adresu IP, próba połączenia z named pipe, opublikowanie zdarzenia ETW). Nawet jeśli nie masz praw SERVICE_START do danej usługi, możesz być w stanie ją uruchomić, powodując zadziałanie jej triggera.

Ta strona koncentruje się na łatwych do wykonania przez atakującego metodach enumeracji i niskotarciowych sposobach aktywacji powszechnych triggerów.

> Tip: Uruchomienie uprzywilejowanej wbudowanej usługi (np. RemoteRegistry, WebClient/WebDAV, EFS) może ujawnić nowe nasłuchiwacze RPC/named-pipe i otworzyć dalsze łańcuchy nadużyć.

## Enumerating Service Triggers

- sc.exe (local)
- List a service's triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers live under: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursively: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Call QueryServiceConfig2 with SERVICE_CONFIG_TRIGGER_INFO (8) to retrieve SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- The SCM can be queried remotely to fetch trigger info using MS‑SCMR. TrustedSec’s Titanis exposes this: `Scm.exe qtriggers`.
- Impacket defines the structures in msrpc MS-SCMR; you can implement a remote query using those.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

These start a service when a client attempts to talk to an IPC endpoint. Useful to low-priv users because the SCM will auto-start the service before your client can actually connect.

- Named pipe trigger
- Behavior: A client connection attempt to \\.\pipe\<PipeName> causes the SCM to start the service so it can begin listening.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Querying the Endpoint Mapper (EPM, TCP/135) for an interface UUID associated with a service causes the SCM to start it so it can register its endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

A service can register a trigger bound to an ETW provider/event. If no additional filters (keyword/level/binary/string) are configured, any event from that provider will start the service.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitting matching events typically requires code that logs to that provider; if no filters are present, any event suffices.

### Group Policy Triggers

Subtypes: Machine/User. On domain-joined hosts where the corresponding policy exists, the trigger runs at boot. `gpupdate` alone won’t trigger without changes, but:

- Activation: `gpupdate /force`
- If the relevant policy type exists, this reliably causes the trigger to fire and start the service.

### IP Address Available

Fires when the first IP is obtained (or last is lost). Often triggers at boot.

- Activation: Toggle connectivity to retrigger, e.g.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Starts a service when a matching device interface arrives. If no data item is specified, any device matching the trigger subtype GUID will fire the trigger. Evaluated at boot and upon hot‑plug.

- Activation: Attach/insert a device (physical or virtual) that matches the class/hardware ID specified by the trigger subtype.

### Domain Join State

Despite confusing MSDN wording, this evaluates domain state at boot:
- DOMAIN_JOIN_GUID → start the service if domain-joined
- DOMAIN_LEAVE_GUID → start the service only if NOT domain-joined

### System State Change – WNF (undocumented)

Some services use undocumented WNF-based triggers (SERVICE_TRIGGER_TYPE 0x7). Activation requires publishing the relevant WNF state; specifics depend on the state name. Research background: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Observed on Windows 11 for some services (e.g., CDPSvc). The aggregated configuration is stored in:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

A service’s Trigger value is a GUID; the subkey with that GUID defines the aggregated event. Triggering any constituent event starts the service.

### Firewall Port Event (quirks and DoS risk)

A trigger scoped to a specific port/protocol has been observed to start on any firewall rule change (disable/delete/add), not just the specified port. Worse, configuring a port without a protocol can corrupt BFE startup across reboots, cascading into many service failures and breaking firewall management. Treat with extreme caution.

## Practical Workflow

1) Enumerate triggers on interesting services (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) If a Network Endpoint trigger exists:
- Named pipe → attempt a client open to \\.\pipe\<PipeName>
- RPC endpoint → perform an Endpoint Mapper lookup for the interface UUID

3) If an ETW trigger exists:
- Check provider and filters with `sc.exe qtriggerinfo`; if no filters, any event from that provider will start the service

4) For Group Policy/IP/Device/Domain triggers:
- Use environmental levers: `gpupdate /force`, toggle NICs, hot-plug devices, etc.

## Related

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Detection and Hardening Notes

- Baseline and audit TriggerInfo across services. Also review HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents for aggregate triggers.
- Monitor for suspicious EPM lookups for privileged service UUIDs and named-pipe connection attempts that precede service starts.
- Restrict who can modify service triggers; treat unexpected BFE failures after trigger changes as suspicious.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
