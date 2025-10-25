# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers zinamruhusu Service Control Manager (SCM) kuanza/kuacha service wakati hali fulani inapotokea (kwa mfano, anuani ya IP inapatikana, jaribio la kuunganishwa kwa named pipe, au tukio la ETW linachapishwa). Hata ukikosa haki za SERVICE_START kwenye service lengwa, bado unaweza kuwa na uwezo wa kuienzisha kwa kusababisha trigger yake ianze.

Ukurasa huu unazingatia namna za kirahisi kwa mshambuliaji za kuorodhesha na njia zenye usumbufu mdogo za kuzindua triggers za kawaida.

> Kidokezo: Kuanzisha service ya builtin yenye hadhi za juu (mfano RemoteRegistry, WebClient/WebDAV, EFS) kunaweza kufunua wasikilizaji wapya wa RPC/named-pipe na kufungua mnyororo wa mbinu za matumizi zaidi.

## Kuorodhesha Service Triggers

- sc.exe (local)
- Orodha ya triggers za service: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers zinapatikana chini ya: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursively: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Piga QueryServiceConfig2 na SERVICE_CONFIG_TRIGGER_INFO (8) ili kupata SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM inaweza kuhojiwa kwa mbali ili kupata taarifa za trigger kwa kutumia MS‑SCMR. TrustedSec’s Titanis inaonyesha hili: `Scm.exe qtriggers`.
- Impacket inaelezea miundo katika msrpc MS-SCMR; unaweza kutekeleza uhojiwa wa mbali ukitumia hizo.

## Aina za Trigger zenye Thamani na Jinsi ya Kuzizindua

### Network Endpoint Triggers

Hizi huanza service wakati mteja anapo jaribu kuzungumza na IPC endpoint. Zinasaidia watumiaji wa haki ndogo kwa sababu SCM itaanzisha service kabla mteja wako hata kuweza kuunganisha.

- Named pipe trigger
- Tabia: Jaribio la mteja kuunganisha kwenye \\.\pipe\<PipeName> husababisha SCM kuanzisha service ili iweze kuanza kusikiliza.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Tabia: Kuhoji Endpoint Mapper (EPM, TCP/135) kwa interface UUID inayohusishwa na service husababisha SCM kuianzisha ili iweze kujisajili endpoint yake.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Service inaweza kusajili trigger iliyofungwa kwa mtangazaji/tukio la ETW. Ikiwa hakuna vichujio vya ziada (keyword/level/binary/string) vilivyowekwa, tukio lolote kutoka kwa mtangazaji huyo litaanza service.

- Mfano (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Orodha ya trigger: `sc.exe qtriggerinfo webclient`
- Thibitisha provider imeandikishwa: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Kutolewa kwa matukio yanayolingana kwa kawaida kunahitaji msimbo unaoandika kwa provider huyo; ikiwa hakuna vichujio, tukio lolote litatosha.

### Group Policy Triggers

Subtypes: Machine/User. Kwenye mashine zilizojiunga na domain ambapo policy inayofanana ipo, trigger inateketea wakati wa boot. `gpupdate` peke yake haitasababisha kuzinduka bila mabadiliko, lakini:

- Activation: `gpupdate /force`
- Ikiwa aina husika ya policy ipo, hii kwa kuaminika itasababisha trigger izinduke na kuanza service.

### IP Address Available

Huiwasha wakati IP ya kwanza inapopatikana (au mwisho unapopotea). Mara nyingi huanzishwa wakati wa boot.

- Activation: Zima/wasilisha upya muunganisho ili kuanzisha tena, kwa mfano:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Huanzisha service wakati interface ya kifaa inayofanana inapoingia. Ikiwa hakuna data item iliyotajwa, kifaa chochote kinachofanana na trigger subtype GUID kitasababisha trigger. Inachunguzwa wakati wa boot na wakati wa hot‑plug.

- Activation: Unganisha/weke kifaa (physical au virtual) kinachofanana na class/hardware ID iliyotajwa na trigger subtype.

### Domain Join State

Licha ya maneno ya MSDN yenye mkanganyiko, hii inathamini hali ya domain wakati wa boot:
- DOMAIN_JOIN_GUID → anzisha service ikiwa imejiunga na domain
- DOMAIN_LEAVE_GUID → anzisha service tu ikiwa HAJAJIUNGA NA DOMAIN

### System State Change – WNF (undocumented)

Baadhi ya services zinatumia triggers za WNF zisizoandikwa (SERVICE_TRIGGER_TYPE 0x7). Kuzindua kunahitaji kuchapisha state ya WNF husika; maelezo maalum yanategemea jina la state. Utafiti wa msingi: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Imeonekana kwenye Windows 11 kwa baadhi ya services (mfano, CDPSvc). Mipangilio iliyokusanywa imehifadhiwa katika:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Thamani ya Trigger ya service ni GUID; subkey yenye GUID hiyo inaelezea tukio lililokusanywa. Kuzindua tukio lolote la sehemu husababisha service kuanza.

### Firewall Port Event (quirks and DoS risk)

Trigger iliyopangwa kwa bandari/protocol maalum imeonekana kuanzishwa kwa mabadiliko yoyote ya rule za firewall (disable/delete/add), si tu bandari iliyotajwa. Mbaya zaidi, kusanidi bandari bila protocol kunaweza kuharibu startup ya BFE kati ya reboots, ikasababisha kushindwa kwa services nyingi na kuvunja usimamizi wa firewall. Tumia kwa tahadhari kubwa.

## Practical Workflow

1) Orodhesha triggers kwenye services zinazoonekana (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Ikiwa kuna Network Endpoint trigger:
- Named pipe → jaribu ufunguo wa mteja kwa \\.\pipe\<PipeName>
- RPC endpoint → fanya Endpoint Mapper lookup kwa interface UUID

3) Ikiwa kuna ETW trigger:
- Angalia provider na vichujio na `sc.exe qtriggerinfo`; ikiwa hakuna vichujio, tukio lolote kutoka kwa provider huo litaanza service

4) Kwa Group Policy/IP/Device/Domain triggers:
- Tumia vinguzo vya mazingira: `gpupdate /force`, zima/anzisha NICs, weka vifaa kwa haraka, n.k.

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

- Tengeneza baseline na audit ya TriggerInfo katika services. Pia hakiki `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` kwa aggregate triggers.
- Sikiliza kwa upelelezi kwa uhojiaji wa EPM usio wa kawaida kwa UUIDs za services zenye hadhi na jaribio za kuunganishwa kwa named-pipe ambazo zinafuata kuanzishwa kwa service.
- Punguza nani anayeweza kubadilisha service triggers; chukulia kushindwa kwa BFE baada ya mabadiliko ya trigger kama jambo lenye shaka.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
