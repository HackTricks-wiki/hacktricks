# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Les Windows Service Triggers permettent au Service Control Manager (SCM) de démarrer/arrêter un service lorsqu’une condition se produit (par ex. une adresse IP devient disponible, une connexion à un named pipe est tentée, un événement ETW est publié). Même sans droits SERVICE_START sur un service cible, il peut être possible de le démarrer en provoquant le déclenchement de son trigger.

Cette page se concentre sur l’énumération orientée attaquant et sur des moyens peu contraignants d’activer les triggers courants.

> Astuce : démarrer un service intégré privilégié (par ex. RemoteRegistry, WebClient/WebDAV, EFS) peut exposer de nouveaux listeners RPC/named-pipe et ouvrir d’autres chaînes d’abus.

## Enumerating Service Triggers

- sc.exe (local)
- List a service's triggers: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Les triggers se trouvent sous : `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump récursif : `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Appeler QueryServiceConfig2 avec SERVICE_CONFIG_TRIGGER_INFO (8) pour récupérer SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] et SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- Le SCM peut être interrogé à distance pour récupérer les trigger info via MS‑SCMR. Titanis de TrustedSec expose cela : `Scm.exe qtriggers`.
- Impacket définit les structures dans msrpc MS-SCMR ; vous pouvez implémenter une requête distante avec celles-ci.
- PowerShell (bulk enumeration)
- Liste rapidement chaque service exposant une clé `TriggerInfo` :
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- Le module `NtObjectManager` de James Forshaw expose `Get-Win32ServiceTrigger` pour analyser les métadonnées des triggers sans parser la sortie de `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Ceux-ci démarrent un service lorsqu’un client tente de communiquer avec un point de terminaison IPC. Utile pour les utilisateurs à faible privilège, car le SCM lancera automatiquement le service avant que votre client ne puisse réellement se connecter.

- Named pipe trigger
- Behavior: Une tentative de connexion client à \\.\pipe\<PipeName> provoque le démarrage du service par le SCM afin qu’il commence à écouter.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: les named-pipe triggers sont pris en charge par `npsvctrig.sys`, un minifilter du système de fichiers qui surveille les ouvertures sur les noms de pipe enregistrés comme trigger. C’est pourquoi la tentative d’ouverture peut démarrer le service avant même que le service ait créé/écouté sur le pipe.
- See also: Named Pipe Client Impersonation pour un abus après démarrage.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Interroger l’Endpoint Mapper (EPM, TCP/135) pour un interface UUID associé à un service provoque le démarrage du service afin qu’il puisse enregistrer son endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un service peut enregistrer un trigger lié à un provider/event ETW. Si aucun filtre supplémentaire (keyword/level/binary/string) n’est configuré, n’importe quel événement provenant de ce provider démarrera le service.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitting matching events requires usually code that logs to that provider ; si aucun filtre n’est présent, n’importe quel événement suffit.
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

Subtypes: Machine/User. Sur les hôtes joints à un domaine où la policy correspondante existe, le trigger s’exécute au boot. `gpupdate` seul ne le déclenchera pas sans changements, mais :

- Activation: `gpupdate /force`
- Si le type de policy pertinent existe, cela provoque de manière fiable le déclenchement du trigger et le démarrage du service.

### IP Address Available

Se déclenche lorsque la première IP est obtenue (ou lorsque la dernière est perdue). Souvent au boot.

- Activation: basculer la connectivité pour redéclencher, par ex. :
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Démarre un service lorsqu’une interface de périphérique correspondante arrive. Si aucun élément de données n’est spécifié, tout périphérique correspondant au GUID du sous-type du trigger déclenchera l’événement. Évalué au boot et lors d’un hot-plug.

- Activation: connecter/insérer un périphérique (physique ou virtuel) correspondant au class/hardware ID spécifié par le sous-type du trigger.

### Domain Join State

Malgré un wording MSDN déroutant, cela évalue l’état du domaine au boot :
- DOMAIN_JOIN_GUID → démarre le service si l’hôte est joint à un domaine
- DOMAIN_LEAVE_GUID → démarre le service uniquement si l’hôte n’est PAS joint à un domaine

### System State Change – WNF (undocumented)

Certains services utilisent des triggers WNF non documentés (SERVICE_TRIGGER_TYPE 0x7). L’activation nécessite de publier l’état WNF pertinent ; les détails dépendent du state name. Contexte de recherche : Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Observés sur Windows 11 pour certains services (par ex. CDPSvc). La configuration agrégée est stockée dans :

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

La valeur Trigger d’un service est un GUID ; la sous-clé portant ce GUID définit l’événement agrégé. Déclencher n’importe quel événement constitutif démarre le service.

### Firewall Port Event (quirks and DoS risk)

Un trigger limité à un port/protocol spécifique a été observé comme se déclenchant sur n’importe quel changement de règle firewall (disable/delete/add), et pas seulement sur le port spécifié. Pire, configurer un port sans protocole peut corrompre le démarrage de BFE à travers les redémarrages, entraînant une cascade d’échecs de nombreux services et cassant la gestion du firewall. À traiter avec une extrême prudence.

## Practical Workflow

1) Énumérez les triggers sur les services intéressants (RemoteRegistry, WebClient, EFS, …) :
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Si un Network Endpoint trigger existe :
- Named pipe → tentez une ouverture client vers \\.\pipe\<PipeName>
- RPC endpoint → effectuez une recherche Endpoint Mapper pour l’interface UUID

3) Si un trigger ETW existe :
- Vérifiez le provider et les filtres avec `sc.exe qtriggerinfo`; si aucun filtre n’existe, n’importe quel événement de ce provider démarrera le service

4) Pour les triggers Group Policy/IP/Device/Domain :
- Utilisez des leviers environnementaux : `gpupdate /force`, bascule des NIC, hot-plug de périphériques, etc.

## Related

- Après avoir démarré un service privilégié via un Named Pipe trigger, vous pouvez éventuellement l’impersonate :

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

- Vérifiez d’abord le start type du service avec `sc.exe qc <Service>`. S’il est `DISABLED`, déclencher le trigger ne suffit pas ; il faut d’abord trouver un moyen de modifier la configuration.
- Les services démarrés par trigger peuvent s’arrêter à nouveau une fois inactifs. Si votre action suivante dépend d’un listener de courte durée (RPC/named pipe/WebDAV), déclenchez-le et consommez-le immédiatement.
- `sc.exe qtriggerinfo` ne comprend pas complètement tous les types de trigger non documentés. Pour les triggers agrégés sur les versions récentes de Windows, confirmez le GUID de support et les événements constitutifs dans `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Établissez une baseline et auditez TriggerInfo sur les services. Examinez aussi HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents pour les triggers agrégés.
- Surveillez les recherches EPM suspectes pour des UUID de services privilégiés et les tentatives de connexion à des named pipes qui précèdent des démarrages de services.
- Restreignez qui peut modifier les triggers de service ; traitez comme suspectes les pannes BFE inattendues après des changements de trigger.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
