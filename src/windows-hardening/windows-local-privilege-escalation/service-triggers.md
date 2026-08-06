# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Les Windows Service Triggers permettent au Service Control Manager (SCM) de démarrer/arrêter un service lorsqu’une condition survient (par exemple, une adresse IP devient disponible, une connexion à un named pipe est tentée ou un événement ETW est publié). Même sans disposer des droits `SERVICE_START` sur un service cible, il peut être possible de le démarrer en provoquant le déclenchement de son trigger.<sup>[[1]](#references)</sup>

Cette page se concentre sur l’énumération utile à un attaquant et les moyens simples d’activer les triggers courants.

> Conseil : le démarrage d’un service intégré privilégié (par exemple, RemoteRegistry, WebClient/WebDAV, EFS) peut exposer de nouveaux listeners RPC/named pipe et permettre d’autres chaînes d’abus.

## Énumération des Service Triggers

- sc.exe (local)
- Lister les triggers d’un service : `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Les triggers se trouvent sous : `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Effectuer un dump récursif : `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Appeler QueryServiceConfig2 avec SERVICE_CONFIG_TRIGGER_INFO (8) pour récupérer SERVICE_TRIGGER_INFO.
- Documentation : QueryServiceConfig2[W/A] et SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC via MS-SCMR (remote)
- Le SCM peut être interrogé à distance pour récupérer les informations des triggers via MS-SCMR. Le Titanis de TrustedSec expose cette fonctionnalité : `Scm.exe qtriggers`.
- Impacket définit les structures dans msrpc MS-SCMR ; vous pouvez implémenter une requête remote à l’aide de celles-ci.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (énumération en masse)
- Lister rapidement chaque service exposant une clé `TriggerInfo` :
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatique)
- Le module `NtObjectManager` de James Forshaw expose `Get-Win32ServiceTrigger` pour analyser les métadonnées des triggers sans extraire la sortie de `sc.exe`.

## Types de Triggers à forte valeur et méthodes d’activation

### Network Endpoint Triggers

Ces triggers démarrent un service lorsqu’un client tente de communiquer avec un endpoint IPC. Ils sont utiles aux utilisateurs low-priv, car le SCM démarre automatiquement le service avant que le client puisse réellement se connecter.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Comportement : une tentative de connexion cliente à \\.\pipe\<PipeName> amène le SCM à démarrer le service afin qu’il commence à écouter.
- Activation (PowerShell) :
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Note interne : les named-pipe triggers reposent sur `npsvctrig.sys`, un filesystem minifilter qui surveille les ouvertures visant les noms de pipes enregistrés comme triggers. C’est pourquoi la tentative d’ouverture peut démarrer le service avant même que celui-ci ait créé ou commencé à écouter sur le pipe.<sup>[[5]](#references)</sup>
- Voir également : Named Pipe Client Impersonation pour l’abus post-démarrage.

- RPC endpoint trigger (Endpoint Mapper)
- Comportement : l’interrogation de l’Endpoint Mapper (EPM, TCP/135) pour un interface UUID associé à un service amène le SCM à démarrer celui-ci afin qu’il puisse enregistrer son endpoint.
- Activation (Impacket) :
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un service peut enregistrer un trigger lié à un provider/événement ETW. Si aucun filtre supplémentaire (keyword/level/binary/string) n’est configuré, tout événement provenant de ce provider démarrera le service.<sup>[[1]](#references)</sup>

- Exemple (WebClient/WebDAV) : provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Lister le trigger : `sc.exe qtriggerinfo webclient`
- Vérifier que le provider est enregistré : `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- L’émission d’événements correspondants nécessite généralement du code qui écrit dans ce provider ; en l’absence de filtres, n’importe quel événement suffit.
- Structure C minimale pour déclencher le provider (lorsqu’aucun filtre ETW supplémentaire n’est configuré) :
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Sous-types : Machine/User. Sur les hôtes joints à un domaine où la stratégie correspondante existe, le trigger s’exécute au démarrage. `gpupdate` seul ne déclenchera rien en l’absence de changements, mais :<sup>[[1]](#references)</sup>

- Activation : `gpupdate /force`
- Si le type de stratégie concerné existe, cela provoque de manière fiable le déclenchement du trigger et le démarrage du service.

### IP Address Available

Se déclenche lorsqu’une première IP est obtenue (ou lorsqu’une dernière IP est perdue). Se déclenche souvent au démarrage.<sup>[[1]](#references)</sup>

- Activation : basculer la connectivité pour provoquer un nouveau déclenchement, par exemple :
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Démarre un service lorsqu’une interface de périphérique correspondante apparaît. Si aucun élément de données n’est spécifié, tout périphérique correspondant au GUID du sous-type du trigger déclenchera celui-ci. L’évaluation a lieu au démarrage et lors d’un hot-plug.<sup>[[1]](#references)</sup>

- Activation : connecter/insérer un périphérique (physique ou virtuel) correspondant à la classe/l’identifiant matériel spécifié par le sous-type du trigger.

### Domain Join State

Malgré la formulation confuse de MSDN, ce trigger évalue l’état du domaine au démarrage :<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → démarrer le service si la machine est jointe à un domaine
- DOMAIN_LEAVE_GUID → démarrer le service uniquement si la machine n’est PAS jointe à un domaine

### System State Change – WNF (undocumented)

Certains services utilisent des triggers basés sur WNF non documentés (SERVICE_TRIGGER_TYPE 0x7). L’activation nécessite la publication de l’état WNF concerné ; les détails dépendent du nom de l’état. Contexte de recherche : Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Observés sur Windows 11 pour certains services (par exemple, CDPSvc). La configuration agrégée est stockée dans :

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

La valeur Trigger d’un service est un GUID ; la sous-clé portant ce GUID définit l’événement agrégé. Le déclenchement de n’importe quel événement constitutif démarre le service.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Un trigger limité à un port/protocole spécifique a été observé comme se déclenchant lors de toute modification d’une règle de firewall (désactivation/suppression/ajout), et pas uniquement pour le port spécifié. Plus grave encore, la configuration d’un port sans protocole peut corrompre le démarrage de BFE après les redémarrages, entraînant de nombreuses défaillances de services et empêchant la gestion du firewall. À utiliser avec une extrême prudence.<sup>[[1]](#references)</sup>

## Workflow pratique

1) Énumérer les triggers des services intéressants (RemoteRegistry, WebClient, EFS, …) :
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Si un Network Endpoint trigger existe :
- Named pipe → tenter une ouverture cliente vers \\.\pipe\<PipeName>
- RPC endpoint → effectuer une recherche dans l’Endpoint Mapper pour l’interface UUID

3) Si un ETW trigger existe :
- Vérifier le provider et les filtres avec `sc.exe qtriggerinfo` ; en l’absence de filtres, tout événement provenant de ce provider démarrera le service

4) Pour les triggers Group Policy/IP/Device/Domain :
- Utiliser les leviers environnementaux : `gpupdate /force`, basculer les NIC, connecter à chaud des périphériques, etc.

## Related

- Après avoir démarré un service privilégié via un Named Pipe trigger, il peut être possible de l’impersonate :

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Récapitulatif des commandes

- Lister les triggers (local) : `sc.exe qtriggerinfo <Service>`
- Vue Registry : `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API : `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis) : `Scm.exe qtriggers`
- Vérification du provider ETW (WebClient) : `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Pièges / Notes opérateur

- Vérifier d’abord le type de démarrage du service avec `sc.exe qc <Service>`. S’il est `DISABLED`, le déclenchement du trigger ne suffit pas ; il faut d’abord trouver un moyen de modifier la configuration.
- Les services démarrés par trigger peuvent s’arrêter à nouveau après être devenus inactifs. Si l’action suivante dépend d’un listener de courte durée (RPC/named pipe/WebDAV), déclencher le service et l’utiliser immédiatement.
- `sc.exe qtriggerinfo` ne comprend pas entièrement tous les types de triggers non documentés. Pour les aggregate triggers des versions récentes de Windows, confirmer le GUID sous-jacent et les événements constitutifs dans `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Notes de détection et de hardening

- Établir une baseline et auditer les TriggerInfo de tous les services. Examiner également `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` pour les aggregate triggers.
- Surveiller les recherches EPM suspectes visant les UUID de services privilégiés ainsi que les tentatives de connexion à des named pipes précédant le démarrage de services.
- Restreindre les personnes autorisées à modifier les service triggers ; considérer comme suspectes les défaillances inattendues de BFE après des modifications de triggers.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
