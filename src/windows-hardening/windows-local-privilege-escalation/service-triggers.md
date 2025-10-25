# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers permettent au Service Control Manager (SCM) de démarrer/arrêter un service lorsqu'une condition se produit (par ex., une adresse IP devient disponible, une connexion à un named pipe est tentée, un événement ETW est publié). Même si vous n'avez pas les droits SERVICE_START sur un service cible, vous pouvez parfois le démarrer en provoquant le déclenchement de son trigger.

Cette page se concentre sur l'énumération pratique orientée attaquant et les moyens peu contraignants d'activer des triggers courants.

> Astuce : Démarrer un service intégré privilégié (par ex., RemoteRegistry, WebClient/WebDAV, EFS) peut exposer de nouveaux listeners RPC/named-pipe et débloquer d'autres chaînes d'abus.

## Enumerating Service Triggers

- sc.exe (local)
- Lister les triggers d'un service : `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Les triggers se trouvent sous : `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump récursif : `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Appeler QueryServiceConfig2 avec SERVICE_CONFIG_TRIGGER_INFO (8) pour récupérer SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- Le SCM peut être interrogé à distance pour récupérer les infos de trigger en utilisant MS‑SCMR. Titanis de TrustedSec expose ceci : `Scm.exe qtriggers`.
- Impacket définit les structures dans msrpc MS-SCMR ; vous pouvez implémenter une requête distante en utilisant celles-ci.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Ceux-ci démarrent un service lorsqu'un client tente de parler à un endpoint IPC. Utile pour des utilisateurs à faibles privilèges car le SCM démarrera automatiquement le service avant que votre client puisse réellement se connecter.

- Named pipe trigger
- Comportement : Une tentative de connexion client à \\.\pipe\<PipeName> provoque le démarrage du service par le SCM afin qu'il puisse commencer à écouter.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Voir aussi : Named Pipe Client Impersonation pour l'abus post-démarrage.

- RPC endpoint trigger (Endpoint Mapper)
- Comportement : Interroger l'Endpoint Mapper (EPM, TCP/135) pour un interface UUID associée à un service provoque le démarrage du service afin qu'il puisse enregistrer son endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Un service peut enregistrer un trigger lié à un provider/événement ETW. Si aucun filtre additionnel (keyword/level/binary/string) n'est configuré, n'importe quel événement provenant de ce provider démarrera le service.

- Exemple (WebClient/WebDAV) : provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Lister le trigger : `sc.exe qtriggerinfo webclient`
- Vérifier que le provider est enregistré : `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Émettre des événements correspondants nécessite généralement du code qui logge vers ce provider ; s'il n'y a pas de filtres, n'importe quel événement suffit.

### Group Policy Triggers

Sous-types : Machine/User. Sur des hôtes joint au domaine où la policy correspondante existe, le trigger s'exécute au boot. `gpupdate` seul ne déclenchera rien sans modifications, mais :

- Activation : `gpupdate /force`
- Si le type de policy pertinent existe, cela provoque de manière fiable le déclenchement et le démarrage du service.

### IP Address Available

Se déclenche lorsque la première IP est obtenue (ou la dernière perdue). Souvent déclenché au démarrage.

- Activation : basculer la connectivité pour retrigger, par ex. :
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Démarre un service lorsqu'une interface d'appareil correspondante arrive. Si aucun data item n'est spécifié, n'importe quel périphérique correspondant au GUID de sous-type du trigger le fera déclencher. Évalué au boot et lors du hot‑plug.

- Activation : Attacher/insérer un périphérique (physique ou virtuel) qui correspond à la classe/ID matériel spécifiée par le sous-type du trigger.

### Domain Join State

Malgré la formulation confuse de MSDN, ceci évalue l'état de jointure au domaine au boot :
- DOMAIN_JOIN_GUID → démarrer le service si la machine est jointe au domaine
- DOMAIN_LEAVE_GUID → démarrer le service seulement si elle N'EST PAS jointe au domaine

### System State Change – WNF (undocumented)

Certains services utilisent des triggers basés sur WNF non documentés (SERVICE_TRIGGER_TYPE 0x7). L'activation nécessite la publication de l'état WNF pertinent ; les détails dépendent du nom de l'état. Contexte de recherche : internals de Windows Notification Facility.

### Aggregate Service Triggers (undocumented)

Observés sur Windows 11 pour certains services (par ex., CDPSvc). La configuration agrégée est stockée dans :

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

La valeur Trigger d’un service est un GUID ; la sous-clé avec ce GUID définit l'événement agrégé. Le déclenchement de n'importe quel événement constituant démarre le service.

### Firewall Port Event (quirks and DoS risk)

Un trigger ciblé sur un port/protocole spécifique a été observé se déclencher sur n'importe quel changement de règle firewall (désactivation/suppression/ajout), pas seulement sur le port spécifié. Pire, configurer un port sans protocole peut corrompre le démarrage de BFE à travers les reboots, entraînant l'échec en cascade de nombreux services et cassant la gestion du firewall. À traiter avec une extrême prudence.

## Practical Workflow

1) Énumérez les triggers sur les services intéressants (RemoteRegistry, WebClient, EFS, …) :
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Si un Network Endpoint trigger existe :
- Named pipe → tenter une ouverture client vers \\.\pipe\<PipeName>
- RPC endpoint → effectuer une lookup Endpoint Mapper pour l'interface UUID

3) Si un ETW trigger existe :
- Vérifiez le provider et les filtres avec `sc.exe qtriggerinfo` ; s'il n'y a pas de filtres, n'importe quel événement de ce provider démarrera le service

4) Pour Group Policy/IP/Device/Domain triggers :
- Utilisez des leviers environnementaux : `gpupdate /force`, basculer les NICs, hot-plug de périphériques, etc.

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

- Faire une baseline et auditer TriggerInfo sur les services. Examiner aussi HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents pour les triggers agrégés.
- Surveiller les requêtes EPM suspectes pour des UUID de services privilégiés et les tentatives de connexion à des named-pipe précédant des démarrages de services.
- Restreindre qui peut modifier les triggers de service ; considérer comme suspect toute défaillance inattendue de BFE après des changements de trigger.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
