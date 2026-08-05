# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Initialement, la fonction `task_threads()` est invoquée sur le task port afin d'obtenir une liste de threads depuis la tâche distante. Un thread est sélectionné pour être détourné. Cette approche diffère des méthodes conventionnelles d'injection de code, car la création d'un nouveau thread distant est interdite en raison de la mitigation qui bloque `thread_create_running()`.<sup>[[1]](#references)</sup>

Pour contrôler le thread, `thread_suspend()` est appelée, ce qui interrompt son exécution.<sup>[[1]](#references)</sup>

Les seules opérations autorisées sur le thread distant consistent à l'**arrêter** et à le **démarrer**, ainsi qu'à **récupérer**/**modifier** les valeurs de ses registres. Les appels de fonctions distantes sont initiés en définissant les registres `x0` à `x7` avec les **arguments**, en configurant `pc` pour cibler la fonction souhaitée, puis en reprenant l'exécution du thread. Pour éviter que le thread ne plante après le retour, il est nécessaire de détecter ce retour.<sup>[[1]](#references)</sup>

Une stratégie consiste à enregistrer un **exception handler** pour le thread distant à l'aide de `thread_set_exception_ports()`, puis à définir le registre `lr` sur une adresse invalide avant l'appel de fonction. Cela déclenche une exception après l'exécution de la fonction et envoie un message à l'exception port, ce qui permet d'inspecter l'état du thread afin de récupérer la valeur de retour. Une autre méthode, adoptée à partir de l'exploit *triple_fetch* d'Ian Beer, consiste à définir `lr` pour boucler indéfiniment ; les registres du thread sont ensuite surveillés en continu jusqu'à ce que `pc` pointe vers cette instruction.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

La phase suivante consiste à établir des Mach ports afin de permettre la communication avec le thread distant. Ces ports sont essentiels pour transférer arbitrairement des send/receive rights entre les tâches.<sup>[[1]](#references)</sup>

Pour permettre une communication bidirectionnelle, deux Mach receive rights sont créés : un dans la tâche locale et l'autre dans la tâche distante. Ensuite, un send right pour chaque port est transféré à la tâche correspondante, ce qui permet l'échange de messages.<sup>[[1]](#references)</sup>

Pour le port local, le receive right est détenu par la tâche locale. Le port est créé avec `mach_port_allocate()`. La difficulté consiste à transférer un send right vers ce port dans la tâche distante.<sup>[[1]](#references)</sup>

Une stratégie consiste à utiliser `thread_set_special_port()` pour placer un send right vers le port local dans le `THREAD_KERNEL_PORT` du thread distant. Le thread distant reçoit ensuite l'instruction d'appeler `mach_thread_self()` afin de récupérer le send right.<sup>[[1]](#references)</sup>

Pour le port distant, le processus est essentiellement inversé. Le thread distant reçoit l'instruction de générer un Mach port via `mach_reply_port()` (`mach_port_allocate()` ne convenant pas en raison de son mécanisme de retour). Une fois le port créé, `mach_port_insert_right()` est invoquée dans le thread distant afin d'établir un send right. Ce right est ensuite stocké dans le kernel à l'aide de `thread_set_special_port()`. De retour dans la tâche locale, `thread_get_special_port()` est utilisée sur le thread distant afin d'obtenir un send right vers le Mach port nouvellement alloué dans la tâche distante.<sup>[[1]](#references)</sup>

L'achèvement de ces étapes entraîne l'établissement des Mach ports, jetant les bases d'une communication bidirectionnelle.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Dans cette section, l'objectif est d'utiliser l'execute primitive afin d'établir des memory read/write primitives de base. Ces premières étapes sont essentielles pour obtenir davantage de contrôle sur le processus distant, bien que les primitives à ce stade ne soient pas très utiles. Elles seront bientôt améliorées pour devenir des versions plus avancées.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

L'objectif est d'effectuer des lectures et des écritures de mémoire à l'aide de fonctions spécifiques. Pour la **lecture de la mémoire** :
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Pour **écrire en mémoire** :
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Ces fonctions correspondent à l’assembly suivant :
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identification des fonctions appropriées

Une analyse des bibliothèques courantes a révélé des candidates appropriées pour ces opérations :<sup>[[1]](#references)</sup>

1. **Lecture de la mémoire — `property_getName()`** (libobjc) :
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Écriture en mémoire — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Pour effectuer une écriture 64 bits à une adresse arbitraire :
```c
_xpc_int64_set_value(address - 0x18, value);
```
Une fois ces primitives établies, les conditions sont réunies pour créer une mémoire partagée, ce qui constitue une avancée significative dans le contrôle du processus distant.<sup>[[1]](#references)</sup>

## 4. Configuration de la mémoire partagée

L’objectif est d’établir une mémoire partagée entre les tâches locale et distante, afin de simplifier le transfert de données et de faciliter l’appel de fonctions avec plusieurs arguments. Cette approche s’appuie sur `libxpc` et son type d’objet `OS_xpc_shmem`, qui repose sur des memory entries Mach.<sup>[[1]](#references)</sup>

### Vue d’ensemble du processus

1. **Allocation de la mémoire**
* Allouer la mémoire à partager avec `mach_vm_allocate()`.
* Utiliser `xpc_shmem_create()` pour créer un objet `OS_xpc_shmem` correspondant à la région allouée.
2. **Création de la mémoire partagée dans le processus distant**
* Allouer de la mémoire pour l’objet `OS_xpc_shmem` dans le processus distant (`remote_malloc`).
* Copier l’objet template local ; le fix-up du Mach send right intégré à l’offset `0x18` est toujours nécessaire.
3. **Correction de la Mach memory entry**
* Insérer un send right avec `thread_set_special_port()` et écraser le champ `0x18` avec le nom de l’entry distante.
4. **Finalisation**
* Valider l’objet distant et le mapper avec un appel distant à `xpc_shmem_remote()`.

## 5. Obtention d’un contrôle total

Une fois qu’une exécution arbitraire et un back-channel en mémoire partagée sont disponibles, vous contrôlez effectivement le processus cible :<sup>[[1]](#references)</sup>

* **Lecture/écriture arbitraire en mémoire** — utiliser `memcpy()` entre les régions locale et partagée.
* **Appels de fonctions avec > 8 arguments** — placer les arguments supplémentaires sur la stack conformément à la calling convention arm64.
* **Transfert de Mach ports** — transmettre des rights dans des messages Mach via les ports établis.
* **Transfert de file descriptors** — exploiter les fileports (voir *triple_fetch*).

Tout cela est encapsulé dans la library [`threadexec`](https://github.com/bazad/threadexec) pour faciliter sa réutilisation.

---

## 6. Particularités d’Apple Silicon (arm64e)

Sur les appareils Apple Silicon (arm64e), les **Pointer Authentication Codes (PAC)** protègent toutes les adresses de retour ainsi que de nombreux pointeurs de fonctions. Les techniques de thread-hijacking qui *réutilisent du code existant* continuent de fonctionner, car les valeurs d’origine dans `lr`/`pc` possèdent déjà des signatures PAC valides. Des problèmes apparaissent lorsque vous tentez d’effectuer un saut vers une mémoire contrôlée par l’attaquant :

1. Allouer de la mémoire exécutable à l’intérieur de la cible (`mach_vm_allocate` distant + `mprotect(PROT_EXEC)`).
2. Copier votre payload.
3. Dans le processus *distant*, signer le pointeur :
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Définissez `pc = ptr` dans l’état du thread détourné.

Vous pouvez également rester conforme à PAC en enchaînant des gadgets/fonctions existants (ROP traditionnelle).

## 7. Détection et durcissement avec EndpointSecurity

Le framework **EndpointSecurity (ES)** expose des événements du kernel qui permettent aux défenseurs d’observer ou de bloquer les tentatives d’injection de thread :

* `ES_EVENT_TYPE_AUTH_GET_TASK` – déclenché lorsqu’un processus demande le port de la task d’un autre processus (par exemple, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – émis chaque fois qu’un thread est créé dans une *task* différente.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (ajouté dans macOS 14 Sonoma) – indique la manipulation des registres d’un thread existant.

Client Swift minimal qui affiche les événements de remote-thread :
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Interroger avec **osquery** ≥ 5.8 :
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Considérations relatives au hardened runtime

Distribuer votre application **sans** l'entitlement `com.apple.security.get-task-allow` empêche les attackers non-root d'obtenir son task-port. System Integrity Protection (SIP) bloque toujours l'accès à de nombreux binaires Apple, mais les logiciels tiers doivent explicitement choisir de ne pas en bénéficier.

## 8. Outils publics récents (2023-2025)

| Outil | Année | Remarques |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compact démontrant le thread hijacking prenant en compte le PAC sur Ventura/Sonoma |
| `remote_thread_es` | 2024 | Helper EndpointSecurity utilisé par plusieurs fournisseurs d'EDR pour exposer les événements `REMOTE_THREAD_CREATE` |

> La lecture du code source de ces projets est utile pour comprendre les changements d'API introduits dans macOS 13/14 et rester compatible entre Intel et Apple Silicon.

## Références

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
