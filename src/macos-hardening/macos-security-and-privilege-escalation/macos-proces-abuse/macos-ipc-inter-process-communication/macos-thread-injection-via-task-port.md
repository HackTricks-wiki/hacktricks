# Injection de thread via le task port de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Détournement de thread

Initialement, la fonction `task_threads()` est invoquée sur le task port afin d'obtenir une liste de threads depuis la tâche distante. Un thread est sélectionné pour être détourné. Cette approche diverge des méthodes conventionnelles d'injection de code, car la création d'un nouveau thread distant est interdite en raison de la mitigation qui bloque `thread_create_running()`.<sup>[[1]](#references)</sup>

Pour contrôler le thread, `thread_suspend()` est appelée, ce qui interrompt son exécution.<sup>[[1]](#references)</sup>

Les seules opérations autorisées sur le thread distant consistent à l'**arrêter** et à le **démarrer**, ainsi qu'à **récupérer**/**modifier** les valeurs de ses registres. Les appels de fonctions distantes sont initiés en définissant les registres `x0` à `x7` sur les **arguments**, en configurant `pc` pour pointer vers la fonction souhaitée, puis en reprenant l'exécution du thread. Pour éviter que le thread ne plante après le retour, il est nécessaire de détecter ce retour.<sup>[[1]](#references)</sup>

Une stratégie consiste à enregistrer un **gestionnaire d'exception** pour le thread distant à l'aide de `thread_set_exception_ports()`, en définissant le registre `lr` sur une adresse invalide avant l'appel de fonction. Cela déclenche une exception après l'exécution de la fonction et envoie un message au port d'exception, ce qui permet d'inspecter l'état du thread afin de récupérer la valeur de retour. Une autre approche, adoptée de l'exploit *triple_fetch* d'Ian Beer, consiste à définir `lr` pour boucler indéfiniment ; les registres du thread sont ensuite surveillés en continu jusqu'à ce que `pc` pointe vers cette instruction.<sup>[[1]](#references)</sup>

## 2. Mach ports pour la communication

La phase suivante consiste à établir des Mach ports afin de permettre la communication avec le thread distant. Ces ports sont essentiels pour transférer arbitrairement des send/receive rights entre les tâches.<sup>[[1]](#references)</sup>

Pour permettre une communication bidirectionnelle, deux receive rights Mach sont créés : l'un dans la tâche locale et l'autre dans la tâche distante. Ensuite, un send right pour chaque port est transféré vers la tâche correspondante, ce qui permet l'échange de messages.<sup>[[1]](#references)</sup>

Concernant le port local, le receive right est détenu par la tâche locale. Le port est créé avec `mach_port_allocate()`. La difficulté consiste à transférer un send right vers ce port dans la tâche distante.<sup>[[1]](#references)</sup>

Une stratégie consiste à utiliser `thread_set_special_port()` pour placer un send right vers le port local dans le `THREAD_KERNEL_PORT` du thread distant. Le thread distant reçoit ensuite l'instruction d'appeler `mach_thread_self()` afin de récupérer le send right.<sup>[[1]](#references)</sup>

Pour le port distant, le processus est essentiellement inversé. Le thread distant reçoit l'instruction de générer un Mach port via `mach_reply_port()` (`mach_port_allocate()` ne convenant pas en raison de son mécanisme de retour). Une fois le port créé, `mach_port_insert_right()` est invoquée dans le thread distant afin d'établir un send right. Ce right est ensuite stocké dans le kernel à l'aide de `thread_set_special_port()`. De retour dans la tâche locale, `thread_get_special_port()` est utilisée sur le thread distant afin d'obtenir un send right vers le Mach port nouvellement alloué dans la tâche distante.<sup>[[1]](#references)</sup>

Une fois ces étapes terminées, les Mach ports sont établis, ce qui prépare le terrain pour une communication bidirectionnelle.<sup>[[1]](#references)</sup>

## 3. Primitives de lecture/écriture mémoire de base

Dans cette section, l'objectif est d'utiliser la primitive d'exécution afin d'établir des primitives de lecture/écriture mémoire de base. Ces premières étapes sont essentielles pour obtenir davantage de contrôle sur le processus distant, même si les primitives à ce stade n'auront pas beaucoup d'utilité. Elles seront bientôt améliorées pour devenir des versions plus avancées.<sup>[[1]](#references)</sup>

### Lecture et écriture mémoire à l'aide de la primitive d'exécution

L'objectif est d'effectuer des lectures et des écritures mémoire à l'aide de fonctions spécifiques. Pour la **lecture mémoire** :
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Pour **l’écriture en mémoire** :
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Ces fonctions correspondent à l’assembleur suivant :
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
2. **Écriture en mémoire — `_xpc_int64_set_value()`** (libxpc) :
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Pour effectuer une écriture de 64 bits à une adresse arbitraire :
```c
_xpc_int64_set_value(address - 0x18, value);
```
Avec ces primitives établies, les conditions sont réunies pour créer une mémoire partagée, ce qui constitue une avancée significative dans le contrôle du processus distant.<sup>[[1]](#references)</sup>

## 4. Configuration de la mémoire partagée

L’objectif est d’établir une mémoire partagée entre les tâches locale et distante, afin de simplifier le transfert de données et de faciliter l’appel de fonctions avec plusieurs arguments. Cette approche exploite `libxpc` et son type d’objet `OS_xpc_shmem`, qui repose sur des entrées mémoire Mach.<sup>[[1]](#references)</sup>

### Vue d’ensemble du processus

1. **Allocation de mémoire**
* Allouer la mémoire à partager avec `mach_vm_allocate()`.
* Utiliser `xpc_shmem_create()` pour créer un objet `OS_xpc_shmem` correspondant à la région allouée.
2. **Création de la mémoire partagée dans le processus distant**
* Allouer de la mémoire pour l’objet `OS_xpc_shmem` dans le processus distant (`remote_malloc`).
* Copier l’objet modèle local ; la correction du send right Mach intégré à l’offset `0x18` reste nécessaire.
3. **Correction de l’entrée mémoire Mach**
* Insérer un send right avec `thread_set_special_port()` et écraser le champ `0x18` avec le nom de l’entrée distante.
4. **Finalisation**
* Valider l’objet distant et le mapper avec un appel distant à `xpc_shmem_remote()`.

## 5. Obtention d’un contrôle total

Une fois l’exécution arbitraire et un back-channel de mémoire partagée disponibles, vous contrôlez effectivement le processus cible :<sup>[[1]](#references)</sup>

* **Lecture/écriture arbitraire de la mémoire** — utiliser `memcpy()` entre les régions locale et partagée.
* **Appels de fonctions avec plus de 8 arguments** — placer les arguments supplémentaires sur la stack en suivant la convention d’appel arm64.
* **Transfert de ports Mach** — transmettre les rights dans des messages Mach via les ports établis.
* **Transfert de descripteurs de fichiers** — exploiter les fileports (voir *triple_fetch*).

Tout cela est encapsulé dans la bibliothèque [`threadexec`](https://github.com/bazad/threadexec) pour faciliter sa réutilisation.

---

## 6. Spécificités d’Apple Silicon (arm64e)

Sur les appareils Apple Silicon (arm64e), les **Pointer Authentication Codes (PAC)** protègent toutes les adresses de retour ainsi que de nombreux pointeurs de fonctions. Les techniques de thread-hijacking qui *réutilisent du code existant* continuent de fonctionner, car les valeurs d’origine dans `lr`/`pc` contiennent déjà des signatures PAC valides. Des problèmes surviennent lorsque vous tentez d’effectuer un saut vers une mémoire contrôlée par l’attaquant :

1. Allouer de la mémoire exécutable à l’intérieur de la cible (`mach_vm_allocate` distant + `mprotect(PROT_EXEC)`).
2. Copier votre payload.
3. Dans le processus *distant*, signer le pointeur :
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Définissez `pc = ptr` dans l’état du thread détourné.

Alternativement, restez conforme à PAC en chaînant des gadgets/fonctions existants (ROP traditionnelle).

## 7. Détection et durcissement avec EndpointSecurity

Le framework **EndpointSecurity (ES)** expose des événements du kernel qui permettent aux défenseurs d’observer ou de bloquer les tentatives d’injection de threads :

* `ES_EVENT_TYPE_AUTH_GET_TASK` – déclenché lorsqu’un processus demande le port d’une autre task (p. ex. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – émis chaque fois qu’un thread est créé dans une *task* différente.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (ajouté dans macOS 14 Sonoma) – indique la manipulation des registres d’un thread existant.

Client Swift minimal qui affiche les événements de threads distants :
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
### Considérations relatives au Hardened Runtime

Distribuer votre application **sans** l’entitlement `com.apple.security.get-task-allow` empêche les attaquants non-root d’obtenir son task-port. System Integrity Protection (SIP) bloque toujours l’accès à de nombreux binaires Apple, mais les logiciels tiers doivent explicitement effectuer un opt-out.

## 8. Outils publics récents (2023-2025)

| Outil | Année | Remarques |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC compact qui démontre le thread hijacking prenant en compte le PAC sur Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Helper EndpointSecurity utilisé par plusieurs fournisseurs d’EDR pour signaler les événements `REMOTE_THREAD_CREATE` |

> Lire le code source de ces projets est utile pour comprendre les changements d’API introduits dans macOS 13/14 et rester compatible entre Intel et Apple Silicon.

## Références

- [1] [Contournement des restrictions applicables aux platform binaries avec task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Documentation Apple Developer](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
