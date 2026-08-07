# Attack de macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Pour plus d’informations, consultez l’article original :** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Voici un résumé :<sup>[[1]](#references)</sup>

## Informations de base sur les Mach Messages

Si vous ne savez pas ce que sont les Mach Messages, commencez par consulter cette page :


{{#ref}}
../../
{{#endref}}

Pour le moment, retenez que ([définition disponible ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :<sup>[[1]](#references)</sup>\
Les Mach messages sont envoyés via un _mach port_, un canal de **communication avec un seul récepteur et plusieurs émetteurs** intégré au noyau Mach. **Plusieurs processus peuvent envoyer des messages** à un mach port, mais à tout moment, **un seul processus peut les lire**. Tout comme les descripteurs de fichiers et les sockets, les mach ports sont alloués et gérés par le noyau. Les processus ne voient qu’un entier, qu’ils peuvent utiliser pour indiquer au noyau lequel de leurs mach ports ils souhaitent utiliser.

## XPC Connection

Si vous ne savez pas comment une XPC connection est établie, consultez :


{{#ref}}
../
{{#endref}}

## Résumé de la vulnérabilité

Il est important de savoir que **l’abstraction XPC est une connection one-to-one**, mais qu’elle repose sur une technologie qui **peut avoir plusieurs émetteurs. Ainsi :**

- Les mach ports ont un seul récepteur et **plusieurs émetteurs**.
- L’audit token d’une XPC connection est l’audit token **copié depuis le message reçu le plus récemment**.
- L’obtention de l’**audit token** d’une XPC connection est essentielle à de nombreux **contrôles de sécurité**.<sup>[[1]](#references)</sup>

Bien que la situation précédente semble prometteuse, certains scénarios ne causent pas de problèmes ([source](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :<sup>[[1]](#references)</sup>

- Les audit tokens sont souvent utilisés pour effectuer un contrôle d’autorisation afin de décider s’il faut accepter une connection. Comme ce contrôle s’effectue au moyen d’un message envoyé au service port, **aucune connection n’est encore établie**. Les autres messages envoyés sur ce port seront simplement traités comme des demandes de connection supplémentaires. Ainsi, **les contrôles effectués avant l’acceptation d’une connection ne sont pas vulnérables** (cela signifie également que, dans `-listener:shouldAcceptNewConnection:`, l’audit token est sûr). Nous recherchons donc des XPC connections qui vérifient des actions spécifiques.
- Les gestionnaires d’événements XPC sont traités de manière synchrone. Cela signifie que le gestionnaire d’événements d’un message doit être terminé avant l’appel de celui du message suivant, même sur des files de dispatch concurrentes. Ainsi, dans un **gestionnaire d’événements XPC, l’audit token ne peut pas être écrasé** par d’autres messages normaux (sans reply).<sup>[[1]](#references)</sup>

Deux méthodes différentes peuvent permettre d’exploiter ce comportement :

1. Variante 1 :
- L’**exploit** se **connecte** au service **A** et au service **B**.
- Le service **B** peut appeler une **fonctionnalité privilégiée** du service A que l’utilisateur ne peut pas appeler.
- Le service **A** appelle **`xpc_connection_get_audit_token`** alors qu’il ne se trouve _**pas**_ dans le **gestionnaire d’événements** d’une connection dans un **`dispatch_async`**.
- Ainsi, un **message différent pourrait écraser l’Audit Token**, car il est dispatché de manière asynchrone en dehors du gestionnaire d’événements.
- L’**exploit** transmet au **service B** le **SEND right vers le service A**.
- Le svc **B** enverra donc réellement les **messages** au **service A**.
- L’**exploit** tente d’appeler l’**action privilégiée**. Dans une RC, le svc **A** **vérifie** l’autorisation de cette **action** alors que le **svc B a écrasé l’Audit token**, donnant ainsi à l’exploit l’accès à l’action privilégiée.
2. Variante 2 :
- Le service **B** peut appeler une **fonctionnalité privilégiée** du service A que l’utilisateur ne peut pas appeler.
- L’exploit se connecte au **service A**, qui **envoie** à l’exploit un **message attendant une réponse** sur un **port de replay** spécifique.
- L’exploit envoie au **service B** un message transmettant **ce port de réponse**.
- Lorsque le service **B répond**, il **envoie le message au service A**, tandis que l’**exploit** envoie un **message différent au service A** pour tenter d’atteindre une **fonctionnalité privilégiée**, en espérant que la réponse du service B écrasera l’Audit token au moment idéal (Race Condition).

## Variante 1 : appel de xpc_connection_get_audit_token en dehors d’un gestionnaire d’événements <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scénario :

- Deux mach services **`A`** et **`B`** auxquels nous pouvons tous deux nous connecter (selon le profil sandbox et les contrôles d’autorisation effectués avant l’acceptation de la connection).
- _**A**_ doit effectuer un **contrôle d’autorisation** pour une action spécifique que **`B`** peut réussir à passer (mais pas notre application).
- Par exemple, si B possède certains **entitlements** ou s’exécute en tant que **root**, il peut être autorisé à demander à A d’effectuer une action privilégiée.
- Pour ce contrôle d’autorisation, **`A`** obtient l’audit token de manière asynchrone, par exemple en appelant `xpc_connection_get_audit_token` depuis `dispatch_async`.

> [!CAUTION]
> Dans ce cas, un attaquant pourrait déclencher une **Race Condition** en créant un **exploit** qui demande plusieurs fois à **A** d’effectuer une action, tout en faisant en sorte que **B envoie des messages à `A`**. Lorsque la RC **réussit**, l’**audit token** de **B** est copié en mémoire alors que la requête de notre **exploit** est en cours de traitement par A, lui donnant accès à l’action privilégiée que seul B pouvait demander.

Cela s’est produit avec **`A`** correspondant à `smd` et **`B`** correspondant à `diagnosticd`. La fonction [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb peut être utilisée pour installer un nouvel outil helper privilégié (en tant que **root**). Si un **processus exécuté en tant que root contacte** **smd**, aucun autre contrôle ne sera effectué.

Le service **B** est donc **`diagnosticd`**, car il s’exécute en tant que **root** et peut être utilisé pour **surveiller** un processus. Une fois la surveillance démarrée, il **enverra plusieurs messages par seconde**.

Pour effectuer l’attaque :

1. Initiez une **connection** vers le service nommé `smd` en utilisant le protocole XPC standard.
2. Établissez une connection secondaire vers `diagnosticd`. Contrairement à la procédure normale, au lieu de créer et d’envoyer deux nouveaux mach ports, le client port send right est remplacé par un duplicata du **send right** associé à la connection `smd`.
3. Ainsi, les messages XPC peuvent être dispatchés vers `diagnosticd`, mais les réponses de `diagnosticd` sont redirigées vers `smd`. Pour `smd`, les messages provenant de l’utilisateur et de `diagnosticd` semblent provenir de la même connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. L’étape suivante consiste à demander à `diagnosticd` de commencer la surveillance d’un processus choisi (potentiellement celui de l’utilisateur). En parallèle, une avalanche de messages 1004 ordinaires est envoyée à `smd`. L’objectif est d’installer un outil avec des privilèges élevés.
5. Cette action déclenche une Race Condition dans la fonction `handle_bless`. Le timing est essentiel : l’appel à la fonction `xpc_connection_get_pid` doit retourner le PID du processus de l’utilisateur (car l’outil privilégié se trouve dans le bundle de l’application de l’utilisateur). Cependant, la fonction `xpc_connection_get_audit_token`, spécifiquement dans la sous-routine `connection_is_authorized`, doit faire référence à l’audit token appartenant à `diagnosticd`.<sup>[[1]](#references)</sup>

## Variante 2 : reply forwarding

Dans un environnement XPC (Cross-Process Communication), bien que les gestionnaires d’événements ne s’exécutent pas simultanément, le traitement des messages de reply possède un comportement particulier. Plus précisément, deux méthodes distinctes permettent d’envoyer des messages qui attendent une reply :

1. **`xpc_connection_send_message_with_reply`** : ici, le message XPC est reçu et traité sur une file désignée.
2. **`xpc_connection_send_message_with_reply_sync`** : à l’inverse, avec cette méthode, le message XPC est reçu et traité sur la file de dispatch actuelle.

Cette distinction est essentielle, car elle permet aux **reply packets d’être analysés simultanément avec l’exécution d’un gestionnaire d’événements XPC**. Il est important de noter que, bien que `_xpc_connection_set_creds` implémente un verrouillage pour empêcher l’écrasement partiel de l’audit token, cette protection ne s’étend pas à l’ensemble de l’objet connection. Cela crée donc une vulnérabilité permettant de remplacer l’audit token pendant l’intervalle entre l’analyse d’un packet et l’exécution de son gestionnaire d’événements.

Pour exploiter cette vulnérabilité, la configuration suivante est nécessaire :

- Deux mach services, appelés **`A`** et **`B`**, auxquels il est possible d’établir une connection.
- Le service **`A`** doit inclure un contrôle d’autorisation pour une action spécifique que seul **`B`** peut effectuer (l’application de l’utilisateur ne le peut pas).
- Le service **`A`** doit envoyer un message qui attend une reply.
- L’utilisateur doit pouvoir envoyer un message à **`B`** auquel celui-ci répondra.

Le processus d’exploitation comprend les étapes suivantes :

1. Attendez que le service **`A`** envoie un message attendant une reply.
2. Au lieu de répondre directement à **`A`**, le reply port est détourné et utilisé pour envoyer un message au service **`B`**.
3. Ensuite, un message impliquant l’action interdite est dispatché, en espérant qu’il soit traité simultanément avec la reply de **`B`**.<sup>[[1]](#references)</sup>

Voici une représentation visuelle du scénario d’attaque décrit :

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problèmes de découverte

- **Difficultés pour localiser les instances** : rechercher les instances d’utilisation de `xpc_connection_get_audit_token` était difficile, aussi bien statiquement que dynamiquement.
- **Méthodologie** : Frida a été utilisé pour hooker la fonction `xpc_connection_get_audit_token`, en filtrant les appels ne provenant pas de gestionnaires d’événements. Cependant, cette méthode était limitée au processus hooké et nécessitait une utilisation active.
- **Outils d’analyse** : des outils comme IDA/Ghidra ont été utilisés pour examiner les mach services accessibles, mais le processus était long et compliqué par les appels impliquant le dyld shared cache.
- **Limitations du scripting** : les tentatives de scripter l’analyse des appels à `xpc_connection_get_audit_token` depuis des blocs `dispatch_async` ont été compliquées par l’analyse des blocs et les interactions avec le dyld shared cache.<sup>[[1]](#references)</sup>

## Le correctif <a href="#the-fix" id="the-fix"></a>

- **Problèmes signalés** : un rapport a été envoyé à Apple concernant les problèmes généraux et spécifiques identifiés dans `smd`.
- **Réponse d’Apple** : Apple a corrigé le problème dans `smd` en remplaçant `xpc_connection_get_audit_token` par `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature du correctif** : la fonction `xpc_dictionary_get_audit_token` est considérée comme sûre, car elle récupère directement l’audit token depuis le mach message associé au message XPC reçu. Cependant, elle ne fait pas partie de l’API publique, tout comme `xpc_connection_get_audit_token`.
- **Absence de correctif plus large** : on ne sait toujours pas pourquoi Apple n’a pas implémenté un correctif plus complet, comme la suppression des messages qui ne correspondent pas à l’audit token enregistré de la connection. La possibilité que l’audit token change légitimement dans certains scénarios (par exemple avec l’utilisation de `setuid`) pourrait être un facteur.
- **État actuel** : le problème persiste dans iOS 17 et macOS 14, ce qui complique son identification et sa compréhension.<sup>[[1]](#references)</sup>

## Identification des chemins de code vulnérables en pratique (2024–2025)

Lors de l’audit de XPC services pour cette classe de bugs, concentrez-vous sur les autorisations effectuées en dehors du gestionnaire d’événements du message ou simultanément au traitement des reply.

Conseils de triage statique :
- Recherchez les appels à `xpc_connection_get_audit_token` accessibles depuis des blocs mis en file via `dispatch_async`/`dispatch_after` ou d’autres files de travail qui s’exécutent en dehors du gestionnaire de messages.
- Recherchez les helpers d’autorisation qui mélangent l’état par connection et l’état par message (par exemple, récupérer le PID avec `xpc_connection_get_pid`, mais l’audit token avec `xpc_connection_get_audit_token`).
- Dans le code NSXPC, vérifiez que les contrôles sont effectués dans `-listener:shouldAcceptNewConnection:` ou, pour les contrôles par message, que l’implémentation utilise un audit token par message (par exemple, le dictionnaire du message via `xpc_dictionary_get_audit_token` dans le code de plus bas niveau).

Conseils de triage dynamique :
- Hookez `xpc_connection_get_audit_token` et signalez les appels dont la stack utilisateur n’inclut pas le chemin de livraison des événements (par exemple, `_xpc_connection_mach_event`). Exemple de hook Frida :
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notes :
- Sur macOS, l’instrumentation de binaires protégés/Apple peut nécessiter la désactivation de SIP ou un environnement de développement ; privilégiez les tests sur vos propres builds ou sur des services userland.
- Pour les races de reply-forwarding (Variant 2), surveillez l’analyse concurrente des paquets de réponse en faisant varier les timings de `xpc_connection_send_message_with_reply` par rapport aux requêtes normales, et vérifiez si l’audit token effectif utilisé lors de l’autorisation peut être influencé.

## Exploitation primitives dont vous aurez probablement besoin

- Configuration multi-sender (Variant 1) : créez des connexions vers A et B ; dupliquez le send right du client port de A et utilisez-le comme client port de B afin que les replies de B soient délivrées à A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2) : capturer le send-once right depuis la pending request de A (reply port), puis envoyer un crafted message à B en utilisant ce reply port afin que la réponse de B arrive chez A pendant que votre privileged request est en cours d’analyse.

Ces techniques nécessitent de créer des mach messages de bas niveau pour les formats bootstrap et message de XPC ; consultez les pages d’introduction à mach/XPC de cette section pour connaître les layouts exacts des paquets et les flags.

## Outillage utile

- XPC sniffing/dynamic inspection : gxpc (open-source XPC sniffer) peut aider à énumérer les connexions et à observer le trafic afin de valider les configurations multi-sender et le timing. Exemple : `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing pour libxpc : interposez `xpc_connection_send_message*` et `xpc_connection_get_audit_token` afin de journaliser les call sites et les stacks pendant les tests en black-box.



## Références

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
