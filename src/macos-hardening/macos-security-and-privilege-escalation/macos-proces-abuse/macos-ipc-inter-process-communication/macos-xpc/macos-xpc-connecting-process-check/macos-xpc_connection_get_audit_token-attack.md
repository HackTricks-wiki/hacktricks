# Attaque macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Pour plus d’informations, consultez l’article original :** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Voici un résumé :

## Informations de base sur les Mach Messages

Si vous ne savez pas ce que sont les Mach Messages, commencez par consulter cette page :


{{#ref}}
../../
{{#endref}}

Pour le moment, retenez que ([définition disponible ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :\
Les Mach messages sont envoyés via un _mach port_, qui est un canal de communication **à un seul récepteur et plusieurs émetteurs** intégré au noyau Mach. **Plusieurs processus peuvent envoyer des messages** à un mach port, mais à tout moment, **un seul processus peut y lire**. Comme les descripteurs de fichiers et les sockets, les mach ports sont alloués et gérés par le noyau, et les processus ne voient qu’un entier qu’ils peuvent utiliser pour indiquer au noyau lequel de leurs mach ports ils veulent utiliser.

## Connexion XPC

Si vous ne savez pas comment établir une connexion XPC, consultez :


{{#ref}}
../
{{#endref}}

## Résumé de la vulnérabilité

Il est important de savoir que **l’abstraction XPC est une connexion un-à-un**, mais qu’elle repose sur une technologie qui **peut avoir plusieurs émetteurs, donc :**

- Les Mach ports ont un seul récepteur et **plusieurs émetteurs**.
- L’audit token d’une connexion XPC est celui qui a été **copié depuis le message reçu le plus récemment**.
- L’obtention de l’**audit token** d’une connexion XPC est essentielle à de nombreux **contrôles de sécurité**.<sup>[1]</sup>

Bien que la situation précédente semble prometteuse, certains scénarios n’entraînent pas de problèmes ([source](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :

- Les audit tokens sont souvent utilisés pour un contrôle d’autorisation afin de décider s’il faut accepter une connexion. Comme cela se produit via un message envoyé au service port, **aucune connexion n’est encore établie**. Les messages supplémentaires envoyés sur ce port seront simplement traités comme des demandes de connexion supplémentaires. Ainsi, **les contrôles effectués avant l’acceptation d’une connexion ne sont pas vulnérables** (cela signifie également que, dans `-listener:shouldAcceptNewConnection:`, l’audit token est sûr). Nous recherchons donc des connexions XPC qui vérifient des actions spécifiques.
- Les gestionnaires d’événements XPC sont traités de manière synchrone. Cela signifie que le gestionnaire d’événements d’un message doit être terminé avant que celui du message suivant soit appelé, même sur des files de dispatch concurrentes. Ainsi, dans un **gestionnaire d’événements XPC, l’audit token ne peut pas être écrasé** par d’autres messages normaux (sans réponse !).<sup>[1]</sup>

Deux méthodes différentes peuvent être exploitables :

1. Variante 1 :
- L’**exploit** se **connecte** au service **A** et au service **B**.
- Le service **B** peut appeler une **fonctionnalité privilégiée** du service A que l’utilisateur ne peut pas appeler.
- Le service **A** appelle **`xpc_connection_get_audit_token`** alors qu’il n’est _**pas**_ dans le **gestionnaire d’événements** d’une connexion dans un **`dispatch_async`**.
- Ainsi, un **message différent pourrait écraser l’Audit Token**, car il est distribué de manière asynchrone en dehors du gestionnaire d’événements.
- L’exploit transmet au **service B le droit SEND vers le service A**.
- Le svc **B** **enverra** donc réellement les **messages** au service **A**.
- L’**exploit** tente d’appeler l’**action privilégiée**. Dans une RC, le svc **A** **vérifie** l’autorisation de cette **action** alors que le **svc B a écrasé l’Audit Token** (ce qui permet à l’exploit d’appeler l’action privilégiée).
2. Variante 2 :
- Le service **B** peut appeler une **fonctionnalité privilégiée** du service A que l’utilisateur ne peut pas appeler.
- L’exploit se connecte au **service A**, qui **envoie** à l’exploit un **message attendant une réponse** sur un **port de réponse** spécifique.
- L’exploit envoie au **service B** un message contenant **ce port de réponse**.
- Lorsque le service **B répond**, il **envoie le message au service A**, tandis que l’**exploit** envoie un **message différent au service A** pour tenter d’atteindre une **fonctionnalité privilégiée**, en espérant que la réponse du service B écrasera l’Audit Token au moment idéal (Race Condition).

## Variante 1 : appel de xpc_connection_get_audit_token en dehors d’un gestionnaire d’événements <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scénario :

- Deux mach services **`A`** et **`B`** auxquels nous pouvons tous deux nous connecter (en fonction du sandbox profile et des contrôles d’autorisation effectués avant l’acceptation de la connexion).
- _**A**_ doit effectuer un **contrôle d’autorisation** pour une action spécifique que **B** peut réussir (mais pas notre application).
- Par exemple, si B possède certains **entitlements** ou s’exécute en tant que **root**, il peut être autorisé à demander à A d’effectuer une action privilégiée.
- Pour ce contrôle d’autorisation, **A** obtient l’audit token de manière asynchrone, par exemple en appelant `xpc_connection_get_audit_token` depuis `dispatch_async`.

> [!CAUTION]
> Dans ce cas, un attaquant pourrait déclencher une **Race Condition** et créer un **exploit** qui demande plusieurs fois à A d’effectuer une action tout en faisant envoyer des **messages à `A` par B**. Lorsque la RC **réussit**, l’**audit token** de **B** est copié en mémoire **pendant le traitement de la demande de notre exploit** par A, ce qui lui donne **accès à l’action privilégiée que seul B pouvait demander**.

Cela s’est produit avec **`A`** correspondant à `smd` et **`B`** à `diagnosticd`. La fonction [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb peut être utilisée pour installer un nouvel helper tool privilégié (en tant que **root**). Si un **processus exécuté en tant que root contacte** **smd**, aucun autre contrôle ne sera effectué.

Le service **B** est donc **`diagnosticd`**, car il s’exécute en tant que **root** et peut être utilisé pour **monitorer** un processus. Une fois le monitoring commencé, il **enverra plusieurs messages par seconde**.

Pour effectuer l’attaque :

1. Initiez une **connexion** au service nommé `smd` en utilisant le protocole XPC standard.
2. Établissez une seconde **connexion** à `diagnosticd`. Contrairement à la procédure normale, au lieu de créer et d’envoyer deux nouveaux mach ports, le client port send right est remplacé par un duplicata du **send right** associé à la connexion `smd`.
3. Ainsi, les messages XPC peuvent être distribués à `diagnosticd`, mais les réponses de `diagnosticd` sont redirigées vers `smd`. Pour `smd`, les messages provenant de l’utilisateur et de `diagnosticd` semblent provenir de la même connexion.

![Image représentant le processus de l’exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. L’étape suivante consiste à demander à `diagnosticd` de commencer le monitoring d’un processus choisi (éventuellement celui de l’utilisateur lui-même). En parallèle, une avalanche de messages 1004 ordinaires est envoyée à `smd`. L’objectif est d’installer un outil avec des privilèges élevés.
5. Cette action déclenche une race condition dans la fonction `handle_bless`. Le timing est essentiel : l’appel à la fonction `xpc_connection_get_pid` doit renvoyer le PID du processus de l’utilisateur (car l’outil privilégié se trouve dans le bundle de l’application de l’utilisateur). Cependant, la fonction `xpc_connection_get_audit_token`, plus précisément dans la sous-routine `connection_is_authorized`, doit faire référence à l’audit token appartenant à `diagnosticd`.<sup>[1]</sup>

## Variante 2 : transfert de réponse

Dans un environnement XPC (Cross-Process Communication), bien que les gestionnaires d’événements ne s’exécutent pas simultanément, le traitement des messages de réponse possède un comportement particulier. Il existe notamment deux méthodes distinctes pour envoyer des messages qui attendent une réponse :

1. **`xpc_connection_send_message_with_reply`** : ici, le message XPC est reçu et traité sur une file désignée.
2. **`xpc_connection_send_message_with_reply_sync`** : à l’inverse, avec cette méthode, le message XPC est reçu et traité sur la file de dispatch actuelle.

Cette distinction est importante, car elle permet aux **paquets de réponse d’être analysés simultanément avec l’exécution d’un gestionnaire d’événements XPC**. Notamment, bien que `_xpc_connection_set_creds` implémente un verrouillage pour empêcher l’écrasement partiel de l’audit token, cette protection ne s’étend pas à l’intégralité de l’objet de connexion. Il en résulte une vulnérabilité permettant de remplacer l’audit token entre l’analyse d’un paquet et l’exécution de son gestionnaire d’événements.

Pour exploiter cette vulnérabilité, la configuration suivante est nécessaire :

- Deux mach services, appelés **`A`** et **`B`**, auxquels il est possible d’établir une connexion.
- Le service **`A`** doit inclure un contrôle d’autorisation pour une action spécifique que seul **`B`** peut effectuer (l’application de l’utilisateur ne le peut pas).
- Le service **`A`** doit envoyer un message attendant une réponse.
- L’utilisateur doit pouvoir envoyer un message à **`B`**, qui y répondra.

Le processus d’exploitation comprend les étapes suivantes :

1. Attendez que le service **`A`** envoie un message qui attend une réponse.
2. Au lieu de répondre directement à **`A`**, détournez le port de réponse et utilisez-le pour envoyer un message au service **`B`**.
3. Ensuite, envoyez un message impliquant l’action interdite, en espérant qu’il sera traité simultanément avec la réponse de **`B`**.<sup>[1]</sup>

Voici une représentation visuelle du scénario d’attaque décrit :

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problèmes liés à la découverte

- **Difficultés pour localiser les instances** : rechercher les utilisations de `xpc_connection_get_audit_token` était difficile, aussi bien de manière statique que dynamique.
- **Méthodologie** : Frida a été utilisé pour hooker la fonction `xpc_connection_get_audit_token` et filtrer les appels ne provenant pas de gestionnaires d’événements. Cependant, cette méthode était limitée au processus hooké et nécessitait une utilisation active.
- **Outils d’analyse** : des outils comme IDA/Ghidra ont été utilisés pour examiner les mach services accessibles, mais le processus était long et compliqué par les appels impliquant le dyld shared cache.
- **Limitations du scripting** : les tentatives visant à automatiser l’analyse des appels à `xpc_connection_get_audit_token` depuis des blocs `dispatch_async` ont été gênées par la complexité de l’analyse des blocs et des interactions avec le dyld shared cache.<sup>[1]</sup>

## Le correctif <a href="#the-fix" id="the-fix"></a>

- **Problèmes signalés** : un rapport a été soumis à Apple, détaillant les problèmes généraux et spécifiques identifiés dans `smd`.
- **Réponse d’Apple** : Apple a corrigé le problème dans `smd` en remplaçant `xpc_connection_get_audit_token` par `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Nature du correctif** : la fonction `xpc_dictionary_get_audit_token` est considérée comme sûre, car elle récupère directement l’audit token depuis le mach message associé au message XPC reçu. Cependant, elle ne fait pas partie de l’API publique, tout comme `xpc_connection_get_audit_token`.
- **Absence de correctif plus large** : on ne sait toujours pas pourquoi Apple n’a pas mis en œuvre un correctif plus complet, comme l’abandon des messages ne correspondant pas à l’audit token sauvegardé de la connexion. La possibilité de changements légitimes de l’audit token dans certains scénarios (par exemple, avec l’utilisation de `setuid`) pourrait être un facteur.
- **État actuel** : le problème persiste dans iOS 17 et macOS 14, ce qui complique son identification et sa compréhension.<sup>[1]</sup>

## Recherche pratique de chemins de code vulnérables (2024–2025)

Lors de l’audit de services XPC pour cette classe de bugs, concentrez-vous sur les autorisations effectuées en dehors du gestionnaire d’événements du message ou simultanément au traitement des réponses.

Conseils de triage statique :
- Recherchez les appels à `xpc_connection_get_audit_token` accessibles depuis des blocs placés en file via `dispatch_async`/`dispatch_after`, ou via d’autres files de worker exécutées en dehors du gestionnaire de messages.
- Recherchez les helpers d’autorisation qui mélangent l’état par connexion et l’état par message (par exemple, récupérer le PID avec `xpc_connection_get_pid`, mais l’audit token avec `xpc_connection_get_audit_token`).
- Dans le code NSXPC, vérifiez que les contrôles sont effectués dans `-listener:shouldAcceptNewConnection:` ou, pour les contrôles par message, que l’implémentation utilise un audit token par message (par exemple, le dictionnaire du message via `xpc_dictionary_get_audit_token` dans du code de niveau inférieur).

Conseils de triage dynamique :
- Hookez `xpc_connection_get_audit_token` et signalez les appels dont la stack utilisateur n’inclut pas le chemin de distribution des événements (par exemple, `_xpc_connection_mach_event`). Exemple de hook Frida :
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
- Pour les races de reply-forwarding (Variant 2), surveillez l’analyse concurrente des paquets de reply en fuzzant les timings de `xpc_connection_send_message_with_reply` par rapport aux requêtes normales, et vérifiez si l’audit token effectif utilisé lors de l’autorisation peut être influencé.

## Primitives d’exploitation dont vous aurez probablement besoin

- Configuration multi-sender (Variant 1) : créez des connexions vers A et B ; dupliquez le send right du port client de A et utilisez-le comme port client de B afin que les replies de B soient délivrées à A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture the send-once right from A’s pending request (reply port), then send a crafted message to B using that reply port so B’s reply lands on A while your privileged request is being parsed.

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## Outils utiles

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) peut aider à énumérer les connexions et à observer le trafic afin de valider les configurations multi-sender et le timing. Exemple : `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` to log call sites and stacks during black-box testing.



## Références

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
