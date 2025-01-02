# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Pour plus d'informations, consultez le post original :** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Voici un résumé :

## Informations de base sur les messages Mach

Si vous ne savez pas ce que sont les messages Mach, commencez par consulter cette page :

{{#ref}}
../../
{{#endref}}

Pour le moment, rappelez-vous que ([définition ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :\
Les messages Mach sont envoyés via un _mach port_, qui est un canal de communication **à récepteur unique et à plusieurs émetteurs** intégré dans le noyau mach. **Plusieurs processus peuvent envoyer des messages** à un mach port, mais à tout moment, **un seul processus peut le lire**. Tout comme les descripteurs de fichiers et les sockets, les mach ports sont alloués et gérés par le noyau, et les processus ne voient qu'un entier, qu'ils peuvent utiliser pour indiquer au noyau lequel de leurs mach ports ils souhaitent utiliser.

## Connexion XPC

Si vous ne savez pas comment une connexion XPC est établie, consultez :

{{#ref}}
../
{{#endref}}

## Résumé des vulnérabilités

Ce qui est intéressant à savoir, c'est que **l'abstraction de XPC est une connexion un-à-un**, mais elle est basée sur une technologie qui **peut avoir plusieurs émetteurs, donc :**

- Les mach ports sont à récepteur unique, **à plusieurs émetteurs**.
- Le jeton d'audit d'une connexion XPC est le jeton d'audit **copié du message reçu le plus récemment**.
- Obtenir le **jeton d'audit** d'une connexion XPC est crucial pour de nombreux **contrôles de sécurité**.

Bien que la situation précédente semble prometteuse, il existe certains scénarios où cela ne posera pas de problèmes ([d'ici](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)) :

- Les jetons d'audit sont souvent utilisés pour un contrôle d'autorisation afin de décider d'accepter une connexion. Comme cela se produit en utilisant un message vers le port de service, **aucune connexion n'est encore établie**. D'autres messages sur ce port seront simplement traités comme des demandes de connexion supplémentaires. Ainsi, tous les **contrôles avant d'accepter une connexion ne sont pas vulnérables** (cela signifie également que dans `-listener:shouldAcceptNewConnection:`, le jeton d'audit est sûr). Nous recherchons donc **des connexions XPC qui vérifient des actions spécifiques**.
- Les gestionnaires d'événements XPC sont traités de manière synchrone. Cela signifie que le gestionnaire d'événements pour un message doit être complété avant d'appeler celui pour le suivant, même sur des files d'attente de dispatch concurrentes. Ainsi, à l'intérieur d'un **gestionnaire d'événements XPC, le jeton d'audit ne peut pas être écrasé** par d'autres messages normaux (non-réponse !).

Deux méthodes différentes par lesquelles cela pourrait être exploitable :

1. Variante 1 :
- **L'exploit** **se connecte** au service **A** et au service **B**
- Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service A que l'utilisateur ne peut pas
- Le service **A** appelle **`xpc_connection_get_audit_token`** tout en _**ne**_ étant pas à l'intérieur du **gestionnaire d'événements** pour une connexion dans un **`dispatch_async`**.
- Ainsi, un **message différent** pourrait **écraser le jeton d'audit** car il est dispatché de manière asynchrone en dehors du gestionnaire d'événements.
- L'exploit passe au **service B le droit d'ENVOYER au service A**.
- Ainsi, le svc **B** sera en fait **en train d'envoyer** les **messages** au service **A**.
- L'**exploit** essaie de **appeler** l'**action privilégiée**. Dans un RC, le svc **A** **vérifie** l'autorisation de cette **action** pendant que **svc B écrase le jeton d'audit** (donnant à l'exploit l'accès pour appeler l'action privilégiée).
2. Variante 2 :
- Le service **B** peut appeler une **fonctionnalité privilégiée** dans le service A que l'utilisateur ne peut pas
- L'exploit se connecte avec **le service A** qui **envoie** à l'exploit un **message s'attendant à une réponse** dans un **port de réponse** spécifique.
- L'exploit envoie au **service** B un message passant **ce port de réponse**.
- Lorsque le service **B répond**, il **envoie le message au service A**, **tandis que** l'**exploit** envoie un **message différent au service A** essayant d'**atteindre une fonctionnalité privilégiée** et s'attendant à ce que la réponse du service B écrase le jeton d'audit au moment parfait (Condition de course).

## Variante 1 : appel de xpc_connection_get_audit_token en dehors d'un gestionnaire d'événements <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scénario :

- Deux services mach **`A`** et **`B`** auxquels nous pouvons nous connecter (en fonction du profil de sandbox et des contrôles d'autorisation avant d'accepter la connexion).
- _**A**_ doit avoir un **contrôle d'autorisation** pour une action spécifique que **`B`** peut passer (mais notre application ne peut pas).
- Par exemple, si B a certains **droits** ou fonctionne en tant que **root**, cela pourrait lui permettre de demander à A d'effectuer une action privilégiée.
- Pour ce contrôle d'autorisation, **`A`** obtient le jeton d'audit de manière asynchrone, par exemple en appelant `xpc_connection_get_audit_token` depuis **`dispatch_async`**.

> [!CAUTION]
> Dans ce cas, un attaquant pourrait déclencher une **Condition de course** en réalisant un **exploit** qui **demande à A d'effectuer une action** plusieurs fois tout en faisant **B envoyer des messages à `A`**. Lorsque la RC est **réussie**, le **jeton d'audit** de **B** sera copié en mémoire **tandis que** la demande de notre **exploit** est en cours de **traitement** par A, lui donnant **accès à l'action privilégiée que seul B pouvait demander**.

Cela s'est produit avec **`A`** en tant que `smd` et **`B`** en tant que `diagnosticd`. La fonction [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb peut être utilisée pour installer un nouvel outil d'assistance privilégié (en tant que **root**). Si un **processus fonctionnant en tant que root contacte** **smd**, aucun autre contrôle ne sera effectué.

Par conséquent, le service **B** est **`diagnosticd`** car il fonctionne en tant que **root** et peut être utilisé pour **surveiller** un processus, donc une fois la surveillance commencée, il **enverra plusieurs messages par seconde.**

Pour effectuer l'attaque :

1. Initier une **connexion** au service nommé `smd` en utilisant le protocole XPC standard.
2. Former une **connexion** secondaire à `diagnosticd`. Contrairement à la procédure normale, plutôt que de créer et d'envoyer deux nouveaux mach ports, le droit d'envoi du port client est remplacé par un duplicata du **droit d'envoi** associé à la connexion `smd`.
3. En conséquence, les messages XPC peuvent être dispatchés à `diagnosticd`, mais les réponses de `diagnosticd` sont redirigées vers `smd`. Pour `smd`, il semble que les messages de l'utilisateur et de `diagnosticd` proviennent de la même connexion.

![Image décrivant le processus d'exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. L'étape suivante consiste à demander à `diagnosticd` de commencer à surveiller un processus choisi (potentiellement celui de l'utilisateur). En même temps, un flot de messages 1004 de routine est envoyé à `smd`. L'intention ici est d'installer un outil avec des privilèges élevés.
5. Cette action déclenche une condition de course dans la fonction `handle_bless`. Le timing est critique : l'appel de la fonction `xpc_connection_get_pid` doit renvoyer le PID du processus de l'utilisateur (car l'outil privilégié réside dans le bundle de l'application de l'utilisateur). Cependant, la fonction `xpc_connection_get_audit_token`, spécifiquement dans la sous-routine `connection_is_authorized`, doit faire référence au jeton d'audit appartenant à `diagnosticd`.

## Variante 2 : transfert de réponse

Dans un environnement XPC (Communication inter-processus), bien que les gestionnaires d'événements ne s'exécutent pas de manière concurrente, le traitement des messages de réponse a un comportement unique. Plus précisément, deux méthodes distinctes existent pour envoyer des messages qui s'attendent à une réponse :

1. **`xpc_connection_send_message_with_reply`** : Ici, le message XPC est reçu et traité sur une file d'attente désignée.
2. **`xpc_connection_send_message_with_reply_sync`** : À l'inverse, dans cette méthode, le message XPC est reçu et traité sur la file d'attente de dispatch actuelle.

Cette distinction est cruciale car elle permet la possibilité que **les paquets de réponse soient analysés de manière concurrente avec l'exécution d'un gestionnaire d'événements XPC**. Notamment, bien que `_xpc_connection_set_creds` mette en œuvre un verrouillage pour protéger contre l'écrasement partiel du jeton d'audit, il n'étend pas cette protection à l'ensemble de l'objet de connexion. Par conséquent, cela crée une vulnérabilité où le jeton d'audit peut être remplacé pendant l'intervalle entre l'analyse d'un paquet et l'exécution de son gestionnaire d'événements.

Pour exploiter cette vulnérabilité, la configuration suivante est requise :

- Deux services mach, appelés **`A`** et **`B`**, qui peuvent tous deux établir une connexion.
- Le service **`A`** doit inclure un contrôle d'autorisation pour une action spécifique que seul **`B`** peut effectuer (l'application de l'utilisateur ne peut pas).
- Le service **`A`** doit envoyer un message qui anticipe une réponse.
- L'utilisateur peut envoyer un message à **`B`** auquel il répondra.

Le processus d'exploitation implique les étapes suivantes :

1. Attendre que le service **`A`** envoie un message qui s'attend à une réponse.
2. Au lieu de répondre directement à **`A`**, le port de réponse est détourné et utilisé pour envoyer un message au service **`B`**.
3. Par la suite, un message impliquant l'action interdite est dispatché, avec l'attente qu'il soit traité de manière concurrente avec la réponse de **`B`**.

Voici une représentation visuelle du scénario d'attaque décrit :

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problèmes de découverte

- **Difficultés à localiser des instances** : La recherche d'instances d'utilisation de `xpc_connection_get_audit_token` était difficile, tant statiquement que dynamiquement.
- **Méthodologie** : Frida a été utilisée pour accrocher la fonction `xpc_connection_get_audit_token`, filtrant les appels ne provenant pas des gestionnaires d'événements. Cependant, cette méthode était limitée au processus accroché et nécessitait une utilisation active.
- **Outils d'analyse** : Des outils comme IDA/Ghidra ont été utilisés pour examiner les services mach accessibles, mais le processus était long, compliqué par les appels impliquant le cache partagé dyld.
- **Limitations de script** : Les tentatives de script de l'analyse pour les appels à `xpc_connection_get_audit_token` à partir de blocs `dispatch_async` ont été entravées par des complexités dans l'analyse des blocs et les interactions avec le cache partagé dyld.

## La solution <a href="#the-fix" id="the-fix"></a>

- **Problèmes signalés** : Un rapport a été soumis à Apple détaillant les problèmes généraux et spécifiques trouvés dans `smd`.
- **Réponse d'Apple** : Apple a abordé le problème dans `smd` en remplaçant `xpc_connection_get_audit_token` par `xpc_dictionary_get_audit_token`.
- **Nature de la solution** : La fonction `xpc_dictionary_get_audit_token` est considérée comme sécurisée car elle récupère le jeton d'audit directement à partir du message mach lié au message XPC reçu. Cependant, elle ne fait pas partie de l'API publique, tout comme `xpc_connection_get_audit_token`.
- **Absence de solution plus large** : Il reste flou pourquoi Apple n'a pas mis en œuvre une solution plus complète, comme le rejet des messages ne s'alignant pas avec le jeton d'audit enregistré de la connexion. La possibilité de changements légitimes de jeton d'audit dans certains scénarios (par exemple, l'utilisation de `setuid`) pourrait être un facteur.
- **Statut actuel** : Le problème persiste dans iOS 17 et macOS 14, posant un défi pour ceux qui cherchent à l'identifier et à le comprendre.

{{#include ../../../../../../banners/hacktricks-training.md}}
