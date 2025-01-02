# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

**Apple Events** sont une fonctionnalité du macOS d'Apple qui permet aux applications de communiquer entre elles. Ils font partie du **Apple Event Manager**, qui est un composant du système d'exploitation macOS responsable de la gestion de la communication interprocessus. Ce système permet à une application d'envoyer un message à une autre application pour demander qu'elle effectue une opération particulière, comme ouvrir un fichier, récupérer des données ou exécuter une commande.

Le démon mina est `/System/Library/CoreServices/appleeventsd` qui enregistre le service `com.apple.coreservices.appleevents`.

Chaque application capable de recevoir des événements vérifiera avec ce démon en fournissant son Apple Event Mach Port. Et lorsque qu'une application souhaite envoyer un événement, elle demandera ce port au démon.

Les applications en bac à sable nécessitent des privilèges comme `allow appleevent-send` et `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` afin de pouvoir envoyer des événements. Notez que des droits comme `com.apple.security.temporary-exception.apple-events` pourraient restreindre qui a accès pour envoyer des événements, ce qui nécessitera des droits comme `com.apple.private.appleevents`.

> [!TIP]
> Il est possible d'utiliser la variable d'environnement **`AEDebugSends`** afin de consigner des informations sur le message envoyé :
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
