# Apple Events macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Les **Apple Events** sont une fonctionnalité de macOS d'Apple qui permet aux applications de communiquer entre elles. Ils font partie de l'**Apple Event Manager**, un composant du système d'exploitation macOS chargé de gérer la communication interprocessus. Ce système permet à une application d'envoyer un message à une autre application afin de lui demander d'effectuer une opération particulière, comme ouvrir un fichier, récupérer des données ou exécuter une commande.

Le daemon principal est `/System/Library/CoreServices/appleeventsd`, qui enregistre le service `com.apple.coreservices.appleevents`.

Chaque application capable de recevoir des événements s'enregistre auprès de ce daemon en lui fournissant son Apple Event Mach Port. Lorsqu'une application souhaite lui envoyer un événement, elle demande ce port au daemon.

Les applications sandboxées nécessitent des privilèges tels que `allow appleevent-send` et `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` pour pouvoir envoyer des événements. Notez que des entitlements comme `com.apple.security.temporary-exception.apple-events` peuvent restreindre les personnes autorisées à envoyer des événements, ce qui nécessite des entitlements comme `com.apple.private.appleevents`.

> [!TIP]
> Il est possible d'utiliser la variable d'environnement **`AEDebugSends`** afin de journaliser des informations sur le message envoyé :
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
