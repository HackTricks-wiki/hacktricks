# FZ - Infrarouge

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Pour en savoir plus sur le fonctionnement de l’infrarouge, consultez :


{{#ref}}
../infrared.md
{{#endref}}

## Récepteur de signal IR dans Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero utilise un récepteur IR démodulant pour capturer les signaux des télécommandes IR courantes. Certains téléphones, notamment certains modèles Xiaomi, sont équipés d’un émetteur IR, mais la plupart ne peuvent pas recevoir et décoder les signaux des télécommandes.<sup>[[1]](#references)</sup>

Le **récepteur infrarouge de Flipper est très sensible**. Vous pouvez même **capter le signal** en vous tenant **quelque part entre** la télécommande et le téléviseur. Il n’est pas nécessaire de pointer la télécommande directement vers le port IR de Flipper. C’est pratique lorsque quelqu’un change de chaîne à proximité du téléviseur, alors que vous et Flipper vous trouvez à une certaine distance.

Le décodage des protocoles est effectué par logiciel. Les protocoles reconnus peuvent être enregistrés sous forme de commandes décodées ; les protocoles non pris en charge peuvent être capturés et rejoués sous forme de données de timing brutes, dans les limites de fréquence porteuse et de timing du matériel.<sup>[[1]](#references)</sup>

## Actions

### Télécommandes universelles

Le mode télécommande universelle de Flipper Zero parcourt les commandes connues de sa base de données infrarouge pour les téléviseurs, équipements audio, projecteurs et climatiseurs pris en charge. Il ne peut pas contrôler tous les appareils, et doit être utilisé uniquement sur du matériel qui vous appartient ou que vous êtes autorisé à tester.<sup>[[1]](#references)</sup>

Il suffit d’appuyer sur le bouton d’alimentation en mode télécommande universelle pour que Flipper envoie **séquentiellement les commandes « Power Off »** de tous les téléviseurs qu’il connaît : Sony, Samsung, Panasonic... et ainsi de suite. Lorsque le téléviseur reçoit le signal, il réagit et s’éteint.

Cette méthode de brute-force prend du temps. Plus le dictionnaire est volumineux, plus l’opération prendra du temps. Il est impossible de savoir exactement quel signal le téléviseur a reconnu, puisqu’il ne renvoie aucun retour.

### Apprendre une nouvelle télécommande

Flipper Zero peut **capturer un signal infrarouge**. S’il reconnaît le protocole et la commande, il enregistre une représentation décodée ; sinon, il peut enregistrer les données de timing brutes pour les rejouer ultérieurement.<sup>[[1]](#references)</sup>

## References

- [1] [Prendre le contrôle des téléviseurs avec le port infrarouge de Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
