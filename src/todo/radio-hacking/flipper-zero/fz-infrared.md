# FZ - Infrarouge

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Pour plus d'informations sur le fonctionnement de l'infrarouge, consultez :


{{#ref}}
../infrared.md
{{#endref}}

## Récepteur de signal IR dans Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero utilise un récepteur IR démodulant pour capturer les signaux des télécommandes IR courantes. Certains téléphones, notamment certains modèles Xiaomi, intègrent un émetteur IR, mais la plupart ne peuvent pas recevoir et décoder les signaux des télécommandes.<sup>[[1]](#references)</sup>

Le **récepteur infrarouge de Flipper est très sensible**. Vous pouvez même **intercepter le signal** en restant **quelque part entre** la télécommande et le téléviseur. Il n'est pas nécessaire de pointer directement la télécommande vers le port IR de Flipper. Cela peut être utile lorsqu'une personne change de chaîne en se tenant près du téléviseur, tandis que vous et Flipper êtes à une certaine distance.

Le décodage du protocole s'effectue dans le software. Les protocoles reconnus peuvent être enregistrés sous forme de commandes décodées ; les protocoles non pris en charge peuvent être capturés et rejoués en tant que données de timing brutes, dans les limites de la fréquence porteuse et du timing du hardware.<sup>[[1]](#references)</sup>

## Actions

### Télécommandes universelles

Le mode télécommande universelle de Flipper Zero parcourt les commandes connues de sa base de données infrarouge pour les téléviseurs, équipements audio, projecteurs et climatiseurs pris en charge. Il n'est pas garanti qu'il puisse contrôler tous les appareils et doit être utilisé uniquement sur des équipements que vous possédez ou que vous êtes autorisé à tester.<sup>[[1]](#references)</sup>

Il suffit d'appuyer sur le bouton d'alimentation en mode Universal Remote pour que Flipper **envoie séquentiellement les commandes "Power Off"** de tous les téléviseurs qu'il connaît : Sony, Samsung, Panasonic... et ainsi de suite. Lorsque le téléviseur reçoit son signal, il réagit et s'éteint.

Un tel brute-force prend du temps. Plus le dictionnaire est volumineux, plus son exécution sera longue. Il est impossible de savoir quel signal exactement le téléviseur a reconnu, car celui-ci ne fournit aucun retour.

### Apprendre une nouvelle télécommande

Flipper Zero peut **capturer un signal infrarouge**. S'il reconnaît le protocole et la commande, il enregistre une représentation décodée ; sinon, il peut enregistrer les données de timing brutes pour une relecture ultérieure.<sup>[[1]](#references)</sup>

## References

- [1] [Prendre le contrôle de téléviseurs avec le port infrarouge de Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
