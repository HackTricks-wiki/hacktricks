# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Pour plus d'informations sur le fonctionnement de l'Infrared, consultez :


{{#ref}}
../infrared.md
{{#endref}}

## Récepteur de signal IR dans Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utilise un récepteur de signal IR numérique TSOP, qui **permet d'intercepter les signaux des télécommandes IR**. Certains **smartphones**, comme Xiaomi, disposent également d'un port IR, mais gardez à l'esprit que **la plupart d'entre eux peuvent uniquement transmettre** des signaux et sont **incapables de les recevoir**.<sup>[[1]](#references)</sup>

Le **récepteur infrarouge de Flipper est très sensible**. Vous pouvez même **capter le signal** en restant **quelque part entre** la télécommande et le téléviseur. Il n'est pas nécessaire de pointer directement la télécommande vers le port IR de Flipper. Cela peut être utile lorsqu'une personne change de chaîne en se tenant près du téléviseur, tandis que vous et Flipper vous trouvez à une certaine distance.

Comme le **décodage du signal infrarouge** s'effectue du côté **logiciel**, Flipper Zero prend potentiellement en charge **la réception et la transmission de tous les codes de télécommandes IR**. Dans le cas de protocoles **inconnus** qui ne peuvent pas être reconnus, il **enregistre et restitue** le signal brut exactement tel qu'il a été reçu.<sup>[[1]](#references)</sup>

## Actions

### Télécommandes universelles

Flipper Zero peut être utilisé comme **télécommande universelle pour contrôler n'importe quel téléviseur, climatiseur ou centre multimédia**. Dans ce mode, Flipper **bruteforce** tous les **codes connus** de tous les fabricants pris en charge **selon le dictionnaire présent sur la carte SD**. Vous n'avez pas besoin de choisir une télécommande particulière pour éteindre le téléviseur d'un restaurant.<sup>[[1]](#references)</sup>

Il suffit d'appuyer sur le bouton d'alimentation en mode Universal Remote, et Flipper enverra **séquentiellement les commandes « Power Off »** de tous les téléviseurs qu'il connaît : Sony, Samsung, Panasonic... et ainsi de suite. Lorsque le téléviseur reçoit son signal, il réagit et s'éteint.

Un tel bruteforce prend du temps. Plus le dictionnaire est volumineux, plus il faudra de temps pour terminer. Il est impossible de savoir quel signal précis le téléviseur a reconnu, puisqu'il ne fournit aucun retour.

### Apprendre une nouvelle télécommande

Il est possible de **capturer un signal infrarouge** avec Flipper Zero. S'il **trouve le signal dans la base de données**, Flipper **saura automatiquement de quel appareil il s'agit** et vous permettra d'interagir avec celui-ci.\
Dans le cas contraire, Flipper peut **stocker** le **signal** et vous permettre de **le rejouer**.<sup>[[1]](#references)</sup>

## Références

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
