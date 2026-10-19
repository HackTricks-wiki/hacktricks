# Piratage radio

{{#include ../../banners/hacktricks-training.md}}

Les tests de sécurité radio examinent la façon dont un appareil transmet, reçoit et interprète les signaux sans fil. Une radio logicielle (SDR) peut aider à localiser un signal, à enregistrer des échantillons en phase/quadrature (I/Q) et à tester la démodulation et le décodage sans s’engager dans du matériel spécifique à un protocole.<sup>[[1]](#references)</sup>

Une méthode pratique consiste à identifier la bande de fréquences et la largeur du canal, à capturer plusieurs actions connues de l’appareil, à comparer les signaux obtenus, puis à déterminer la modulation et la structure des paquets. Ne testez la relecture ou la transmission que dans un environnement isolé, sur des fréquences et avec du matériel pour lesquels vous êtes autorisé. Les pages de cette section couvrent le RFID, le NFC, les radiofréquences sub-GHz, l’infrarouge, le BLE et les outils associés.<sup>[[1]](#references)</sup>

## Trouver l’interface appropriée

- Pour un badge d’accès ou une clé de contact, commencez par [les types de tags RFID/NFC et les attaques](pentesting-rfid.md), [les méthodes de travail avec Proxmark3](proxmark-3.md) ou [les clés iButton et 1-Wire](ibutton.md). Le [guide Flipper Zero](flipper-zero/README.md) présente les actions propres à son interface.
- Pour un signal de télécommande, consultez [les radiofréquences sub-GHz et les codes tournants](sub-ghz-rf.md) ou [les protocoles infrarouges et les attaques](infrared.md).
- Pour les appareils et capteurs proches, consultez [les tests de publicité BLE, GATT et mesh](pentesting-ble-bluetooth-low-energy.md) ou [la sécurité LPWAN/LoRaWAN](low-power-wide-area-network.md).
- Pour les signaux RF capturés ou inconnus, consultez [l’analyse de signaux avec SigDigger](../hardware-hacking/radio.md#sigdigger) ou [le framework FISSURE](fissure-the-rf-framework.md).
- Pour les liaisons descendantes des terminaux satellites, consultez [l’injection de signal sur la liaison montante VSAT](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Radio logicielle avec HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
