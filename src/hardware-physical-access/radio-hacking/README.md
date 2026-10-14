# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Les tests de sécurité radio examinent comment un appareil transmet, reçoit et interprète les signaux sans fil. Une radio logicielle (SDR) peut aider à localiser un signal, à enregistrer des échantillons en phase/quadrature (I/Q) et à tester la démodulation et le décodage sans s’engager dans du matériel propre à un protocole.<sup>[[1]](#references)</sup>

Un workflow pratique consiste à identifier la bande de fréquences et la largeur de canal, à capturer plusieurs actions connues de l’appareil, à comparer les signaux obtenus, puis à déterminer la modulation et la structure des paquets. Ne testez le replay ou la transmission que dans un environnement isolé et sur des fréquences et équipements pour lesquels vous êtes autorisé. Les pages de cette section couvrent le RFID, le NFC, la radio sub-GHz, l’infrarouge, le BLE et les outils associés.<sup>[[1]](#references)</sup>

## Trouver l’interface pertinente

- Pour un badge d’accès ou une clé de contact, commencez par [les types de tags RFID/NFC et leurs attaques](pentesting-rfid.md), les [workflows Proxmark3](proxmark-3.md) ou les [clés iButton et 1-Wire](ibutton.md). Le [guide Flipper Zero](flipper-zero/README.md) renvoie aux actions propres à son interface.
- Pour un signal de télécommande, utilisez [la RF sub-GHz et les rolling codes](sub-ghz-rf.md) ou [les protocoles et attaques infrarouges](infrared.md).
- Pour les appareils et capteurs à proximité, utilisez les [tests de publicité BLE, GATT et mesh](pentesting-ble-bluetooth-low-energy.md) ou la [sécurité LPWAN/LoRaWAN](low-power-wide-area-network.md).
- Pour les signaux RF capturés ou inconnus, utilisez [l’analyse des signaux avec SigDigger](../hardware-hacking/radio.md#sigdigger) ou le [framework FISSURE](fissure-the-rf-framework.md).

## References

- [1] [Great Scott Gadgets - Radio logicielle avec HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
