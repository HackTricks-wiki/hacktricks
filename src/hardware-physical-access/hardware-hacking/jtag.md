# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** est un outil que vous pouvez charger sur un MCU compatible Arduino ou, à titre expérimental, sur un Raspberry Pi afin de forcer par brute force des brochages JTAG inconnus et d’énumérer les registres d’instructions.<sup>[[3]](#references)</sup>

- Arduino : connectez les broches numériques D2–D11 à un maximum de 10 pastilles/points de test JTAG potentiels, et la broche GND de l’Arduino à la masse de la cible. Alimentez la cible séparément, sauf si vous savez que le rail est sûr. Privilégiez une logique 3,3 V (par exemple, Arduino Due) ou utilisez un convertisseur de niveau/des résistances en série pour sonder des cibles de 1,8–3,3 V.
- Raspberry Pi : la version pour Pi expose moins de GPIO utilisables (les scans sont donc plus lents) ; consultez le dépôt pour connaître le brochage et les contraintes à jour.

Une fois le programme flashé, ouvrez le moniteur série à 115200 bauds et envoyez `h` pour afficher l’aide. Déroulement typique :

- `l` trouver les loopbacks pour éviter les faux positifs
- `r` activer/désactiver les pull-ups internes si nécessaire
- `s` rechercher TCK/TMS/TDI/TDO (et parfois TRST/SRST)
- `y` forcer par brute force l’IR afin de découvrir des opcodes non documentés
- `x` prendre un instantané boundary-scan de l’état des broches

![JTAG - JTAGenum: x boundary-scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snapshot of pin states](<../../images/image (774).png>)



Si un TAP valide est détecté, des lignes commençant par `FOUND!` indiquent les broches découvertes.

### Conseils de sécurité pour JTAGenum

- Reliez toujours les masses et ne pilotez jamais des broches inconnues à une tension supérieure à Vtref de la cible. En cas de doute, ajoutez des résistances de 100–470 Ω en série sur les broches candidates.
- Si l’appareil utilise SWD/SWJ au lieu du JTAG à 4 fils, JTAGenum risque de ne pas le détecter ; essayez des outils SWD ou un adaptateur compatible avec SWJ-DP.

## Recherche plus sûre des broches et configuration matérielle

- Identifiez d’abord Vtref et GND avec un multimètre. De nombreux adaptateurs ont besoin de Vtref pour régler la tension des E/S.
- Adaptation de niveau : privilégiez des convertisseurs de niveau bidirectionnels conçus pour les signaux push-pull (les lignes JTAG ne sont pas à drain ouvert). Évitez les convertisseurs I2C à direction automatique pour le JTAG.
- Adaptateurs utiles : cartes FT2232H/FT232H (par exemple, Tigard), CMSIS-DAP, J-Link, ST-LINK (spécifique au fabricant), ESP-USB-JTAG (sur ESP32-Sx). Connectez au minimum TCK, TMS, TDI, TDO, GND et Vtref ; TRST et SRST sont facultatifs.

## Premier contact avec OpenOCD (scan et IDCODE)

OpenOCD est l’OSS de facto pour JTAG/SWD. Avec un adaptateur pris en charge, vous pouvez scanner la chaîne et lire les IDCODE :<sup>[[1]](#references)</sup>

- Exemple générique avec un J-Link :
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG intégré à l’ESP32-S3 (aucune sonde externe requise) :<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Remarques

- Si vous obtenez un IDCODE composé uniquement de 1 ou de 0, vérifiez le câblage, l’alimentation, Vtref et que le port n’est pas verrouillé par des fusibles/option bytes.
- Consultez les commandes bas niveau `irscan`/`drscan` d’OpenOCD pour interagir manuellement avec le TAP lors de la mise en service de chaînes inconnues.<sup>[[1]](#references)</sup>

## Arrêter le CPU et dumper la mémoire/flash

Une fois le TAP reconnu et le script de cible choisi, vous pouvez arrêter le cœur et dumper des régions mémoire ou la flash interne. Exemples (ajustez la cible, les adresses de base et les tailles) :<sup>[[1]](#references)</sup>

- Cible générique après l’initialisation :
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (privilégier SBA lorsqu’il est disponible) :
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmer ou lire via l’utilitaire OpenOCD :<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Conseils pour le dump de mémoire

- Utilisez `mdw/mdh/mdb` pour vérifier rapidement la mémoire avant les longs dumps.
- Pour les chaînes multi-périphériques, définissez BYPASS sur les périphériques qui ne sont pas des cibles ou utilisez un fichier de carte qui définit tous les TAP.

## Astuces de boundary-scan (EXTEST/SAMPLE)

Même lorsque l’accès de débogage du CPU est verrouillé, le boundary-scan peut rester exposé. Avec UrJTAG/OpenOCD, vous pouvez :<sup>[[1]](#references)</sup>
- Utiliser SAMPLE pour capturer l’état des broches pendant l’exécution du système (repérer l’activité du bus, confirmer le brochage).
- Utiliser EXTEST pour piloter les broches (par ex., utiliser le bit-banging pour piloter les lignes d’une mémoire flash SPI externe via le MCU afin de la lire hors ligne, si le câblage de la carte le permet).

Flux UrJTAG minimal avec un adaptateur FT2232x :
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Vous avez besoin du BSDL du périphérique pour connaître l’ordre des bits du registre boundary. Attention : certains fabricants verrouillent les cellules boundary-scan en production.

## Cibles modernes et remarques

- Les ESP32‑S3/C3 intègrent un pont USB‑JTAG natif ; OpenOCD peut communiquer directement via USB, sans sonde externe. Très pratique pour le triage et les dumps.<sup>[[2]](#references)</sup>
- Le debug RISC‑V (v0.13+) est largement pris en charge par OpenOCD ; préférez SBA pour l’accès mémoire lorsque le cœur ne peut pas être arrêté en toute sécurité.
- De nombreux MCU implémentent une authentification du debug et des états de cycle de vie. Si JTAG semble inactif alors que l’alimentation est correcte, le périphérique est peut-être fusé en état fermé ou nécessite une sonde authentifiée.

## Défenses et renforcement (à quoi s’attendre sur les appareils réels)

- Désactivez ou verrouillez définitivement JTAG/SWD en production (par exemple, STM32 RDP niveau 2, eFuses ESP qui désactivent PAD JTAG, APPROTECT/DPAP NXP/Nordic).
- Exigez une authentification du debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response géré par l’OEM) tout en conservant l’accès à la fabrication.
- Évitez les points de test faciles d’accès ; enterrez les vias de test, retirez/installez des résistances pour isoler le TAP, utilisez des connecteurs détrompés ou des montages à pogo pins.
- Verrouillage du debug à la mise sous tension : placez le TAP derrière la ROM de démarrage précoce, qui applique le démarrage sécurisé.

## References

- [1] [Guide de l’utilisateur d’OpenOCD – Commandes JTAG et configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG de l’Espressif ESP32‑S3 (USB‑JTAG, utilisation d’OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Scanner de brochage JTAG basé sur Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
