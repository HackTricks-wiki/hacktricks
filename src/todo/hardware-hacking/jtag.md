# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** est un outil que vous pouvez charger sur un MCU compatible Arduino ou, à titre expérimental, sur un Raspberry Pi afin de brute-force des pinouts JTAG inconnus et d'énumérer les registres d'instructions.<sup>[[3]](#references)</sup>

- Arduino : connectez les broches numériques D2–D11 à jusqu'à 10 pads/testpoints JTAG suspects, et la masse GND de l'Arduino à la masse GND de la cible. Alimentez séparément la cible, sauf si vous savez que le rail est sûr. Privilégiez une logique 3,3 V (par exemple, Arduino Due) ou utilisez un level shifter/des résistances en série lors du sondage de cibles en 1,8–3,3 V.
- Raspberry Pi : la build pour Pi expose moins de GPIO utilisables (les scans sont donc plus lents) ; consultez le repo pour connaître le mapping actuel des broches et les contraintes.

Une fois le firmware chargé, ouvrez le moniteur série à 115200 bauds et envoyez `h` pour obtenir de l'aide. Flux typique :

- `l` rechercher les loopbacks afin d'éviter les faux positifs
- `r` basculer les pull-ups internes si nécessaire
- `s` scanner TCK/TMS/TDI/TDO (et parfois TRST/SRST)
- `y` brute-force de l'IR pour découvrir des opcodes non documentés
- `x` snapshot boundary-scan de l'état des broches

![JTAG - JTAGenum : x snapshot boundary-scan de l'état des broches](<../../images/image (939).png>)

![JTAG - JTAGenum : x snapshot boundary-scan de l'état des broches](<../../images/image (578).png>)

![JTAG - JTAGenum : x snapshot boundary-scan de l'état des broches](<../../images/image (774).png>)



Si un TAP valide est trouvé, vous verrez des lignes commençant par `FOUND!`, indiquant les broches découvertes.

### Conseils de sécurité pour JTAGenum

- Partagez toujours la masse et ne forcez jamais des broches inconnues au-dessus de Vtref de la cible. En cas de doute, ajoutez des résistances de 100–470 Ω en série sur les broches candidates.
- Si le périphérique utilise SWD/SWJ au lieu du JTAG à 4 fils, JTAGenum peut ne pas le détecter ; essayez des outils SWD ou un adaptateur prenant en charge SWJ-DP.

## Recherche plus sûre des broches et configuration matérielle

- Identifiez d'abord Vtref et GND avec un multimètre. De nombreux adaptateurs ont besoin de Vtref pour régler la tension des E/S.
- Level shifting : privilégiez les level shifters bidirectionnels conçus pour les signaux push-pull (les lignes JTAG ne sont pas open-drain). Évitez les shifters I2C à direction automatique pour le JTAG.
- Adaptateurs utiles : cartes FT2232H/FT232H (par exemple, Tigard), CMSIS-DAP, J-Link, ST-LINK (spécifique au vendor), ESP-USB-JTAG (sur ESP32-Sx). Connectez au minimum TCK, TMS, TDI, TDO, GND et Vtref ; TRST et SRST sont optionnels.

## Premier contact avec OpenOCD (scan et IDCODE)

OpenOCD est l'OSS de facto pour JTAG/SWD. Avec un adaptateur pris en charge, vous pouvez scanner la chaîne et lire les IDCODEs :<sup>[[1]](#references)</sup>

- Exemple générique avec un J-Link :
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB-JTAG intégré à l’ESP32‑S3 (aucune sonde externe requise) :<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notes

- Si vous obtenez un IDCODE composé uniquement de uns/zéros, vérifiez le câblage, l’alimentation, Vtref et que le port n’est pas verrouillé par des fuses/option bytes.
- Consultez `irscan`/`drscan` low-level d’OpenOCD pour une interaction manuelle avec le TAP lors de la mise en service de chaînes inconnues.<sup>[[1]](#references)</sup>

## Arrêter le CPU et dumper la mémoire/flash

Une fois le TAP reconnu et un target script sélectionné, vous pouvez arrêter le core et dumper des régions mémoire ou la flash interne. Exemples (ajustez la target, les adresses de base et les tailles) :<sup>[[1]](#references)</sup>

- Target générique après l’init :
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (préférer SBA lorsqu’il est disponible) :
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmer ou lire via l'outil auxiliaire OpenOCD :<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Astuces de memory dumping

- Utilisez `mdw/mdh/mdb` pour vérifier la cohérence de la mémoire avant les dumps prolongés.
- Pour les chaînes multi-device, définissez BYPASS sur les cibles non visées ou utilisez un fichier de board qui définit tous les TAPs.

## Astuces de boundary-scan (EXTEST/SAMPLE)

Même lorsque l’accès au debug du CPU est verrouillé, le boundary-scan peut rester exposé. Avec UrJTAG/OpenOCD, vous pouvez :<sup>[[1]](#references)</sup>
- Utiliser SAMPLE pour capturer l’état des broches pendant l’exécution du système (détecter l’activité du bus, confirmer le mapping des broches).
- Utiliser EXTEST pour piloter les broches (par exemple, faire du bit-banging sur les lignes d’une flash SPI externe via le MCU afin de la lire offline si le câblage de la board le permet).

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
Vous avez besoin du BSDL du device pour connaître l’ordre des bits du boundary register. Attention : certains vendors verrouillent les cellules boundary-scan en production.

## Cibles modernes et notes

- Les ESP32-S3/C3 incluent un bridge USB-JTAG natif ; OpenOCD peut communiquer directement via USB sans probe externe. Très pratique pour le triage et les dumps.<sup>[[2]](#references)</sup>
- Le debug RISC-V (v0.13+) est largement supporté par OpenOCD ; préférez le SBA pour l’accès mémoire lorsque le core ne peut pas être arrêté sans risque.
- De nombreux MCU implémentent une authentification du debug et des états de lifecycle. Si JTAG semble inactif alors que l’alimentation est correcte, le device peut être fused dans un état fermé ou nécessiter un probe authentifié.

## Défenses et hardening (à prévoir sur les devices réels)

- Désactiver ou verrouiller définitivement JTAG/SWD en production (par exemple, STM32 RDP niveau 2, eFuses ESP qui désactivent PAD JTAG, APPROTECT/DPAP NXP/Nordic).
- Exiger un debug authentifié (ARMv8.2-A ADIv6 Debug Authentication, challenge-response géré par l’OEM) tout en conservant l’accès de production.
- Ne pas router de test pads facilement accessibles ; enterrer les test vias, retirer/installer des résistances pour isoler le TAP, utiliser des connecteurs avec détrompage ou des fixtures à pogo pins.
- Verrouillage du debug à la mise sous tension : placer le TAP derrière une ROM précoce qui impose le secure boot.

## References

- [1] [Guide utilisateur OpenOCD – commandes et configuration JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG de l’Espressif ESP32-S3 (USB-JTAG, utilisation d’OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – scanner de pinout JTAG basé sur Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
