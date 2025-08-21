# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) est un outil que vous pouvez charger sur un MCU compatible Arduino ou (expérimentalement) un Raspberry Pi pour forcer les pinouts JTAG inconnus et même énumérer les registres d'instructions.

- Arduino : connectez les broches numériques D2–D11 à jusqu'à 10 pads/testpoints JTAG suspects, et GND Arduino à GND cible. Alimentez la cible séparément à moins que vous ne sachiez que le rail est sûr. Préférez la logique 3,3 V (par exemple, Arduino Due) ou utilisez un convertisseur de niveau/résistances en série lors de la sonde des cibles 1,8–3,3 V.
- Raspberry Pi : la version Pi expose moins de GPIO utilisables (donc les scans sont plus lents) ; vérifiez le dépôt pour la carte des broches actuelle et les contraintes.

Une fois flashé, ouvrez le moniteur série à 115200 bauds et envoyez `h` pour obtenir de l'aide. Flux typique :

- `l` trouver les boucles de retour pour éviter les faux positifs
- `r` basculer les pull-ups internes si nécessaire
- `s` scanner pour TCK/TMS/TDI/TDO (et parfois TRST/SRST)
- `y` forcer IR pour découvrir des opcodes non documentés
- `x` instantané de scan de frontière des états des broches

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



Si un TAP valide est trouvé, vous verrez des lignes commençant par `FOUND!` indiquant les broches découvertes.

Conseils
- Partagez toujours la masse, et ne jamais alimenter des broches inconnues au-dessus de Vtref cible. En cas de doute, ajoutez des résistances en série de 100–470 Ω sur les broches candidates.
- Si le dispositif utilise SWD/SWJ au lieu de JTAG à 4 fils, JTAGenum peut ne pas le détecter ; essayez des outils SWD ou un adaptateur qui prend en charge SWJ‑DP.

## Chasse aux broches plus sûre et configuration matérielle

- Identifiez d'abord Vtref et GND avec un multimètre. De nombreux adaptateurs ont besoin de Vtref pour définir la tension I/O.
- Conversion de niveau : préférez les convertisseurs de niveau bidirectionnels conçus pour les signaux push-pull (les lignes JTAG ne sont pas à drain ouvert). Évitez les convertisseurs I2C à direction automatique pour JTAG.
- Adaptateurs utiles : cartes FT2232H/FT232H (par exemple, Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (spécifique au fournisseur), ESP‑USB‑JTAG (sur ESP32‑Sx). Connectez au minimum TCK, TMS, TDI, TDO, GND et Vtref ; TRST et SRST en option.

## Premier contact avec OpenOCD (scan et IDCODE)

OpenOCD est le OSS de facto pour JTAG/SWD. Avec un adaptateur pris en charge, vous pouvez scanner la chaîne et lire les IDCODEs :

- Exemple générique avec un J‑Link :
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 USB‑JTAG intégré (aucun sonde externe requise) :
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- Si vous obtenez un IDCODE "tous les uns/zéros", vérifiez le câblage, l'alimentation, Vtref, et que le port n'est pas verrouillé par des fusibles/bytes d'option.
- Voir OpenOCD bas niveau `irscan`/`drscan` pour une interaction manuelle TAP lors de la mise en route de chaînes inconnues.

## Arrêt du CPU et vidage de la mémoire/flash

Une fois que le TAP est reconnu et qu'un script cible est choisi, vous pouvez arrêter le cœur et vider les régions de mémoire ou la flash interne. Exemples (ajuster la cible, les adresses de base et les tailles) :

- Cible générique après init :
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (préférer SBA lorsque disponible) :
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmer ou lire via l'assistant OpenOCD :
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Utilisez `mdw/mdh/mdb` pour vérifier la mémoire avant de faire de longs dumps.
- Pour les chaînes multi-appareils, définissez BYPASS sur les non-cibles ou utilisez un fichier de carte qui définit tous les TAPs.

## Astuces de scan de frontière (EXTEST/SAMPLE)

Même lorsque l'accès de débogage du CPU est verrouillé, le scan de frontière peut encore être exposé. Avec UrJTAG/OpenOCD, vous pouvez :
- SAMPLE pour prendre un instantané des états des broches pendant que le système fonctionne (trouver l'activité du bus, confirmer le mappage des broches).
- EXTEST pour piloter des broches (par exemple, bit-bang des lignes SPI flash externes via le MCU pour les lire hors ligne si le câblage de la carte le permet).

Flux minimal UrJTAG avec un adaptateur FT2232x :
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Vous avez besoin du BSDL de l'appareil pour connaître l'ordre des bits des registres de frontière. Attention, certains fournisseurs verrouillent les cellules de scan de frontière en production.

## Cibles modernes et notes

- ESP32‑S3/C3 incluent un pont USB‑JTAG natif ; OpenOCD peut communiquer directement via USB sans sonde externe. Très pratique pour le triage et les dumps.
- Le débogage RISC‑V (v0.13+) est largement supporté par OpenOCD ; préférez SBA pour l'accès mémoire lorsque le cœur ne peut pas être arrêté en toute sécurité.
- De nombreux MCU mettent en œuvre l'authentification de débogage et les états de cycle de vie. Si le JTAG semble mort mais que l'alimentation est correcte, l'appareil peut être fusionné dans un état fermé ou nécessite une sonde authentifiée.

## Défenses et durcissement (à quoi s'attendre sur des appareils réels)

- Désactivez ou verrouillez définitivement le JTAG/SWD en production (par exemple, niveau 2 RDP STM32, eFuses ESP qui désactivent PAD JTAG, APPROTECT/DPAP NXP/Nordic).
- Exigez une authentification de débogage (ARMv8.2‑A ADIv6 Authentification de débogage, défi-réponse géré par l'OEM) tout en maintenant l'accès à la fabrication.
- Ne pas acheminer de pads de test faciles ; enterrez les vias de test, retirez/remplissez les résistances pour isoler le TAP, utilisez des connecteurs avec clé ou des dispositifs à broches pogo.
- Verrouillage de débogage à l'alimentation : placez le TAP derrière un ROM précoce imposant un démarrage sécurisé.

## Références

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
