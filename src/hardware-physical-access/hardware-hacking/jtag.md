# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Repérage des broches et configuration matérielle en toute sécurité

- Identifiez d’abord Vtref et GND avec un multimètre. De nombreux adaptateurs ont besoin de Vtref pour régler la tension des E/S.
- Adaptation de niveau : préférez les convertisseurs de niveau bidirectionnels conçus pour les signaux push-pull (les lignes JTAG ne sont pas à drain ouvert). Évitez les convertisseurs I2C à direction automatique pour JTAG.
- Adaptateurs utiles : cartes FT2232H/FT232H (par ex., Tigard), CMSIS-DAP, J-Link, ST-LINK (spécifique au fabricant), ESP-USB-JTAG (sur ESP32-Sx). Connectez au minimum TCK, TMS, TDI, TDO, GND et Vtref ; éventuellement TRST et SRST.

Pour un connecteur non documenté, identifiez GND en vérifiant la continuité avec un plan de masse connu **lorsque la cible n’est pas alimentée**. Après être passé en mode tension et avoir mis la cible sous tension, ne considérez pas toute broche à niveau haut comme Vtref : les entrées numériques à niveau haut peuvent avoir un aspect similaire au multimètre. Suivez les pistes candidates jusqu’aux condensateurs de découplage voisins et comparez leurs formes d’onde à la mise sous tension et hors tension avec un oscilloscope. Une montée ou une descente plus lente, en forme de charge de condensateur, indique qu’il pourrait s’agir d’un réseau d’alimentation ou de référence, mais vérifiez la tension et le câblage avant de connecter une sonde avec adaptation de niveau. Sur PiFex, une référence externe de tension inférieure pour la cible peut être sélectionnée via `VCCA_IN` au lieu du réglage par défaut de 3,3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** est un outil que vous pouvez charger sur un microcontrôleur compatible Arduino ou, à titre expérimental, sur un Raspberry Pi pour tester par force brute des brochages JTAG inconnus et énumérer les registres d’instructions.<sup>[[3]](#references)</sup>

- Arduino : connectez les broches numériques D2–D11 à un maximum de 10 pastilles ou points de test JTAG suspects, et la broche GND de l’Arduino à GND de la cible. Alimentez la cible séparément, sauf si vous savez que le rail est sûr. Privilégiez la logique 3,3 V (par ex., Arduino Due) ou utilisez un convertisseur de niveau/des résistances en série lors du sondage de cibles fonctionnant entre 1,8 et 3,3 V.
- Raspberry Pi : la version pour Pi expose moins de GPIO utilisables (les scans sont donc plus lents) ; consultez le dépôt pour connaître le brochage et les contraintes actuels.

Une fois le programme flashé, ouvrez le moniteur série à 115200 bauds et envoyez `h` pour obtenir de l’aide. Déroulement habituel :

- `l` rechercher les boucles de rebouclage afin d’éviter les faux positifs
- `r` activer ou désactiver les résistances de rappel internes si nécessaire
- `s` rechercher TCK/TMS/TDI/TDO (et parfois TRST/SRST)
- `y` tester par force brute l’IR pour découvrir des opcodes non documentés
- `x` capturer un instantané boundary-scan de l’état des broches

![JTAG - JTAGenum : x, instantané boundary-scan de l’état des broches](<../../images/image (939).png>)

![JTAG - JTAGenum : x, instantané boundary-scan de l’état des broches](<../../images/image (578).png>)

![JTAG - JTAGenum : x, instantané boundary-scan de l’état des broches](<../../images/image (774).png>)



Si un TAP valide est détecté, des lignes commençant par `FOUND!` indiquent les broches découvertes.

### Conseils de sécurité pour JTAGenum

- Reliez toujours les masses et ne pilotez jamais des broches inconnues avec une tension supérieure à Vtref de la cible. En cas de doute, ajoutez des résistances de 100–470 Ω en série sur les broches candidates.
- Si l’appareil utilise SWD/SWJ au lieu du JTAG à 4 fils, JTAGenum risque de ne pas le détecter ; essayez des outils SWD ou un adaptateur compatible avec SWJ-DP.

## Découverte des broches GPIO avec go-jtagenum

Sur une cible alimentée, avec une masse commune vérifiée et une tension d’E/S compatible, `go-jtagenum` peut énumérer les signaux JTAG candidats à partir des GPIO du Raspberry Pi. Le JSON `-pins` associe des étiquettes à des **numéros GPIO**, et non aux positions physiques du connecteur.<sup>[[5]](#references)</sup> Dans l’exemple du SSD, le premier scan IDCODE a également signalé une chaîne anormalement longue de valeurs changeantes : une ligne TDO candidate qui change à elle seule ne prouve pas la présence d’un TAP valide. Vérifiez à nouveau tout résultat plausible avec un scan BYPASS, qui décale un motif de bits connu de TDI vers TDO en passant par le registre bypass d’un bit.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Pour cette carte, BYPASS a confirmé `TCK=10`, `TMS=14`, `TDI=9` et `TDO=15` ; les broches supplémentaires n’étaient que des candidates **possibles** pour nTRST. Si une candidate renvoie uniquement des zéros ou un motif incohérent, vérifiez le contact, l’alimentation de la cible, les pull-ups et les délais d’horloge/réinitialisation avant de lui attribuer un signal.<sup>[[4]](#references)[[5]](#references)</sup> L’outil accepte également `-known-pins` avec `test_bypass` pour retester une correspondance récupérée.<sup>[[5]](#references)</sup>

## Caractériser un TAP non documenté avec UrJTAG

La découverte du brochage ne permet pas d’identifier les opcodes du registre d’instructions (IR) ni les largeurs des registres de données (DR) nécessaires au débogage. Avec une version d’UrJTAG compatible avec le câble GPIO du Raspberry Pi, configurez la correspondance récupérée et exécutez `idcode`, puis `detect`, puis `discover`. L’exemple SSD a renvoyé un TAP, un IR de quatre bits et différentes largeurs de DR selon les valeurs d’IR. Une longueur de DR de `-1` ou le message « TDO stuck at 0 » ne constitue pas une définition de registre exploitable ; vérifiez le timing, le câblage et l’instruction sélectionnée au lieu de lui attribuer une largeur.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Il s’agit de reconnaissance TAP, et non d’identification automatique du CPU : comparez l’IDCODE obtenu à la documentation du périphérique et aux cibles prises en charge par OpenOCD. La base de données locale des fabricants d’UrJTAG peut indiquer comme inconnu un ID pourtant valide.<sup>[[4]](#references)</sup>

## Premier contact avec OpenOCD (scan et IDCODE)

OpenOCD est l’OSS de facto pour JTAG/SWD. Avec un adaptateur pris en charge, vous pouvez scanner la chaîne et lire les IDCODE :<sup>[[1]](#references)</sup>

- Exemple générique avec un J-Link :
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG intégré à l’ESP32-S3 (aucune sonde externe requise) :<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Remarques

- Si vous obtenez un IDCODE composé uniquement de 1 ou de 0, vérifiez le câblage, l’alimentation, Vtref et que le port n’est pas verrouillé par des fusibles ou des octets d’option.
- Consultez les commandes bas niveau `irscan`/`drscan` d’OpenOCD pour interagir manuellement avec le TAP lors de la mise en service de chaînes inconnues.<sup>[[1]](#references)</sup>

## Ajouter une cible non documentée à OpenOCD

Une fois l’ID du TAP et la longueur de l’IR connus, examinez les scripts `cpu/`, `target/` et `board/` d’OpenOCD pour trouver une **architecture CPU correspondante**, puis créez des configurations distinctes pour l’adaptateur et la cible.<sup>[[4]](#references)[[6]](#references)</sup> Le mappage GPIO du Pi et la cible ARCv2 ci-dessous constituent l’exemple SSD testé, et non une configuration JTAG universelle. Le choix de la cible ARC et les paramètres de débogage étaient des hypothèses qui ont fonctionné avec cet appareil ; sur une autre carte, utilisez l’ID, la longueur de l’IR, l’architecture et les numéros GPIO mesurés pour cette cible.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Exécutez `openocd -f raspberrypi-io.cfg -f target.cfg` et confirmez que l’examen du TAP réussit avant de lire la mémoire. L’exemple ouvrait Telnet sur le port `4444` et un serveur GDB sur `3333` ; un IDCODE reconnu ne prouve pas à lui seul que la cible CPU sélectionnée peut être examinée ou déboguée.<sup>[[4]](#references)</sup> Les GPIO du Raspberry Pi ne sont pas nécessairement les broches étiquetées JTAG sur une carte breakout si l’adaptateur permet le remappage via `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Arrêt du CPU et dump de la mémoire/flash

Une fois le TAP reconnu et un script de cible choisi, vous pouvez arrêter le cœur et dumper des régions mémoire ou la flash interne. Exemples (ajustez la cible, les adresses de base et les tailles) :<sup>[[1]](#references)</sup>

- Cible générique après l’initialisation :
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (privilégier SBA si disponible) :
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmer ou lire via l’utilitaire OpenOCD :<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Conseils pour le dump mémoire

- Utilisez `mdw/mdh/mdb` pour vérifier rapidement la mémoire avant les longs dumps.
- Pour les chaînes multi-appareils, définissez BYPASS sur les appareils non ciblés ou utilisez un fichier de carte qui définit tous les TAP.

Pour une carte mémoire non documentée, la recherche sur le SSD a vérifié un dump de 1 MiB à la recherche de chaînes de contrôleur reconnaissables, puis a utilisé GDB compatible avec l’architecture via OpenOCD pour examiner `$pc`, le désassemblage et les registres. Ces adresses en direct ont guidé le dump d’une deuxième région, qui a été comparé aux instructions correspondantes dans une version de Ghidra compatible avec ARC. Les chaînes seules ne constituent qu’une vérification de plausibilité, et ne prouvent pas que l’image est complète ou correctement mappée.<sup>[[4]](#references)</sup> Consultez l’[analyse du firmware](../firmware-analysis/) pour découvrir d’autres étapes d’analyse statique.

## Astuces de boundary-scan (EXTEST/SAMPLE)

Même lorsque l’accès au débogage du CPU est verrouillé, le boundary-scan peut rester exposé. Avec UrJTAG/OpenOCD, vous pouvez :<sup>[[1]](#references)</sup>
- Utiliser SAMPLE pour capturer l’état des broches pendant l’exécution du système (repérer l’activité du bus, confirmer le brochage).
- Utiliser EXTEST pour piloter les broches (par exemple, bit-banger les lignes SPI flash externes via le MCU afin de les lire hors ligne, si le câblage de la carte le permet).

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

- Les ESP32-S3/C3 intègrent un pont USB-JTAG natif ; OpenOCD peut communiquer directement par USB sans sonde externe. Très pratique pour le triage et les dumps.<sup>[[2]](#references)</sup>
- Le debug RISC-V (v0.13+) est largement pris en charge par OpenOCD ; privilégiez le SBA pour accéder à la mémoire lorsque le cœur ne peut pas être arrêté en toute sécurité.
- De nombreux MCU implémentent l’authentification du debug et des états de cycle de vie. Si JTAG semble inactif alors que l’alimentation est correcte, le périphérique est peut-être verrouillé dans un état fermé par des fusibles ou nécessite une sonde authentifiée.

## Défenses et renforcement (à quoi s’attendre sur de vrais appareils)

- Désactiver ou verrouiller définitivement JTAG/SWD en production (p. ex., STM32 RDP niveau 2, eFuses ESP qui désactivent PAD JTAG, APPROTECT/DPAP de NXP/Nordic).
- Exiger une authentification du debug (ARMv8.2-A ADIv6 Debug Authentication, défi-réponse géré par l’OEM) tout en conservant l’accès de fabrication.
- Éviter les points de test faciles d’accès ; enfouir les vias de test, retirer/installer des résistances pour isoler le TAP, utiliser des connecteurs détrompés ou des montages à broches pogo.
- Verrouillage du debug à la mise sous tension : contrôler l’accès au TAP au moyen d’une ROM précoce qui impose le démarrage sécurisé.

## References

- [1] [Guide utilisateur OpenOCD – Commandes JTAG et configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG de l’Espressif ESP32-S3 (USB-JTAG, utilisation d’OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Scanner de brochage JTAG basé sur Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Hacking JTAG avec un Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — Énumération JTAG via GPIO](https://github.com/gremwell/go-jtagenum)
- [6] [Guide utilisateur OpenOCD — Configuration de l’adaptateur de debug](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
