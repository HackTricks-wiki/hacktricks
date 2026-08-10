# Touches USB

Si vous avez un pcap contenant la communication via USB d'un clavier comme celui présenté ci-dessous :

![Touches USB : si vous avez un pcap contenant la communication via USB d'un clavier comme celui présenté ci-dessous](<../../../images/image (962).png>)

Pour un clavier utilisant le **boot protocol** HID, chaque rapport Interrupt IN possède une structure fixe de 8 octets : un octet de modificateur, un octet réservé et six octets de keycode. L'hôte compare les rapports successifs et fait correspondre les keycodes aux usages HID afin de reconstituer les événements clavier.<sup>[[8]](#references)</sup>

## Principes de base des rapports USB HID

Le rapport d'entrée standard d'un clavier boot est structuré comme suit.<sup>[[8]](#references)[[9]](#references)</sup>

| Octet | Signification |
| --- | --- |
| 0 | Bitmap des modificateurs (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, etc.). Plusieurs bits peuvent être définis simultanément. |
| 1 | Octet réservé ; les rapports inutilisés doivent normalement le définir à zéro. Une utilisation spécifique à un OEM ou à un système n'est pas portable. |
| 2-7 | Jusqu'à six keycodes simultanés au format USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` signifie « aucune touche ». |

Dans la structure boot, l'usage ID `0x01` (`Keyboard ErrorRollOver`) est signalé dans tous les emplacements de touche lorsque plus de six touches non-modificatrices sont pressées ; il peut également signaler une combinaison non reconnaissable.<sup>[[8]](#references)[[9]](#references)</sup> Comprendre cette structure est utile lorsque vous ne disposez que des octets bruts `usb.capdata`.

## Extraction des données HID à partir d'un PCAP

### Identifier d'abord l'interface du clavier

Dans les captures chargées, identifiez le clavier HID avant d'extraire les rapports. Un point de départ fiable est la réponse du descripteur d'interface :<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
La classe HID définit ces valeurs d’interface :<sup>[[8]](#references)</sup>

- `subclass == 1` correspond au Boot Interface Subclass ; avec `protocol == 1`, il identifie un boot keyboard
- `protocol == 2` identifie une boot mouse
- `protocol == 0` signifie qu’aucun boot protocol n’est utilisé ; inspectez plutôt le HID report descriptor au lieu de supposer une disposition de 8 octets

Une fois l’interface identifiée, limitez vos filtres à `usb.bus_id`, `usb.device_address` et, si possible, `usb.bInterfaceNumber` avant toute exportation.

### Flux de travail Wireshark

1. **Isoler le périphérique** : filtrez le trafic interrupt IN du clavier, par exemple `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Ajouter des colonnes utiles** : cliquez avec le bouton droit sur le champ `Leftover Capture Data` (`usb.capdata`) et sur les champs `usbhid.*` de votre choix (par exemple `usbhid.boot_report.keyboard.keycode_1`) afin de suivre les frappes sans ouvrir chaque frame.<sup>[[11]](#references)</sup>
3. **Masquer les reports vides** : appliquez `!(usb.capdata == 00:00:00:00:00:00:00:00)` pour supprimer les frames inactives.
4. **Exporter pour le post-traitement** : `File -> Export Packet Dissections -> As CSV`, en incluant `frame.number`, `usb.src`, `usb.capdata` et les champs de modificateurs décodés tels que `usbhid.boot_report.keyboard.modifier.left_shift` et `usbhid.boot_report.keyboard.modifier.right_alt`, afin de pouvoir automatiser la reconstruction ultérieurement.<sup>[[10]](#references)[[11]](#references)</sup>

### Flux de travail en ligne de commande

Le schéma d’extraction classique — extraire `usb.capdata`, supprimer les reports inactifs et mapper les usage IDs — apparaît dans l’analyse originale de 2017 et dans son walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

Le dépôt `ctf-usb-keyboard-parser` automatise le pipeline classique tshark + sed :<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Sur les captures plus récentes, privilégiez le champ décodé `usbhid.data` de Wireshark et utilisez `usb.capdata` en secours ; écrivez un payload par rapport dans un fichier par périphérique :<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Ces fichiers par périphérique peuvent être transmis à un décodeur après normalisation du format hexadécimal attendu. Si la capture provient de claviers BLE encapsulés via GATT, filtrez avec `btatt.value && frame.len == 20` et exportez les payloads hexadécimaux avant le décodage.<sup>[[7]](#references)</sup>

### Lorsque le rapport n'est pas le rapport boot classique de 8 octets

Une interface non-boot ou un report ID peut modifier la disposition du payload ; ne supposez donc pas que chaque rapport de clavier correspond à `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Préférez `usbhid.data` à `usb.capdata` lorsque Wireshark a déjà parsé la couche HID.
- Si chaque ligne commence par un préfixe constant ou un report ID, supprimez-le avec un décodeur prenant en compte l'offset, plutôt que de supposer que l'octet 0 est toujours le modifier.<sup>[[7]](#references)</sup>
- Certains exports USBPcap omettent l'octet reserved ; les décodeurs prenant en charge `--no-reserved` ou un offset personnalisé permettent donc de gagner du temps.<sup>[[7]](#references)</sup>
- Si le HID report descriptor ou la BLE HOGP report map est présent dans la capture, utilisez-le pour retrouver la disposition réelle des champs avant d'écrire un parser.

## Automatiser le décodage

- **ctf-usb-keyboard-parser** reste pratique pour les challenges CTF rapides et est déjà inclus dans le repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parse nativement les fichiers `pcap` et `pcapng`, comprend `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` et ne nécessite ni tshark ni autre dépendance externe ; il convient donc aux sandboxes isolées.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** ajoute des visualiseurs pour clavier, souris et tablette. Vous pouvez soit exécuter l'helper `extract_hid_data.sh` (backend tshark), soit `extract_hid_data.py` (backend scapy), puis transmettre le fichier texte obtenu au décodeur ou aux modules de replay pour observer les frappes au clavier se dérouler.<sup>[[7]](#references)</sup>

### Le décodage stateful est important

Les claviers USB boot envoient des rapports au idle rate même lorsqu'aucun nouvel événement de touche ne se produit ; les captures peuvent donc contenir des rapports répétés avant l'événement de relâchement. Un décodeur pratique devrait :<sup>[[3]](#references)[[8]](#references)</sup>

- émettre uniquement les keycodes nouvellement pressés par rapport au rapport précédent
- conserver l'état des modifiers (`Shift`, `Ctrl`, `AltGr`) depuis l'octet 0 ou les champs parsés tels que `usbhid.boot_report.keyboard.modifier.left_shift` et `usbhid.boot_report.keyboard.modifier.right_alt`
- suivre les touches à bascule telles que `Caps Lock`, car la sortie en majuscules n'est pas contrôlée uniquement par Shift
- garder à l'esprit que les HID usage IDs sont indépendants de la disposition : `0x1d` correspond à la position physique de la touche `z`/`y` selon la disposition du clavier hôte.<sup>[[9]](#references)</sup>

## Décodeur Python rapide
```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
modifier = int(raw[0:2], 16)
keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
current = {k for k in keycodes if k}
newly_pressed = [k for k in keycodes if k and k not in prev]
shift = bool(modifier & 0x22)
for keycode in newly_pressed:
if keycode == 0x39:
caps = not caps
continue
char = SHIFTED.get(keycode) if shift else None
if char is None:
char = NORMAL.get(keycode, '?')
if char.isalpha() and (shift ^ caps):
char = char.upper()
sys.stdout.write(char)
prev = current
```
Alimentez-le avec les lignes hexadécimales brutes extraites précédemment pour obtenir instantanément une reconstruction approximative sans intégrer un parser complet dans l’environnement. Pour les layouts non américains, cela reconstruit toujours la position physique de la touche, pas nécessairement le caractère final affiché sur l’hôte victime.

## Conseils de dépannage

- Si Wireshark ne renseigne pas les champs `usbhid.*`, le descripteur de rapport HID n’a probablement pas été capturé. Rebranchez le clavier pendant la capture ou utilisez `usb.capdata` brut.
- Pour les captures logicielles sous Linux, `usbmon` est la source normale ; sous Windows, Wireshark dépend de l’extcap **USBPcap** pour voir les URB USB brutes.<sup>[[4]](#references)</sup>
- Si le clavier était connecté via un hub ou une station d’accueil, vérifiez d’abord le descripteur d’interface, puis décodez uniquement cette paire périphérique/interface. Les captures HID composites mélangent fréquemment les rapports du clavier et de la souris.
- Les captures Windows nécessitent l’interface extcap **USBPcap** ; assurez-vous qu’elle a été conservée après les mises à niveau de Wireshark, car l’absence d’extcap laisse les listes de périphériques vides.<sup>[[4]](#references)</sup>
- Corrélez toujours le tuple bus, périphérique et interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber` ; par exemple `1.9.1`) avant tout décodage — mélanger plusieurs claviers ou périphériques de stockage produit des frappes incohérentes.<sup>[[10]](#references)</sup>

## References

- [1] [Writeup du CTF HackIT 2017 : foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analyse d’une capture de paquets d’un clavier USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up de pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuration de capture USB de Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Décodeurs USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Définition de classe de périphérique pour les périphériques d’interface humaine (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tables d’utilisation HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Référence des filtres d’affichage Wireshark : USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Référence des filtres d’affichage Wireshark : USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
