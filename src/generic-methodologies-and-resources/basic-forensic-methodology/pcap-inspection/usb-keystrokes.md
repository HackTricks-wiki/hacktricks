# Keystrokes USB

{{#include ../../../banners/hacktricks-training.md}}

Si vous avez un pcap contenant la communication via USB d'un clavier comme celui présenté ci-dessous :

![Keystrokes USB : Si vous avez un pcap contenant la communication via USB d'un clavier comme celui présenté ci-dessous](<../../../images/image (962).png>)

Les claviers USB utilisent généralement le **boot protocol** HID. Ainsi, chaque transfert d'interruption vers l'hôte ne fait que 8 octets : un octet de bits de modification (Ctrl/Shift/Alt/Super), un octet réservé et jusqu'à six keycodes par rapport. Le décodage de ces octets suffit pour reconstituer tout ce qui a été saisi.

## Bases des rapports USB HID

Le rapport IN typique ressemble à ceci :

| Octet | Signification |
| --- | --- |
| 0 | Bitmap des modificateurs (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Plusieurs bits peuvent être définis simultanément. |
| 1 | Réservé/remplissage, mais souvent réutilisé par les claviers gaming pour des données du fournisseur. |
| 2-7 | Jusqu'à six keycodes simultanés au format USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` signifie « aucune touche ». |

Les claviers sans NKRO envoient généralement `0x01` dans l'octet 2 lorsque plus de six touches sont pressées afin de signaler un « rollover ». Comprendre cette structure est utile lorsque vous ne disposez que des octets `usb.capdata` bruts.

## Extraction des données HID depuis un PCAP

### Identifier d'abord l'interface du clavier

Dans les captures chargées, identifiez le clavier HID avant de vider les rapports. Un bon point de départ fiable est la réponse du descripteur d'interface :<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Examinez `usb.bInterfaceSubClass` et `usb.bInterfaceProtocol` :

- `subclass == 1` et `protocol == 1` signifient généralement un clavier boot
- `protocol == 2` correspond généralement à une souris
- `protocol == 0` signifie souvent une interface HID définie par le vendeur ou de type NKRO qui transporte tout de même des données de clavier, mais pas dans le format boot simple de 8 octets

Une fois l'interface identifiée, limitez vos filtres à `usb.bus_id`, `usb.device_address` et, si possible, `usb.interface_number` avant toute exportation.

### Flux de travail Wireshark

1. **Isolez le périphérique** : filtrez le trafic interrupt IN provenant du clavier, par exemple `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Ajoutez des colonnes utiles** : faites un clic droit sur le champ `Leftover Capture Data` (`usb.capdata`) et sur les champs `usbhid.*` de votre choix (par exemple `usbhid.boot_report.keyboard.keycode_1`) afin de suivre les frappes sans ouvrir chaque trame.
3. **Masquez les rapports vides** : appliquez `!(usb.capdata == 00:00:00:00:00:00:00:00)` pour supprimer les trames inactives.
4. **Exportez pour le post-traitement** : `File -> Export Packet Dissections -> As CSV`, incluez `frame.number`, `usb.src`, `usb.capdata` et `usbhid.modifiers` afin de pouvoir automatiser la reconstruction ultérieurement.

### Flux de travail en ligne de commande

`ctf-usb-keyboard-parser` automatise déjà le pipeline classique tshark + sed :
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Dans les captures plus récentes, vous pouvez conserver à la fois `usb.capdata` et le champ plus riche `usbhid.data` en regroupant les données par périphérique :
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ces fichiers par périphérique peuvent être directement utilisés avec n’importe quel décodeur. Si la capture provient de claviers BLE tunnelisés via GATT, filtrez avec `btatt.value && frame.len == 20` et extrayez les payloads hexadécimaux avant le décodage.

### Lorsque le report n’est pas le report boot classique de 8 octets

Les claviers gaming récents, les claviers séparés et les périphériques HID composites exposent souvent une interface clavier non boot, dont le payload ne correspond plus à `modifier,reserved,key1..key6`.

- Préférez `usbhid.data` à `usb.capdata` lorsque Wireshark a déjà analysé la couche HID.
- Si chaque ligne commence par un préfixe constant ou un report ID, retirez-le avec un décodeur prenant en compte l’offset au lieu de supposer que l’octet 0 est toujours le modificateur.
- Certains exports USBPcap omettent l’octet réservé ; les décodeurs prenant en charge `--no-reserved` ou un offset personnalisé permettent de gagner du temps.
- Si le descripteur de report HID ou la report map BLE HOGP est présent dans la capture, utilisez-le pour retrouver la structure réelle des champs avant d’écrire un parser.

## Automatisation du décodage

- **ctf-usb-keyboard-parser** reste pratique pour les challenges CTF rapides et est déjà inclus dans le repository.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analyse nativement les fichiers `pcap` et `pcapng`, comprend `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` et ne nécessite pas tshark ; il fonctionne donc très bien dans des sandbox isolées.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** ajoute des visualiseurs pour clavier, souris et tablette. Vous pouvez exécuter le helper `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy), puis fournir le fichier texte obtenu au décodeur ou aux modules de replay pour observer les frappes se dérouler.<sup>[[5]](#references)</sup>

### Le décodage stateful est important

Les captures d’interruptions USB contiennent généralement à la fois l’appui sur la touche et une ou plusieurs copies répétées du même report avant l’arrivée de l’événement de relâchement. Un décodeur pratique devrait :<sup>[[2]](#references)</sup>

- n’émettre que les keycodes nouvellement pressés par rapport au report précédent
- conserver l’état des modificateurs (`Shift`, `Ctrl`, `AltGr`) depuis l’octet 0 ou depuis le champ analysé `usbhid.boot_report.keyboard.modifier`
- suivre les touches à bascule telles que `Caps Lock`, car la sortie en majuscules n’est pas contrôlée uniquement par Shift
- se rappeler que les IDs d’utilisation HID sont indépendants de la disposition : `0x1d` correspond à la position physique de la touche `z`/`y` selon la disposition du clavier de l’hôte

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
Utilisez les lignes hexadécimales brutes extraites précédemment pour obtenir instantanément une reconstruction approximative, sans intégrer un parser complet dans l’environnement. Pour les layouts non américains, cela reconstruit toujours la position physique de la touche, et pas nécessairement le caractère final affiché sur la machine victime.

## Conseils de dépannage

- Si Wireshark ne renseigne pas les champs `usbhid.*`, le descripteur de rapport HID n’a probablement pas été capturé. Rebranchez le clavier pendant la capture ou utilisez `usb.capdata` brut.
- Sous Linux, les captures logicielles utilisent généralement `usbmon` comme source ; sous Windows, Wireshark dépend de l’extcap **USBPcap** pour voir les URB USB brutes.<sup>[[1]](#references)</sup>
- Si le clavier était connecté via un hub ou une station d’accueil, vérifiez d’abord le descripteur d’interface, puis ne décodez que cette paire périphérique/interface. Les captures HID composites mélangent fréquemment les rapports du clavier et de la souris.
- Les captures Windows nécessitent l’interface extcap **USBPcap** ; assurez-vous qu’elle a été conservée après les mises à niveau de Wireshark, car l’absence d’extcaps laisse les listes de périphériques vides.<sup>[[1]](#references)</sup>
- Corrélez toujours `usb.bus_id:device:interface` (par exemple `1.9.1`) avant de décoder quoi que ce soit — mélanger plusieurs claviers ou périphériques de stockage produit des frappes incohérentes.

## Références

- [1] [Configuration des captures USB de Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
