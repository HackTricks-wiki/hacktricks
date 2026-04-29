# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Si vous avez un pcap contenant la communication via USB d’un clavier comme le suivant :

![](<../../../images/image (962).png>)

Les claviers USB parlent généralement le protocole HID **boot**, donc chaque transfert interrupt vers l’hôte ne mesure que 8 octets : un octet de bits de modificateurs (Ctrl/Shift/Alt/Super), un octet réservé, et jusqu’à six keycodes par rapport. Décoder ces octets suffit pour reconstruire tout ce qui a été saisi.

## Notions de base des rapports USB HID

Le rapport IN typique ressemble à ceci :

| Byte | Meaning |
| --- | --- |
| 0 | Bitmap de modificateurs (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Plusieurs bits peuvent être définis simultanément. |
| 1 | Réservé/remplissage mais souvent réutilisé par les claviers gaming pour des données vendor. |
| 2-7 | Jusqu’à six keycodes simultanés au format USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` signifie "no key". |

Les claviers sans NKRO envoient généralement `0x01` en byte 2 lorsque plus de six touches sont pressées pour signaler un "rollover". Comprendre cette disposition aide lorsque vous n’avez que les octets bruts `usb.capdata`.

## Extraire les données HID d’un PCAP

### Identifiez d’abord l’interface du clavier

Dans les captures chargées, identifiez le clavier HID avant de dumper tout rapport. Un point de départ fiable est la réponse du descripteur d’interface :
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Regardez `usb.bInterfaceSubClass` et `usb.bInterfaceProtocol` :

- `subclass == 1` et `protocol == 1` signifient généralement un boot keyboard
- `protocol == 2` est généralement une mouse
- `protocol == 0` signifie souvent une interface HID définie par le vendor ou de type NKRO qui transporte quand même des données de clavier, mais pas dans le simple format boot de 8 octets

Une fois l'interface connue, figez vos filtres sur `usb.bus_id`, `usb.device_address` et, si possible, `usb.interface_number` avant d'exporter quoi que ce soit.

### Wireshark workflow

1. **Isoler le device** : filtrez le trafic interrupt IN venant du keyboard, par exemple `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Ajouter des colonnes utiles** : clic droit sur le champ `Leftover Capture Data` (`usb.capdata`) et sur vos champs `usbhid.*` préférés (par ex. `usbhid.boot_report.keyboard.keycode_1`) pour suivre les keystrokes sans ouvrir chaque frame.
3. **Masquer les rapports vides** : appliquez `!(usb.capdata == 00:00:00:00:00:00:00:00)` pour supprimer les frames inactives.
4. **Exporter pour le post-processing** : `File -> Export Packet Dissections -> As CSV`, incluez `frame.number`, `usb.src`, `usb.capdata`, et `usbhid.modifiers` pour script-er la reconstruction plus tard.

### Command-line workflow

`ctf-usb-keyboard-parser` automatise déjà le pipeline classique tshark + sed :
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Sur les captures plus récentes, vous pouvez conserver à la fois `usb.capdata` et le champ plus riche `usbhid.data` en regroupant par périphérique :
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ces fichiers par périphérique se branchent directement dans n’importe quel decoder. Si la capture provient de claviers BLE tunnelés via GATT, filtrez sur `btatt.value && frame.len == 20` et extrayez les payloads hex avant de décoder.

### When the report is not the classic 8-byte boot report

Les claviers gaming récents, les claviers split et les dispositifs HID composites exposent souvent une interface clavier non-boot où le payload ne correspond plus à `modifier,reserved,key1..key6`.

- Préférez `usbhid.data` à `usb.capdata` quand Wireshark a déjà analysé la couche HID.
- Si chaque ligne commence par un préfixe constant ou un report ID, retirez-le avec un decoder tenant compte de l’offset plutôt que de supposer que l’octet 0 est toujours le modifier.
- Certains exports USBPcap omettent l’octet reserved, donc les decoders qui supportent `--no-reserved` ou un offset personnalisé font gagner du temps.
- Si le HID report descriptor ou la BLE HOGP report map est présent dans la capture, utilisez-le pour retrouver la vraie disposition des champs avant d’écrire un parser.

## Automating the decoding

- **ctf-usb-keyboard-parser** reste pratique pour les challenges CTF rapides et est déjà inclus dans le repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parse nativement les fichiers `pcap` et `pcapng`, comprend `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, et ne nécessite pas tshark, donc il fonctionne bien dans des sandboxes isolés.
- **USB-HID-decoders** ajoute des visualiseurs pour clavier, souris et tablette. Vous pouvez soit lancer l’aide `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy), puis fournir le fichier texte الناتant au decoder ou aux modules de replay pour voir les frappes se dérouler.

### Stateful decoding matters

Les captures USB interrupt contiennent généralement à la fois l’appui sur une touche et une ou plusieurs copies répétées du même report avant que l’événement de relâchement n’arrive. Un decoder pratique devrait :

- n’émettre que les keycodes nouvellement pressés par rapport au report précédent
- conserver l’état des modifiers (`Shift`, `Ctrl`, `AltGr`) à partir de l’octet 0 ou du champ parsé `usbhid.boot_report.keyboard.modifier`
- suivre les touches à bascule comme `Caps Lock`, car la sortie en majuscules n’est pas contrôlée par Shift seul
- se rappeler que les HID usage IDs sont indépendants de la disposition clavier : `0x1d` est la position physique de la touche `z`/`y` selon la disposition clavier de l’hôte

## Quick Python decoder
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
Alimentez-le avec les lignes hexadécimales brutes extraites plus tôt pour obtenir une reconstruction approximative instantanée sans intégrer un parser complet dans l’environnement. Pour les layouts non-US, cela reconstruit toujours la position physique de la touche, pas nécessairement le glyph final affiché sur l’hôte victime.

## Conseils de dépannage

- Si Wireshark ne renseigne pas les champs `usbhid.*`, le descripteur de rapport HID n’a probablement pas été capturé. Rebranchez le clavier pendant la capture ou revenez à `usb.capdata` brut.
- Sur les captures logicielles Linux, `usbmon` est la source normale ; sur Windows, Wireshark dépend de l’extcap **USBPcap** pour voir des URB USB bruts tout court.
- Si le clavier était connecté via un hub ou un dock, confirmez d’abord le descripteur d’interface, puis décodez uniquement cette paire device/interface. Les captures HID composites mélangent souvent les rapports clavier et souris.
- Les captures Windows nécessitent l’interface extcap **USBPcap** ; vérifiez qu’elle a survécu aux mises à jour de Wireshark, car des extcaps manquantes vous laissent avec des listes de périphériques vides.
- Faites toujours correspondre `usb.bus_id:device:interface` (par ex. `1.9.1`) avant de décoder quoi que ce soit — mélanger plusieurs claviers ou périphériques de stockage mène à des frappes incohérentes.

## Références

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
