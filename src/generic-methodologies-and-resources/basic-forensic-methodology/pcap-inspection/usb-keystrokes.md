# Frappe clavier USB

{{#include ../../../banners/hacktricks-training.md}}

Si vous disposez d'un pcap contenant la communication via USB d'un clavier comme celui-ci :

![](<../../../images/image (962).png>)

Les claviers USB utilisent généralement le protocole HID **boot protocol**, donc chaque transfert d'interruption vers l'hôte ne fait que 8 octets : un octet de bits de modificateur (Ctrl/Shift/Alt/Super), un octet réservé, et jusqu'à six keycodes par rapport. Décoder ces octets suffit à reconstruire tout ce qui a été tapé.

## USB HID report basics

Le rapport IN typique ressemble à :

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Plusieurs bits peuvent être définis simultanément. |
| 1 | Réservé/padding mais souvent réutilisé par les claviers gaming pour des données vendor. |
| 2-7 | Jusqu'à six keycodes simultanés au format USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` signifie "pas de touche". |

Les claviers sans NKRO envoient généralement `0x01` dans l'octet 2 lorsque plus de six touches sont pressées pour signaler un "rollover". Comprendre cette disposition aide lorsque vous n'avez que les octets bruts `usb.capdata`.

## Extracting HID data from a PCAP

### Wireshark workflow

1. **Isoler le périphérique** : filtrer le trafic IN d'interruption provenant du clavier, par ex. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Ajouter des colonnes utiles** : clic droit sur le champ `Leftover Capture Data` (`usb.capdata`) et vos champs `usbhid.*` préférés (p. ex. `usbhid.boot_report.keyboard.keycode_1`) pour suivre les saisies sans ouvrir chaque trame.
3. **Masquer les rapports vides** : appliquer `!(usb.capdata == 00:00:00:00:00:00:00:00)` pour supprimer les trames inactives.
4. **Exporter pour post-traitement** : `File -> Export Packet Dissections -> As CSV`, inclure `frame.number`, `usb.src`, `usb.capdata`, et `usbhid.modifiers` pour automatiser la reconstruction ensuite.

### Command-line workflow

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Sur les captures récentes, vous pouvez conserver à la fois `usb.capdata` et le champ plus riche `usbhid.data` en regroupant par périphérique :
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ces fichiers par périphérique s'insèrent directement dans n'importe quel décodeur. Si la capture provient de claviers BLE tunnelisés sur GATT, filtrez sur `btatt.value && frame.len == 20` et dump the hex payloads avant le décodage.

## Automatiser le décodage

- **ctf-usb-keyboard-parser** reste utile pour les challenges CTF rapides et est déjà fourni dans le dépôt.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analyse nativement les fichiers `pcap` et `pcapng`, comprend `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, et ne nécessite pas tshark, ce qui le rend pratique dans des sandboxes isolés.
- **USB-HID-decoders** ajoute des visualiseurs pour keyboard, mouse et tablet. Vous pouvez soit exécuter l'helper `extract_hid_data.sh` (tshark backend) ou `extract_hid_data.py` (scapy backend) puis fournir le fichier texte résultant aux modules de décodage ou de replay pour voir les keystrokes se dérouler.

## Décodeur Python rapide
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
Alimentez-le avec les lignes hex brutes extraites précédemment pour obtenir une reconstitution approximative instantanée sans intégrer un parser complet dans l'environnement.

## Conseils de dépannage

- Si Wireshark ne remplit pas les champs `usbhid.*`, le HID report descriptor n'a probablement pas été capturé. Rebranchez le clavier pendant la capture ou revenez aux données brutes `usb.capdata`.
- Les captures Windows nécessitent l'interface extcap **USBPcap** ; assurez-vous qu'elle a survécu aux mises à jour de Wireshark, car l'absence d'extcaps vous laissera avec des listes de périphériques vides.
- Corrélez toujours `usb.bus_id:device:interface` (par exemple `1.9.1`) avant de décoder quoi que ce soit — mélanger plusieurs claviers ou périphériques de stockage entraîne des frappes incohérentes.

## Références

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
