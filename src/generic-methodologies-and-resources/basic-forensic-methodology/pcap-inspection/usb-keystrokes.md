# Saisie clavier USB

{{#include ../../../banners/hacktricks-training.md}}

Si vous avez un pcap contenant les communications USB d’un clavier, comme celui-ci :

![Saisie clavier USB : si vous avez un pcap contenant les communications USB d’un clavier, comme celui-ci](<../../../images/image (962).png>)

Pour un clavier utilisant le **boot protocol** HID, chaque rapport Interrupt IN a une structure fixe de 8 octets : un octet de modificateurs, un octet réservé et six octets de codes de touche. L’hôte compare les rapports successifs et associe les codes de touche aux usages HID pour reconstruire les événements clavier.<sup>[[8]](#references)</sup>

Pour le triage général des captures, consultez [Inspection des pcap](./).

## Principes de base des rapports USB HID

Le rapport d’entrée standard d’un clavier en mode boot est structuré comme suit.<sup>[[8]](#references)[[9]](#references)</sup>

| Octet | Signification |
| --- | --- |
| 0 | Bitmap des modificateurs (`0x02` = Maj gauche, `0x20` = Maj droite, `0x40` = Alt droit, etc.). Plusieurs bits peuvent être activés simultanément. |
| 1 | Octet réservé ; les rapports inutilisés doivent normalement le définir à zéro. Son utilisation par un fabricant ou un système spécifique n’est pas portable. |
| 2-7 | Jusqu’à six codes de touche simultanés au format USB Usage ID (`0x04 = a`, `0x1E = 1`). `0x00` signifie « aucune touche ». |

Dans la disposition boot, l’usage ID `0x01` (`Keyboard ErrorRollOver`) est signalé dans tous les emplacements de touche lorsque plus de six touches non-modificatrices sont enfoncées ; il peut également indiquer une combinaison non reconnaissable.<sup>[[8]](#references)[[9]](#references)</sup> Comprendre cette disposition est utile lorsque vous ne disposez que des octets bruts de `usb.capdata`.

## Extraire les données HID d’un PCAP

### Identifier d’abord l’interface du clavier

Sur les captures chargées, identifiez le clavier HID avant de vider les rapports. Le descripteur d’interface est un bon point de départ :<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

La classe HID définit les valeurs d’interface suivantes :<sup>[[8]](#references)</sup>

- `subclass == 1` correspond à la sous-classe d’interface Boot ; avec `protocol == 1`, elle identifie un clavier boot
- `protocol == 2` identifie une souris boot
- `protocol == 0` signifie qu’aucun protocole boot n’est utilisé ; examinez plutôt le descripteur de rapport HID au lieu de supposer une disposition de 8 octets

Une interface compatible avec le mode boot **ne prouve pas que le protocole boot est actif**. Les appareils HID s’initialisent en mode report protocol. L’hôte sélectionne le mode boot avec `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`) ; `wValue = 1` sélectionne le mode report protocol. Si l’énumération figure dans la capture, vérifiez la requête pour l’interface clavier (`wIndex`) avant d’utiliser un décodeur boot à huit octets. Si elle est absente, vérifiez la disposition de rapport observée au lieu de déduire le mode à partir du descripteur d’interface.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Once l’interface est connue, fixez vos filtres sur `usb.bus_id`, `usb.device_address` et, si possible, `usb.bInterfaceNumber` avant toute exportation.

### Flux de travail dans Wireshark

1. **Isoler le périphérique** : filtrez le trafic interrupt IN provenant du clavier, par exemple `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Ajouter des colonnes utiles** : faites un clic droit sur le champ `Leftover Capture Data` (`usb.capdata`) et sur les champs `usbhid.*` de votre choix (par exemple `usbhid.boot_report.keyboard.keycode_1`) pour suivre les frappes sans ouvrir chaque trame.<sup>[[11]](#references)</sup>
3. **Masquer les rapports vides** : appliquez `!(usb.capdata == 00:00:00:00:00:00:00:00)` pour exclure les trames inactives.
4. **Exporter pour le post-traitement** : `File -> Export Packet Dissections -> As CSV`, en incluant `frame.number`, `usb.src`, `usb.capdata` et les champs de modificateurs décodés, tels que `usbhid.boot_report.keyboard.modifier.left_shift` et `usbhid.boot_report.keyboard.modifier.right_alt`, afin de script-er la reconstruction ultérieurement.<sup>[[10]](#references)[[11]](#references)</sup>

### Flux de travail en ligne de commande

La méthode classique d’extraction — extraire `usb.capdata`, exclure les rapports inactifs et mapper les IDs d’usage — est présentée dans l’analyse originale de 2017 et son tutoriel.<sup>[[1]](#references)[[2]](#references)</sup>

Le dépôt `ctf-usb-keyboard-parser` automatise le pipeline classique tshark + sed :<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Dans les captures récentes, privilégiez le champ `usbhid.data` décodé par Wireshark et utilisez `usb.capdata` en solution de repli ; écrivez une charge utile par rapport dans un fichier par périphérique :<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Ces fichiers par périphérique peuvent être transmis à un décodeur après normalisation du format hexadécimal attendu. Si la capture provient de claviers BLE utilisant un tunnel GATT, filtrez avec `btatt.value && frame.len == 20` et extrayez les payloads hexadécimaux avant le décodage.<sup>[[7]](#references)</sup>

### Lorsque le rapport n’est pas le rapport de démarrage classique de 8 octets

Une interface qui n’utilise pas le protocole de démarrage ou un ID de rapport peut modifier la disposition du payload : ne supposez donc pas que chaque rapport de clavier suit le format `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Préférez `usbhid.data` à `usb.capdata` lorsque Wireshark a déjà analysé la couche HID.
- Si chaque ligne commence par un préfixe constant ou un ID de rapport, supprimez-le avec un décodeur tenant compte du décalage, au lieu de supposer que l’octet 0 est toujours le modificateur.<sup>[[7]](#references)</sup>
- Certains exports USBPcap omettent l’octet réservé ; les décodeurs prenant en charge `--no-reserved` ou un décalage personnalisé font gagner du temps.<sup>[[7]](#references)</sup>
- Si le descripteur de rapport HID ou la table de correspondance des rapports BLE HOGP est présent dans la capture, utilisez-le pour retrouver la disposition réelle des champs avant d’écrire un analyseur.

### Décoder une bitmap de touches du protocole de rapport

Pour un clavier dont le rapport d’entrée est une bitmap plutôt que six emplacements de touches du protocole de démarrage, repérez son **descripteur de rapport HID** dans le trafic d’énumération. Ce filtre trouve les trames dans lesquelles Wireshark a décodé un élément Report Size ; ouvrez-en une et examinez le descripteur complet. Démarrez une nouvelle capture avant de brancher le clavier si le descripteur est absent.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Pour chaque rapport d’entrée du clavier, notez son `Report ID` (le cas échéant), sa `Usage Page` (`0x07` pour les touches du clavier), ses `Usage Minimum/Maximum`, son `Report Size`, son `Report Count` et si chaque élément `Input` est de type **Variable** ou **Array**. Comptez tous les champs `Input` précédents et le bourrage constant pour trouver le décalage en bits du champ des touches ; les champs de rapport ne sont pas nécessairement alignés sur des octets. Un champ `Variable` d’un bit avec des usages de clavier consécutifs est un bitmap d’état des touches : le bit 0 de ce champ correspond au premier usage déclaré, le bit 1 au suivant, et ainsi de suite. Un `Array` contient plutôt des valeurs résolues à l’aide de la plage d’usages du descripteur ; chaque bit ne correspond donc pas à une touche enfoncée. Si un `Report ID` est déclaré, sélectionnez d’abord les rapports portant ce préfixe et ignorez son octet lors du calcul des décalages des champs. Comparez les ensembles d’usages maintenus entre les rapports consécutifs de la **même interface et du même Report ID** pour ne signaler que les nouvelles pressions.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Automatiser le décodage

- **ctf-usb-keyboard-parser** reste pratique pour les défis CTF rapides et est déjà inclus dans le dépôt.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analyse nativement les fichiers `pcap` et `pcapng`, prend en charge `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` et ne nécessite ni tshark ni autre dépendance externe ; il convient donc aux environnements isolés.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** ajoute des visualiseurs pour les claviers, les souris et les tablettes. Vous pouvez exécuter le script auxiliaire `extract_hid_data.sh` (backend tshark) ou `extract_hid_data.py` (backend scapy), puis fournir le fichier texte obtenu au décodeur ou aux modules de relecture pour observer le déroulement des frappes.<sup>[[7]](#references)</sup>

### Le décodage avec état est important

Les claviers USB boot envoient des rapports à la fréquence d’inactivité même en l’absence de nouvel événement de touche ; les captures peuvent donc contenir des rapports répétés avant l’événement de relâchement. Un décodeur pratique devrait :<sup>[[3]](#references)[[8]](#references)</sup>

- ne signaler que les codes de touche nouvellement enfoncés par rapport au rapport précédent
- conserver l’état des modificateurs (`Shift`, `Ctrl`, `AltGr`) à partir de l’octet 0 ou de champs analysés tels que `usbhid.boot_report.keyboard.modifier.left_shift` et `usbhid.boot_report.keyboard.modifier.right_alt`
- suivre les touches à bascule telles que `Caps Lock`, car la production de majuscules ne dépend pas uniquement de Shift
- garder à l’esprit que les identifiants d’usage HID sont indépendants de la disposition : `0x1d` correspond à la position physique de la touche `z` ou `y`, selon la disposition du clavier de l’hôte.<sup>[[9]](#references)</sup>

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

Fournissez-lui les lignes hexadécimales brutes précédemment extraites pour obtenir instantanément une reconstruction approximative, sans intégrer un parseur complet à l’environnement. Pour les dispositions de clavier autres que US, cela permet de retrouver la position physique des touches, mais pas nécessairement le caractère final affiché sur la machine de la victime.

## Conseils de dépannage

- Si Wireshark ne renseigne pas les champs `usbhid.*`, le descripteur de rapport HID n’a probablement pas été capturé. Rebranchez le clavier pendant la capture ou utilisez `usb.capdata` brut.
- Pour les captures logicielles sous Linux, `usbmon` est la source habituelle ; sous Windows, Wireshark dépend de l’extcap **USBPcap** pour voir les URB USB brutes.<sup>[[4]](#references)</sup>
- Si le clavier était connecté via un hub ou une station d’accueil, vérifiez d’abord le descripteur d’interface, puis ne décodez que la paire appareil/interface concernée. Les captures HID composites mélangent souvent les rapports du clavier et de la souris.
- Les captures sous Windows nécessitent l’interface extcap **USBPcap** ; vérifiez qu’elle a bien été conservée après les mises à niveau de Wireshark, car l’absence d’extcap laisse la liste des appareils vide.<sup>[[4]](#references)</sup>
- Faites toujours correspondre le triplet bus, appareil et interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber` ; par exemple `1.9.1`) avant tout décodage — mélanger plusieurs claviers ou appareils de stockage produit des frappes incohérentes.<sup>[[10]](#references)</sup>



## References

- [1] [Compte rendu du CTF HackIT 2017 : foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analyse d’une capture de paquets d’un clavier USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - compte rendu de pcap 1 et 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configuration de la capture USB dans Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Définition de classe de périphérique pour les périphériques d’interface humaine (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tables d’utilisation HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Référence des filtres d’affichage Wireshark : USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Référence des filtres d’affichage Wireshark : USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Noyau Linux : introduction aux descripteurs de rapport HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024 : compte rendu d’ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
