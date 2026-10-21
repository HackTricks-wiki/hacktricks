# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attaquer les systèmes RFID avec Proxmark3

Installez le client Proxmark3 RRG/Iceman activement maintenu et le firmware correspondant, puis vérifiez la syntaxe des commandes avec cette version, car les anciennes commandes présentées ci-dessous ont pu changer.<sup>[[1]](#references)[[5]](#references)</sup>

### Attaquer les MIFARE Classic 1KB

MIFARE Classic 1K comporte **16 secteurs**, chacun composé de **4 blocs** de **16 octets**. Le bloc fabricant 0 contient l’UID et les données fabricant ; il est en lecture seule sur les cartes NXP authentiques. Des cartes clonées spéciales, ou cartes « magic », peuvent permettre de le réécrire.<sup>[[1]](#references)[[2]](#references)</sup>\
Pour accéder à chaque secteur, vous avez besoin de **2 clés** (**A** et **B**), stockées dans le **bloc 3 de chaque secteur** (trailer de secteur). Le trailer de secteur stocke également les **bits d’accès**, qui définissent les permissions de **lecture et d’écriture** pour **chaque bloc** avec les deux clés.\
Par exemple, les deux clés sont utiles pour accorder des permissions de lecture si vous connaissez la première, et d’écriture si vous connaissez la seconde.

Plusieurs attaques peuvent être effectuées

```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```

Le Proxmark3 permet d’effectuer d’autres actions, comme **écouter clandestinement** une **communication Tag vers Reader**, afin de tenter d’y trouver des données sensibles. Avec cette carte, vous pouvez simplement intercepter la communication et calculer la clé utilisée, car les **opérations cryptographiques employées sont faibles** et il est possible de la calculer à partir du texte en clair et du texte chiffré (`mfkey64`).<sup>[[3]](#references)</sup>

#### Workflow rapide MiFare Classic pour détourner une carte à valeur stockée

Pour la séquence de récupération de clé, de comparaison des soldes, de vérification du champ d’intégrité et de clonage de l’UID — y compris la transcription du client Proxmark3 et les limitations des cartes magiques — voir [Altération hors ligne des valeurs stockées sur MiFare Classic](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Commandes brutes

Les systèmes IoT utilisent parfois des **tags sans marque ou non commerciaux**. Dans ce cas, vous pouvez utiliser Proxmark3 pour envoyer des **commandes brutes personnalisées aux tags**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Avec ces informations, vous pouvez essayer de rechercher des informations sur la carte et sur la manière de communiquer avec elle. Proxmark3 permet d’envoyer des commandes brutes comme : `hf 14a raw -p -b 7 26`

### Scripts

Le logiciel Proxmark3 est fourni avec une liste préchargée de **scripts d’automatisation** que vous pouvez utiliser pour effectuer des tâches simples. Pour afficher la liste complète, utilisez la commande `script list`. Ensuite, utilisez la commande `script run`, suivie du nom du script :

```
proxmark3> script run mfkeys
```

Vous pouvez créer un script pour **fuzzer des lecteurs de tags** : copiez les données d’une **carte valide**, écrivez simplement un **script Lua** qui **randomise** un ou plusieurs **octets** aléatoires, puis vérifiez si le **lecteur plante** à une itération quelconque.

## References

- [1] [Wiki Proxmark3 : HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki Proxmark3 : cartes HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Déclaration de NXP sur Crypto1 de MIFARE Classic](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Exploitation d’une vulnérabilité de carte NFC dans KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [Proxmark3 RRG/Iceman — Installation sous Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
