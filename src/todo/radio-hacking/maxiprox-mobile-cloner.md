# Construire un cloner mobile HID MaxiProx 125 kHz portable

{{#include ../../banners/hacktricks-training.md}}

## Objectif
Transformer un lecteur HID MaxiProx 5375 longue portée 125 kHz alimenté sur secteur en un cloner de badges déployable sur le terrain et alimenté par batterie, capable de collecter silencieusement des cartes de proximité lors d’évaluations de sécurité physique.

La conversion présentée ici s’appuie sur la série de recherches de TrustedSec « Let’s Clone a Cloner – Part 3: Putting It All Together » et combine des considérations mécaniques, électriques et RF afin que l’appareil final puisse être placé dans un sac à dos et utilisé immédiatement sur site.<sup>[[1]](#references)</sup>

> [!warning]
> La manipulation d’équipements alimentés sur secteur et de power-banks Lithium-ion peut être dangereuse. Vérifiez chaque connexion **avant** de mettre le circuit sous tension et conservez les antennes, le coaxial et les plans de masse exactement comme dans la conception d’usine afin d’éviter de désaccorder le lecteur.

## Nomenclature (BOM)

* Lecteur HID MaxiProx 5375 (ou tout lecteur longue portée HID Prox® 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand basé sur ESP32)
* Module trigger USB-PD (Power-Delivery) capable de négocier 12 V à ≥3 A
* Power-bank USB-C de 100 W (sortie avec profil 12 V PD)
* Fil de câblage en silicone 26 AWG – rouge/blanc
* Interrupteur à bascule SPST pour montage sur panneau (pour le kill-switch du beeper)
* Capuchon de protection NKK AT4072 / capuchon anti-accident
* Fer à souder, tresse à dessouder et pompe à dessouder
* Outils à main adaptés à l’ABS : scie à guichet, cutter, limes plate et demi-ronde
* Forets de 1/16″ (1,5 mm) et 1/8″ (3 mm)
* Ruban adhésif double face 3 M VHB et colliers de serrage

## 1. Sous-système d’alimentation

1. Dessoudez et retirez la carte fille du convertisseur buck d’origine utilisée pour produire 5 V pour le PCB logique.
2. Fixez un trigger USB-PD à côté de l’ESP RFID Tool et faites passer le connecteur USB-C du trigger vers l’extérieur du boîtier.
3. Le trigger PD négocie 12 V depuis la power-bank et les fournit directement au MaxiProx (le lecteur accepte nativement 10–14 V). Un rail secondaire de 5 V est prélevé sur la carte ESP pour alimenter les accessoires éventuels.
4. La batterie de 100 W est positionnée à plat contre l’entretoise interne afin qu’**aucun** câble d’alimentation ne passe au-dessus de l’antenne en ferrite, ce qui préserve les performances RF.

## 2. Kill-switch du beeper – Fonctionnement silencieux

1. Repérez les deux pastilles du haut-parleur sur la carte logique du MaxiProx.
2. Nettoyez *les deux* pastilles avec de la tresse à dessouder, puis ressoudez uniquement la pastille **négative**.
3. Soudez des fils 26 AWG (blanc = négatif, rouge = positif) aux pastilles du beeper et faites-les passer par une fente nouvellement découpée jusqu’à un interrupteur SPST monté sur panneau.
4. Lorsque l’interrupteur est ouvert, le circuit du beeper est interrompu et le lecteur fonctionne en silence total, ce qui est idéal pour la collecte discrète de badges.
5. Installez un capuchon de sécurité à ressort NKK AT4072 sur le bouton à bascule. Agrandissez soigneusement l’alésage avec une scie à guichet / une lime jusqu’à ce qu’il s’enclenche sur le corps de l’interrupteur. Le protège-interrupteur empêche toute activation accidentelle dans un sac à dos.

## 3. Boîtier et travaux mécaniques

• Utilisez une pince coupante, puis un cutter et une lime pour *retirer* la « bosse » interne en ABS afin que la grande batterie USB-C repose à plat sur l’entretoise.  
• Creusez deux rainures parallèles dans la paroi du boîtier pour le câble USB-C ; cela bloque la batterie et élimine les mouvements et vibrations.  
• Créez une ouverture rectangulaire pour le bouton **d’alimentation** de la batterie :
1. Fixez un gabarit en papier sur l’emplacement.
2. Percez des avant-trous de 1/16″ aux quatre coins.
3. Agrandissez-les avec un foret de 1/8″.
4. Reliez les trous avec une scie à guichet, puis finissez les bords avec une lime.
✱  Un Dremel rotatif a été *évité* : la mèche à haute vitesse fait fondre l’ABS épais et laisse un bord disgracieux.

## 4. Assemblage final

1. Réinstallez la carte logique du MaxiProx et ressoudez le pigtail SMA à la pastille de masse du PCB du lecteur.
2. Fixez l’ESP RFID Tool et le trigger USB-PD avec du ruban VHB 3 M.
3. Organisez tous les fils avec des colliers de serrage, en maintenant les câbles d’alimentation **loin** de la boucle d’antenne.
4. Serrez les vis du boîtier jusqu’à ce que la batterie soit légèrement comprimée ; la friction interne empêche la batterie de se déplacer lorsque l’appareil recule après chaque lecture de carte.

## 5. Tests de portée et de blindage

* Avec une carte de test **Pupa** 125 kHz, le cloner portable a obtenu des lectures régulières à **≈ 8 cm** en espace libre, soit une portée identique à celle obtenue avec une alimentation secteur.<sup>[[1]](#references)</sup>
* En plaçant le lecteur dans une boîte métallique à parois fines (pour simuler un comptoir d’accueil bancaire), la portée a été réduite à ≤ 2 cm, confirmant que les boîtiers métalliques importants agissent comme des blindages RF efficaces.<sup>[[1]](#references)</sup>

## Procédure d’utilisation

1. Chargez la batterie USB-C, branchez-la et activez l’interrupteur principal.
2. (Facultatif) Ouvrez le protège-interrupteur du beeper et activez le retour sonore lors des tests sur établi ; verrouillez-le avant toute utilisation discrète sur le terrain.
3. Passez à proximité du porteur du badge ciblé : le MaxiProx alimente la carte et l’ESP RFID Tool capture le flux Wiegand.
4. Extrayez les identifiants capturés via Wi-Fi ou USB-UART, puis rejouez-les/clônez-les si nécessaire.

## Dépannage

| Symptôme | Cause probable | Correctif |
|---------|----------------|-----------|
| Le lecteur redémarre lorsqu’une carte est présentée | Le trigger PD a négocié 9 V au lieu de 12 V | Vérifiez les jumpers du trigger / essayez un câble USB-C plus puissant |
| Aucune portée de lecture | La batterie ou le câblage se trouve *au-dessus* de l’antenne | Réacheminez les câbles et maintenez un dégagement de 2 cm autour de la boucle en ferrite |
| Le beeper émet toujours des bips | L’interrupteur est câblé sur le fil positif au lieu du négatif | Déplacez le kill-switch afin d’interrompre la piste **négative** du haut-parleur |

## Références

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
