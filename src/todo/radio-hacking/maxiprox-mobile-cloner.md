# Construction d'un Cloner Mobile HID MaxiProx 125 kHz Portable

{{#include ../../banners/hacktricks-training.md}}

## Objectif
Transformer un lecteur HID MaxiProx 5375 à longue portée de 125 kHz alimenté par le secteur en un cloner de badge portable, alimenté par batterie, qui récolte silencieusement des cartes de proximité lors des évaluations de sécurité physique.

La conversion décrite ici est basée sur la série de recherches de TrustedSec "Let’s Clone a Cloner – Part 3: Putting It All Together" et combine des considérations mécaniques, électriques et RF afin que le dispositif final puisse être glissé dans un sac à dos et utilisé immédiatement sur site.

> [!warning]
> Manipuler des équipements alimentés par le secteur et des batteries Lithium-ion peut être dangereux. Vérifiez chaque connexion **avant** d'alimenter le circuit et gardez les antennes, le coaxial et les plans de masse exactement comme ils étaient dans la conception d'origine pour éviter de désaccorder le lecteur.

## Liste des Matériaux (BOM)

* Lecteur HID MaxiProx 5375 (ou tout lecteur HID Prox® à longue portée de 12 V)
* Outil RFID ESP v2.2 (sniffer/logger Wiegand basé sur ESP32)
* Module de déclenchement USB-PD (Power-Delivery) capable de négocier 12 V @ ≥3 A
* Batterie USB-C de 100 W (sorties 12 V profil PD)
* Fil de connexion isolé en silicone 26 AWG – rouge/blanc
* Interrupteur à bascule SPST à montage en panneau (pour le kill-switch du beeper)
* Capuchon de protection NKK AT4072 / capuchon anti-accident
* Fer à souder, tresse à dessouder et pompe à dessouder
* Outils manuels classés ABS : scie à métaux, couteau utilitaire, limes plates et demi-rondes
* Forets de 1/16″ (1,5 mm) et 1/8″ (3 mm)
* Ruban adhésif double face 3 M VHB & attaches zip

## 1. Sous-système d'Alimentation

1. Dessoudez et retirez la carte fille du convertisseur buck d'origine utilisée pour générer 5 V pour le PCB logique.
2. Montez un déclencheur USB-PD à côté de l'outil RFID ESP et faites passer le réceptacle USB-C du déclencheur à l'extérieur de l'enceinte.
3. Le déclencheur PD négocie 12 V à partir de la batterie et l'alimente directement au MaxiProx (le lecteur s'attend nativement à 10–14 V). Un rail secondaire de 5 V est pris de la carte ESP pour alimenter tout accessoire.
4. Le pack de batterie de 100 W est positionné à fleur contre le support interne afin qu'il n'y ait **aucun** câble d'alimentation traînant sur l'antenne ferrite, préservant ainsi les performances RF.

## 2. Kill-Switch du Beeper – Fonctionnement Silencieux

1. Localisez les deux pads de haut-parleur sur la carte logique du MaxiProx.
2. Nettoyez *les deux* pads, puis ressoudez uniquement le pad **négatif**.
3. Soudez des fils 26 AWG (blanc = négatif, rouge = positif) aux pads du beeper et faites-les passer par une fente nouvellement découpée vers un interrupteur SPST à montage en panneau.
4. Lorsque l'interrupteur est ouvert, le circuit du beeper est interrompu et le lecteur fonctionne en silence complet – idéal pour la récolte discrète de badges.
5. Installez un capuchon de sécurité à ressort NKK AT4072 sur le bascule. Agrandissez soigneusement le trou avec une scie à métaux / lime jusqu'à ce qu'il s'enclenche sur le corps de l'interrupteur. Le garde empêche une activation accidentelle à l'intérieur d'un sac à dos.

## 3. Enceinte & Travaux Mécaniques

• Utilisez des coupe-fils à fleur puis un couteau & une lime pour *retirer* le "bump-out" ABS interne afin que la grande batterie USB-C soit à plat sur le support.
• Creusez deux canaux parallèles dans le mur de l'enceinte pour le câble USB-C ; cela fixe la batterie en place et élimine le mouvement/la vibration.
• Créez une ouverture rectangulaire pour le bouton **d'alimentation** de la batterie :
1. Collez un pochoir en papier sur l'emplacement.
2. Percez des trous pilotes de 1/16″ dans les quatre coins.
3. Agrandissez avec un foret de 1/8″.
4. Reliez les trous avec une scie à métaux ; finissez les bords avec une lime.
✱ Un Dremel rotatif a été *évité* – la mèche à grande vitesse fait fondre l'ABS épais et laisse un bord inesthétique.

## 4. Assemblage Final

1. Réinstallez la carte logique du MaxiProx et ressoudez le pigtail SMA au pad de masse du PCB du lecteur.
2. Montez l'outil RFID ESP et le déclencheur USB-PD en utilisant 3 M VHB.
3. Organisez tous les câbles avec des attaches zip, en gardant les fils d'alimentation **loin** de la boucle d'antenne.
4. Serrez les vis de l'enceinte jusqu'à ce que la batterie soit légèrement comprimée ; la friction interne empêche le pack de se déplacer lorsque le dispositif se rétracte après chaque lecture de carte.

## 5. Tests de Portée & de Blindage

* En utilisant une carte de test **Pupa** de 125 kHz, le cloner portable a obtenu des lectures cohérentes à **≈ 8 cm** en plein air – identique à l'opération alimentée par le secteur.
* Placer le lecteur à l'intérieur d'une boîte en métal à paroi fine (pour simuler un bureau de hall de banque) a réduit la portée à ≤ 2 cm, confirmant que des enceintes métalliques substantielles agissent comme des écrans RF efficaces.

## Flux de Travail d'Utilisation

1. Chargez la batterie USB-C, connectez-la et activez l'interrupteur principal.
2. (Optionnel) Ouvrez le garde du beeper et activez le retour sonore lors des tests sur banc ; verrouillez-le avant une utilisation discrète sur le terrain.
3. Passez devant le titulaire de badge cible – le MaxiProx va alimenter la carte et l'outil RFID ESP capture le flux Wiegand.
4. Déversez les identifiants capturés via Wi-Fi ou USB-UART et rejouez/cloner selon les besoins.

## Dépannage

| Symptôme | Cause Probable | Solution |
|---------|--------------|------|
| Le lecteur redémarre lorsque la carte est présentée | Le déclencheur PD a négocié 9 V au lieu de 12 V | Vérifiez les jumpers du déclencheur / essayez un câble USB-C de plus haute puissance |
| Pas de portée de lecture | Batterie ou câblage reposant *sur* l'antenne | Réacheminez les câbles & gardez 2 cm de dégagement autour de la boucle ferrite |
| Le beeper émet toujours des bips | Interrupteur câblé sur le fil positif au lieu du négatif | Déplacez le kill-switch pour interrompre la trace du haut-parleur **négatif** |

## Références

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
