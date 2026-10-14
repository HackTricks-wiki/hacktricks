# Construire un cloner mobile HID MaxiProx 125 kHz portable

{{#include ../../banners/hacktricks-training.md}}

## Objectif
Transformer un lecteur longue portée HID MaxiProx 5375 de 125 kHz alimenté sur secteur en un cloner de badges portable alimenté par batterie, déployable sur le terrain, qui collecte discrètement des cartes de proximité lors d’évaluations de la sécurité physique.

La conversion décrite ici s’appuie sur la série de recherches de TrustedSec « Let’s Clone a Cloner – Part 3: Putting It All Together » et combine des considérations mécaniques, électriques et RF afin que l’appareil final puisse être rangé dans un sac à dos et utilisé immédiatement sur site.<sup>[[1]](#references)</sup>

> [!warning]
> La manipulation d’équipements alimentés sur secteur et de batteries externes au lithium-ion peut être dangereuse. Vérifiez chaque connexion **avant** de mettre le circuit sous tension et conservez les antennes, le câble coaxial et les plans de masse exactement comme dans la conception d’origine afin d’éviter de désaccorder le lecteur.

## Liste des composants (BOM)

* Lecteur HID MaxiProx 5375 (ou tout lecteur longue portée HID Prox® 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand à base d’ESP32)
* Module trigger USB-PD (Power Delivery) capable de négocier 12 V à ≥3 A
* Batterie externe USB-C de 100 W (sortie avec profil PD 12 V)
* Fil de câblage 26 AWG à isolation silicone – rouge/blanc
* Interrupteur à bascule SPST à montage sur panneau (pour le kill-switch du buzzer)
* Capuchon de protection NKK AT4072 pour interrupteur, à l’épreuve des activations accidentelles
* Fer à souder, tresse à dessouder et pompe à dessouder
* Outils à main adaptés à l’ABS : scie à chantourner, couteau utilitaire, limes plates et demi-rondes
* Forets 1/16″ (1,5 mm) et 1/8″ (3 mm)
* Ruban adhésif double face 3 M VHB et serre-câbles

## 1. Sous-système d’alimentation

1. Dessoudez et retirez la carte fille du convertisseur buck d’origine utilisée pour produire le 5 V de la carte logique.
2. Fixez un trigger USB-PD à côté de l’ESP RFID Tool et faites passer la prise USB-C du trigger jusqu’à l’extérieur du boîtier.
3. Le trigger PD négocie le 12 V de la batterie externe et l’envoie directement au MaxiProx (le lecteur attend nativement une tension de 10–14 V). Un rail secondaire de 5 V est fourni par la carte ESP pour alimenter les accessoires éventuels.
4. La batterie de 100 W est placée à plat contre l’entretoise interne afin qu’aucun câble d’alimentation ne passe au-dessus de l’antenne en ferrite, ce qui préserve les performances RF.

## 2. Kill-switch du buzzer – fonctionnement silencieux

1. Repérez les deux pastilles du haut-parleur sur la carte logique du MaxiProx.
2. Nettoyez *les deux* pastilles à la tresse à dessouder, puis ressoudez uniquement la pastille **négative**.
3. Soudez des fils 26 AWG (blanc = négatif, rouge = positif) aux pastilles du buzzer et faites-les passer par une fente nouvellement découpée jusqu’à un interrupteur SPST à montage sur panneau.
4. Lorsque l’interrupteur est ouvert, le circuit du buzzer est interrompu et le lecteur fonctionne en silence complet – idéal pour collecter discrètement des badges.
5. Installez un capuchon de sécurité à ressort NKK AT4072 sur l’interrupteur à bascule. Élargissez soigneusement l’alésage à l’aide d’une scie à chantourner ou d’une lime jusqu’à ce qu’il s’emboîte sur le corps de l’interrupteur. Le capuchon évite toute activation accidentelle dans un sac à dos.

## 3. Boîtier et travaux mécaniques

• Utilisez une pince coupante à ras, puis un couteau et une lime pour *retirer* la « bosse » interne en ABS afin que la grosse batterie USB-C repose à plat sur l’entretoise.
• Creusez deux rainures parallèles dans la paroi du boîtier pour le câble USB-C ; elles maintiennent la batterie en place et éliminent les mouvements et vibrations.
• Créez une ouverture rectangulaire pour le bouton d’alimentation de la batterie :
  1. Fixez un gabarit en papier à l’emplacement voulu avec du ruban adhésif.
  2. Percez des trous pilotes de 1/16″ dans les quatre coins.
  3. Agrandissez-les avec un foret de 1/8″.
  4. Reliez les trous avec une scie à chantourner ; finissez les bords à la lime.  
  ✱ Une mini-perceuse rotative Dremel a été *écartée* : sa mèche à grande vitesse fait fondre l’ABS épais et laisse un bord irrégulier.

## 4. Assemblage final

1. Réinstallez la carte logique du MaxiProx et ressoudez le pigtail SMA à la pastille de masse du PCB du lecteur.
2. Fixez l’ESP RFID Tool et le trigger USB-PD avec du ruban 3 M VHB.
3. Rangez tous les fils à l’aide de serre-câbles, en éloignant **au maximum** les fils d’alimentation de la boucle d’antenne.
4. Serrez les vis du boîtier jusqu’à ce que la batterie soit légèrement comprimée ; la friction interne empêche la batterie de bouger lorsque l’appareil recule après chaque lecture de carte.

## 5. Tests de portée et de blindage

* Avec une carte de test **Pupa** de 125 kHz, le cloner portable a effectué des lectures fiables à **≈ 8 cm** à l’air libre – une portée identique à celle obtenue avec l’alimentation secteur.<sup>[[1]](#references)</sup>
* Placer le lecteur dans une boîte métallique à parois fines (pour simuler un comptoir d’accueil de banque) a réduit la portée à ≤ 2 cm, confirmant que les boîtiers métalliques importants constituent des blindages RF efficaces.<sup>[[1]](#references)</sup>

## Procédure d’utilisation

1. Chargez la batterie USB-C, branchez-la et actionnez l’interrupteur principal.
2. (Facultatif) Ouvrez le capuchon du buzzer et activez le retour sonore lors des tests sur établi ; verrouillez-le avant toute utilisation discrète sur le terrain.
3. Passez près du porteur du badge ciblé : le MaxiProx alimentera la carte et l’ESP RFID Tool capturera le flux Wiegand.
4. Récupérez les identifiants capturés par Wi-Fi ou USB-UART et rejouez-les/clonez-les selon les besoins.

## Dépannage

| Symptôme | Cause probable | Solution |
|---------|--------------|------|
| Le lecteur redémarre lorsqu’une carte est présentée | Le trigger PD a négocié 9 V au lieu de 12 V | Vérifiez les cavaliers du trigger / essayez un câble USB-C plus puissant |
| Aucune portée de lecture | Batterie ou câblage placé *au-dessus* de l’antenne | Réacheminez les câbles et gardez un dégagement de 2 cm autour de la boucle en ferrite |
| Le buzzer émet encore des bips | L’interrupteur est câblé sur le fil positif plutôt que négatif | Déplacez le kill-switch pour interrompre la piste du haut-parleur **négative** |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}