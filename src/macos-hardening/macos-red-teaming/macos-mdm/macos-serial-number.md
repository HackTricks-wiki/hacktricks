# Numéro de série macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les appareils Apple fabriqués après 2010 possèdent des numéros de série composés de **12 caractères alphanumériques**, chaque segment fournissant des informations spécifiques :

- **Les 3 premiers caractères** : indiquent le **lieu de fabrication**.
- **Les caractères 4 et 5** : indiquent l'**année et la semaine de fabrication**.
- **Les caractères 6 à 8** : servent d'**identifiant unique** pour chaque appareil.
- **Les 4 derniers caractères** : spécifient le **numéro de modèle**.

Par exemple, le numéro de série **C02L13ECF8J2** suit cette structure.

### **Lieux de fabrication (3 premiers caractères)**

Certains codes représentent des usines spécifiques :

- **FC, F, XA/XB/QP/G8** : différents sites aux États-Unis.
- **RN** : Mexique.
- **CK** : Cork, Irlande.
- **VM** : Foxconn, République tchèque.
- **SG/E** : Singapour.
- **MB** : Malaisie.
- **PT/CY** : Corée.
- **EE/QT/UV** : Taïwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7** : différents sites en Chine.
- **C0, C3, C7** : villes spécifiques en Chine.
- **RM** : appareils reconditionnés.

### **Année de fabrication (4e caractère)**

Ce caractère varie de 'C' (représentant le premier semestre de 2010) à 'Z' (second semestre de 2019), différentes lettres indiquant différentes périodes de six mois.

### **Semaine de fabrication (5e caractère)**

Les chiffres 1 à 9 correspondent aux semaines 1 à 9. Les lettres C à Y (à l'exception des voyelles et de 'S') représentent les semaines 10 à 27. Pour le second semestre de l'année, 26 est ajouté à ce nombre.

{{#include ../../../banners/hacktricks-training.md}}
