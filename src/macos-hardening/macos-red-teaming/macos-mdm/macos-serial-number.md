# Numéro de série macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Les appareils Apple post-2010 ont des numéros de série composés de **12 caractères alphanumériques**, chaque segment transmettant des informations spécifiques :

- **Premiers 3 caractères** : Indiquent le **lieu de fabrication**.
- **Caractères 4 et 5** : Dénote l'**année et la semaine de fabrication**.
- **Caractères 6 à 8** : Servent d'**identifiant unique** pour chaque appareil.
- **Derniers 4 caractères** : Spécifient le **numéro de modèle**.

Par exemple, le numéro de série **C02L13ECF8J2** suit cette structure.

### **Lieux de fabrication (Premiers 3 caractères)**

Certains codes représentent des usines spécifiques :

- **FC, F, XA/XB/QP/G8** : Divers emplacements aux États-Unis.
- **RN** : Mexique.
- **CK** : Cork, Irlande.
- **VM** : Foxconn, République tchèque.
- **SG/E** : Singapour.
- **MB** : Malaisie.
- **PT/CY** : Corée.
- **EE/QT/UV** : Taïwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7** : Différents emplacements en Chine.
- **C0, C3, C7** : Villes spécifiques en Chine.
- **RM** : Appareils remis à neuf.

### **Année de fabrication (4ème caractère)**

Ce caractère varie de 'C' (représentant la première moitié de 2010) à 'Z' (deuxième moitié de 2019), avec différentes lettres indiquant différentes périodes de six mois.

### **Semaine de fabrication (5ème caractère)**

Les chiffres 1-9 correspondent aux semaines 1-9. Les lettres C-Y (à l'exception des voyelles et de 'S') représentent les semaines 10-27. Pour la seconde moitié de l'année, 26 est ajouté à ce nombre.

{{#include ../../../banners/hacktricks-training.md}}
