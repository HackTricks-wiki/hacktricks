# Numéro de série macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Ne supposez pas que chaque Mac possède un numéro de série décodable de 12 caractères. L'ancien format d'Apple encodait des informations sur la fabrication et la configuration, mais Apple a commencé à introduire des numéros de série randomisés avec ses nouveaux produits en 2021. Le format randomisé n'expose pas les détails de fabrication ou de configuration.<sup>[[1]](#references)</sup>

### Ancien format à 12 caractères

Pour de nombreux appareils fabriqués entre 2010 et la transition vers les numéros randomisés, le format à 12 caractères peut encore fournir des indications utiles sur l'inventaire :<sup>[[3]](#references)</sup>

- Les caractères 1 à 3 identifient le lieu de fabrication.
- Les caractères 4 et 5 encodent le semestre et la semaine de production.
- Les caractères 6 à 8 distinguent les unités produites au même endroit et au même moment.
- Les caractères 9 à 12 identifient le modèle ou le code de configuration.

Par exemple, `C02L13ECF8J2` suit cette structure héritée. Les correspondances d'usines maintenues par la communauté incluent des préfixes tels que `FC`, `F`, `XA`, `XB`, `QP` et `G8` pour des sites aux États-Unis ; `RN` pour le Mexique ; `CK` pour Cork ; `VM` pour un site Foxconn en République tchèque ; `SG` ou `E` pour Singapour ; `MB` pour la Malaisie ; `PT` ou `CY` pour la Corée ; et `EE`, `QT` ou `UV` pour Taïwan. De nombreux préfixes — notamment `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` et `C7` — ont été associés à des sites chinois ; `RM` a été associé à des appareils reconditionnés.<sup>[[3]](#references)</sup>

Les codes de date du quatrième caractère vont de `C` (premier semestre 2010) à `Z` (second semestre 2019), puis la séquence est réutilisée. Pour le cinquième caractère, les chiffres `1` à `9` représentent les semaines 1 à 9, tandis que les lettres `C` à `Y`, à l'exception des voyelles et de `S`, représentent les semaines 10 à 27 ; ajoutez 26 lorsque le quatrième caractère indique le second semestre d'une année.<sup>[[3]](#references)</sup>

Ces correspondances sont utiles pour le triage des anciens appareils, mais ne constituent pas une preuve irréfutable de l'origine, de l'âge ou de l'authenticité. Confirmez le résultat à l'aide des données d'inventaire d'Apple.

Pour une identification fiable, récupérez le numéro de série depuis l'appareil et utilisez la page de vérification de la couverture ou des spécifications techniques d'Apple, plutôt que d'essayer de déduire le modèle à partir de la position des caractères.<sup>[[2]](#references)</sup>

### Récupérer le numéro de série

L'interface graphique l'affiche sous **menu Apple > À propos de ce Mac**.<sup>[[2]](#references)</sup> Depuis un shell, l'une ou l'autre des commandes suivantes lit le numéro de série de la plateforme :
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Traitez un numéro de série comme un identifiant, et non comme un authentificateur : confirmez l’appareil via le workflow d’inventaire Apple ou MDM pertinent avant de prendre des décisions concernant l’enrollment ou la propriété.

## References

- [1] [MacRumors - Apple commence la transition vers des numéros de série randomisés](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Trouver le nom du modèle et le numéro de série de votre Mac](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Décoder la signification d’un numéro de série Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
