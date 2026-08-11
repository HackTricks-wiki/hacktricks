# Macros Word

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Les macros peuvent contenir du **code inaccessible ou non pertinent** destiné à ralentir l'analyse. Identifiez les conditions constantes et suivez le comportement accessible avant de consacrer du temps à l'analyse inversée d'une branche. L'exemple ci-dessous utilise une condition `If` qui ne peut jamais être vraie afin de dissimuler du Junk Code.

![Une macro Word contenant une branche conditionnelle inaccessible avec du Junk Code](<../images/image (369).png>)

## Macro Forms

Les UserForms VBA peuvent stocker des données dans des contrôles tels que des zones de texte. Comme les forms, frames et pages peuvent chacune exposer une collection `Controls`, les analystes doivent énumérer toute la hiérarchie des contrôles plutôt que de se fier uniquement à ce que le form affiche. L'exemple ci-dessous stocke des données dissimulées dans des zones de texte superposées.<sup>[[1]](#references)</sup>

![Un UserForm de macro contenant des données dissimulées dans des zones de texte superposées](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, contrôles et objets (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
