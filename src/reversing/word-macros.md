# Macros Word

{{#include ../banners/hacktricks-training.md}}

## Code inutile

Les macros peuvent contenir du **code inaccessible ou sans pertinence** destiné à ralentir l'analyse. Identifiez les conditions constantes et retracez le comportement accessible avant de consacrer du temps à l'inversion d'une branche. L'exemple ci-dessous utilise une condition `If` qui ne peut jamais être vraie afin de dissimuler du code inutile.

![Une macro Word contenant une branche conditionnelle inaccessible avec du code inutile](<../images/image (369).png>)

## Formulaires de macro

Les VBA UserForms peuvent stocker des données dans des contrôles tels que des zones de texte. Comme les formulaires, les cadres et les pages peuvent chacun exposer une collection `Controls`, les analystes doivent énumérer toute la hiérarchie des contrôles plutôt que de se limiter à ce que le formulaire affiche. L'exemple ci-dessous stocke des données dissimulées dans des zones de texte superposées.<sup>[[1]](#references)</sup>

Lors de l'analyse dynamique, la fonction VBA `GetObject` peut récupérer un objet Automation depuis un fichier ou se connecter à un serveur Automation déjà en cours d'exécution. Les macros peuvent utiliser cet accès à l'objet pour atteindre des données qui ne sont pas visibles dans le document affiché ; inspectez à la fois l'objet renvoyé et l'arborescence des contrôles du UserForm.<sup>[[2]](#references)</sup>

![Un UserForm de macro contenant des données dissimulées dans des zones de texte superposées](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, contrôles et objets (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Fonction `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
