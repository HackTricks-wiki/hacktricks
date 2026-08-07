# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Il est très courant de trouver du **junk code qui n'est jamais utilisé** afin de rendre le reversing de la macro plus difficile.\
Par exemple, dans l'image suivante, vous pouvez voir qu'un `If` dont la condition ne sera jamais vraie est utilisé pour exécuter du junk code inutile.

![Word Macros - Junk Code : par exemple, dans l'image suivante, vous pouvez voir qu'un If dont la condition ne sera jamais vraie est utilisé pour exécuter du junk code inutile](<../images/image (369).png>)

### Macro Forms

En utilisant la fonction **GetObject**, il est possible d'obtenir des données provenant des forms de la macro. Cela peut être utilisé pour compliquer l'analyse. Voici une image d'une macro form utilisée pour **cacher des données à l'intérieur de zones de texte** (une zone de texte peut en cacher d'autres) :

![Junk Code - Macro Forms : en utilisant la fonction GetObject, il est possible d'obtenir des données provenant des forms de la macro. Cela peut être utilisé pour compliquer l'analyse. Voici une image d'une...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
