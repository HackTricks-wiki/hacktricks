# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Il est très courant de trouver **du code inutile qui n'est jamais utilisé** pour rendre le reverse engineering de la macro plus difficile.\
Par exemple, dans l'image suivante, vous pouvez voir qu'un If qui ne sera jamais vrai est utilisé pour exécuter du code inutile.

![](<../images/image (369).png>)

### Macro Forms

En utilisant la fonction **GetObject**, il est possible d'obtenir des données à partir des formulaires de la macro. Cela peut être utilisé pour compliquer l'analyse. La photo suivante montre un formulaire de macro utilisé pour **cacher des données à l'intérieur de zones de texte** (une zone de texte peut cacher d'autres zones de texte) :

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
