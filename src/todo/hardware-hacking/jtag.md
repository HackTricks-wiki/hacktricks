# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum) est un outil qui peut être utilisé avec un Raspberry PI ou un Arduino pour essayer de trouver les broches JTAG d'une puce inconnue.\
Dans l'**Arduino**, connectez les **broches de 2 à 11 à 10 broches potentiellement appartenant à un JTAG**. Chargez le programme dans l'Arduino et il essaiera de brute-forcer toutes les broches pour déterminer si l'une d'elles appartient à JTAG et laquelle est laquelle.\
Dans le **Raspberry PI**, vous ne pouvez utiliser que **les broches de 1 à 6** (6 broches, donc vous avancerez plus lentement en testant chaque broche JTAG potentielle).

### Arduino

Dans Arduino, après avoir connecté les câbles (broche 2 à 11 aux broches JTAG et GND Arduino au GND de la carte de base), **chargez le programme JTAGenum dans Arduino** et dans le Moniteur Série, envoyez un **`h`** (commande pour l'aide) et vous devriez voir l'aide :

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Configurez **"Pas de fin de ligne" et 115200baud**.\
Envoyez la commande s pour commencer le scan :

![](<../../images/image (774).png>)

Si vous contactez un JTAG, vous trouverez une ou plusieurs **lignes commençant par FOUND!** indiquant les broches de JTAG.

{{#include ../../banners/hacktricks-training.md}}
