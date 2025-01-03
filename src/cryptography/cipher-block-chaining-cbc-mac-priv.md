{{#include ../banners/hacktricks-training.md}}

# CBC

Si le **cookie** est **uniquement** le **nom d'utilisateur** (ou si la première partie du cookie est le nom d'utilisateur) et que vous souhaitez usurper le nom d'utilisateur "**admin**". Alors, vous pouvez créer le nom d'utilisateur **"bdmin"** et **bruteforcer** le **premier octet** du cookie.

# CBC-MAC

**Code d'authentification de message par chaîne de blocs chiffrés** (**CBC-MAC**) est une méthode utilisée en cryptographie. Elle fonctionne en prenant un message et en l'encryptant bloc par bloc, où l'encryption de chaque bloc est liée à celle du bloc précédent. Ce processus crée une **chaîne de blocs**, garantissant que changer même un seul bit du message original entraînera un changement imprévisible dans le dernier bloc de données chiffrées. Pour effectuer ou inverser un tel changement, la clé de chiffrement est requise, assurant la sécurité.

Pour calculer le CBC-MAC du message m, on chiffre m en mode CBC avec un vecteur d'initialisation nul et on conserve le dernier bloc. La figure suivante esquisse le calcul du CBC-MAC d'un message composé de blocs ![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) en utilisant une clé secrète k et un chiffre par blocs E :

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Vulnérabilité

Avec CBC-MAC, généralement le **IV utilisé est 0**.\
C'est un problème car 2 messages connus (`m1` et `m2`) généreront indépendamment 2 signatures (`s1` et `s2`). Donc :

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Ensuite, un message composé de m1 et m2 concaténés (m3) générera 2 signatures (s31 et s32) :

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Ce qui est possible à calculer sans connaître la clé de chiffrement.**

Imaginez que vous chiffrez le nom **Administrator** en blocs de **8 octets** :

- `Administ`
- `rator\00\00\00`

Vous pouvez créer un nom d'utilisateur appelé **Administ** (m1) et récupérer la signature (s1).\
Ensuite, vous pouvez créer un nom d'utilisateur appelé le résultat de `rator\00\00\00 XOR s1`. Cela générera `E(m2 XOR s1 XOR 0)` qui est s32.\
Maintenant, vous pouvez utiliser s32 comme la signature du nom complet **Administrator**.

### Résumé

1. Obtenez la signature du nom d'utilisateur **Administ** (m1) qui est s1
2. Obtenez la signature du nom d'utilisateur **rator\x00\x00\x00 XOR s1 XOR 0** qui est s32**.**
3. Définissez le cookie sur s32 et ce sera un cookie valide pour l'utilisateur **Administrator**.

# Attaque Contrôlant IV

Si vous pouvez contrôler l'IV utilisé, l'attaque pourrait être très facile.\
Si le cookie est juste le nom d'utilisateur chiffré, pour usurper l'utilisateur "**administrator**", vous pouvez créer l'utilisateur "**Administrator**" et vous obtiendrez son cookie.\
Maintenant, si vous pouvez contrôler l'IV, vous pouvez changer le premier octet de l'IV de sorte que **IV\[0] XOR "A" == IV'\[0] XOR "a"** et régénérer le cookie pour l'utilisateur **Administrator.** Ce cookie sera valide pour **usurper** l'utilisateur **administrator** avec l'**IV** initial.

## Références

Plus d'informations sur [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
