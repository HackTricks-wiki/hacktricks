# Attaque par extension de longueur de hachage

{{#include ../banners/hacktricks-training.md}}

## Résumé de l'attaque

Imaginez un serveur qui **signe** des **données** en **ajoutant** un **secret** à des données en clair connues, puis en hachant ces données. Si vous savez :

- **La longueur du secret** (cela peut également être bruteforced à partir d'une plage de longueurs donnée)
- **Les données en clair**
- **L'algorithme (et il est vulnérable à cette attaque)**
- **Le remplissage est connu**
- En général, un par défaut est utilisé, donc si les 3 autres exigences sont remplies, cela l'est aussi
- Le remplissage varie en fonction de la longueur du secret + données, c'est pourquoi la longueur du secret est nécessaire

Alors, il est possible pour un **attaquant** d'**ajouter** des **données** et de **générer** une **signature** valide pour les **données précédentes + données ajoutées**.

### Comment ?

Fondamentalement, les algorithmes vulnérables génèrent les hachages en **hachant d'abord un bloc de données**, puis, **à partir** du **hachage** **précédemment** créé (état), ils **ajoutent le prochain bloc de données** et **le hachent**.

Ensuite, imaginez que le secret est "secret" et que les données sont "data", le MD5 de "secretdata" est 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un attaquant veut ajouter la chaîne "append", il peut :

- Générer un MD5 de 64 "A"
- Changer l'état du hachage précédemment initialisé en 6036708eba0d11f6ef52ad44e8b74d5b
- Ajouter la chaîne "append"
- Terminer le hachage et le hachage résultant sera un **valide pour "secret" + "data" + "padding" + "append"**

### **Outil**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

### Références

Vous pouvez trouver cette attaque bien expliquée sur [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
