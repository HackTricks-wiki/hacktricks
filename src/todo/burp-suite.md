# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Payloads de base

- **Simple List :** Une simple liste contenant une entrée par ligne
- **Runtime File :** Une liste lue au runtime (non chargée en mémoire). Pour prendre en charge les grandes listes.
- **Case Modification :** Appliquer certaines modifications à une liste de chaînes (aucune modification, en minuscules, en MAJUSCULES, en nom propre - première lettre en majuscule et le reste en minuscules -, en Nom Propre - première lettre en majuscule et le reste inchangé -).
- **Numbers :** Générer des nombres de X à Y avec un pas de Z ou aléatoirement.
- **Brute Forcer :** Jeu de caractères, longueur minimale et maximale.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload permettant d'exécuter des commandes et d'en récupérer la sortie via des requêtes DNS vers burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
