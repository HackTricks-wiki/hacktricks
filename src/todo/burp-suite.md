# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Types de payloads d'Intruder

Burp Intruder inclut les générateurs et transformations de payloads intégrés suivants :<sup>[[1]](#references)</sup>

- **Liste simple :** utilise une liste configurée de chaînes comme payloads.
- **Fichier d'exécution :** lit un payload par ligne au moment de l'exécution. Cela est utile pour les grandes listes, car Burp ne charge pas l'intégralité du fichier en mémoire.
- **Modification de la casse :** génère la valeur inchangée, les formes en minuscules et en majuscules, `Propername` (première lettre en majuscule et le reste en minuscules), ou `ProperName` (première lettre en majuscule, les caractères restants restant inchangés). Burp supprime les résultats en double.
- **Nombres :** génère des nombres séquentiels ou aléatoires dans une plage configurée.
- **Brute forcer :** génère toutes les permutations pour un jeu de caractères et une longueur minimale/maximale choisis.

## Extensions et outils associés

- **Collabfiltrator** génère des payloads qui exécutent des commandes et exfiltrent leur sortie via des requêtes DNS vers Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporte les résultats de Burp pour les utiliser dans d'autres workflows de reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** convertit les requêtes HTTP en scripts dans plusieurs langages.<sup>[[4]](#references)</sup>

## References

- [1] [Documentation de PortSwigger - types de payloads de Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
