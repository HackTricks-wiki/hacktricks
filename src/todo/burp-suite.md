# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Types de payloads Intruder

- **Liste simple :** Utilise une liste configurée de chaînes comme payloads.
- **Fichier runtime :** Lit un payload par ligne au runtime. Cela est utile pour les listes volumineuses, car Burp ne charge pas le fichier entier en mémoire.
- **Modification de la casse :** Modifie la casse d'une chaîne d'entrée, par exemple en minuscules, en majuscules, en casse de phrase ou en casse de titre.
- **Nombres :** Génère des nombres séquentiels ou aléatoires dans une plage configurée.
- **Brute forcer :** Génère toutes les permutations pour un jeu de caractères et une longueur minimale/maximale choisis.<sup>[[1]](#references)</sup>

## Extensions et outils complémentaires

- **Collabfiltrator** génère des payloads qui exécutent des commandes et exfiltrent leur sortie via des requêtes DNS vers Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporte les résultats de Burp pour les utiliser dans d'autres workflows de reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** convertit les requêtes HTTP en scripts dans plusieurs langages.<sup>[[4]](#references)</sup>

## References

- [1] [Documentation PortSwigger - Types de payloads de Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
