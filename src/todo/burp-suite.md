# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Types de payloads Intruder

Burp Intruder inclut les générateurs et transformations de payloads intégrés suivants :<sup>[[1]](#references)</sup>

- **Simple list:** Utiliser une liste configurée de chaînes comme payloads.
- **Runtime file:** Lire un payload par ligne à l’exécution. C’est utile pour les grandes listes, car Burp ne charge pas tout le fichier en mémoire.
- **Case modification:** Générer la valeur inchangée, en minuscules et en majuscules, au format `Propername` (première lettre en majuscule et le reste en minuscules) ou `ProperName` (première lettre en majuscule et caractères restants inchangés). Burp élimine les doublons.
- **Numbers:** Générer des nombres séquentiels ou aléatoires dans une plage configurée.
- **Brute forcer:** Générer toutes les permutations pour un jeu de caractères et une longueur minimale/maximale choisis.

## Extensions et outils complémentaires

- **Collabfiltrator** génère des payloads qui exécutent des commandes et exfiltrent leur résultat via des requêtes DNS vers Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporte les résultats de Burp pour les utiliser dans d’autres processus de création de rapports.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** convertit les requêtes HTTP en scripts dans plusieurs langages.<sup>[[4]](#references)</sup>

## Tests d’autorisation multi-session avec Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) est une extension Java pour Burp Suite `2025.5+` qui stocke les cookies et les en-têtes peu courants dans des profils d’identifiants nommés. La sélection d’un profil dans un éditeur de requêtes modifiable, notamment Repeater ou une requête Proxy interceptée, remplace les éléments d’authentification de la requête. C’est une aide à la relecture, **pas un contournement d’autorisation** : utilisez-la pour envoyer la même requête avec différents comptes afin de vérifier les accès horizontaux, les limites entre rôles, l’isolation des tenants et les vulnérabilités [IDOR/BOLA](../pentesting-web/idor.md), dans le cadre de la [méthodologie de test web](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Flux de travail reproductible pour comparer les identités

Le flux de travail suivant distingue la ressource/l’action de l’identité utilisée, réduisant ainsi les faux résultats dus à des tokens périmés ou à une mauvaise session de navigateur.<sup>[[5]](#references)[[8]](#references)</sup>

1. Authentifiez des comptes de test représentant chaque utilisateur, rôle et tenant pertinent dans des profils de navigateur ou des conteneurs distincts.
2. Ouvrez une requête contenant les cookies et en-têtes d’une identité, sélectionnez **Sessions > New**, puis attribuez au profil un nom explicite, par exemple `tenant-a-user` ou `tenant-b-admin`. Répétez pour chaque identité de test.
3. Envoyez une requête candidate à Repeater et rejouez-la sans modifier sa méthode, son endpoint, ses paramètres ni l’identifiant de l’objet, en changeant uniquement la session sélectionnée. Comparez les données de réponse et les changements d’état observables, pas seulement les codes de statut.
4. Pour les vérifications au niveau des objets, rejouez une requête visant un objet dont on sait qu’il appartient au compte A tout en sélectionnant le profil du compte B. Pour les vérifications au niveau des fonctions, rejouez la même action privilégiée avec des profils aux privilèges inférieurs.
5. Après une nouvelle authentification ou une rotation de token, utilisez **Update** sur une requête actuelle du navigateur ou configurez une règle Auto Update avant de répéter la comparaison.

### Sémantique de capture et d’injection

Examinez les modes de mise à jour/d’injection avant les tests, car une requête hybride contenant des identifiants de deux identités peut fausser la comparaison. Par défaut, les paramètres actuels recopient tous les cookies de la requête dans un profil, ne mettent à jour que les en-têtes peu courants déjà enregistrés, recopient les cookies du profil sélectionné dans la requête de destination (en supprimant ses cookies existants) et ajoutent les en-têtes du profil. Le sélecteur peut être limité à un sous-domaine exact, au domaine de premier niveau de l’application (par défaut) ou à tous les profils enregistrés.<sup>[[7]](#references)</sup>

- **Mirror** est utile lorsque l’ensemble complet des cookies définit une identité et qu’il faut supprimer les cookies périmés de la requête de destination.
- **Update existing** suit les valeurs qui changent sans récupérer de cookies ou d’en-têtes sans rapport depuis le trafic du navigateur.
- **Add all** conserve les valeurs supplémentaires déjà enregistrées dans le profil ou la requête ; vérifiez que cela ne laisse pas de données d’identification de la session précédente.
- **Do nothing** exclut les cookies ou les en-têtes des mises à jour du profil lorsque cette catégorie d’identifiants n’est pas pertinente.

### Synchronisation des sessions via Proxy

Les règles Auto Update associent le trafic Proxy à un profil enregistré et actualisent ses cookies/en-têtes. Privilégiez un indicateur stable, tel qu’un en-tête de requête dédié, un marqueur `User-Agent` propre au profil, un cookie d’identification, `X-PwnFox-Color` ou une revendication JWT ; combinez-le avec des conditions de portée/domaine/chemin afin que des applications sans rapport ne puissent pas mettre à jour le profil. Toutes les conditions d’une même règle sont évaluées dans l’ordre avec un opérateur logique `AND` ; placez donc les vérifications les plus restrictives en premier. Pour implémenter un `OR`, créez plusieurs règles ciblant le même profil. Les correspondances négatives sont également prises en charge.<sup>[[6]](#references)</sup>

Pour chaque règle correspondante, choisissez **Mirror request**, **Add all**, **Update existing** ou **Do nothing** séparément pour les cookies et les en-têtes. Les règles portant uniquement sur les requêtes s’exécutent lorsque Proxy reçoit la requête ; l’ajout d’une condition portant sur le statut, un en-tête ou le corps de la réponse reporte l’évaluation jusqu’à l’arrivée de celle-ci. Une couleur de surbrillance peut marquer le trafic correspondant, ce qui aide à vérifier que chaque identité de navigateur ne met à jour que le profil qui lui est destiné.<sup>[[6]](#references)</sup>

Les profils enregistrés se trouvent dans le projet Burp, et les exportations de données du projet au format JSON incluent les sessions, et donc leurs cookies et en-têtes. Traitez ces deux fichiers comme des identifiants actifs, limitez-en l’accès et supprimez les données enregistrées de l’extension après l’intervention.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [Documentation PortSwigger - Types de payloads Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Documentation sur le code source et l’utilisation de Session Switcher](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Règles Auto Update de Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Paramètres de Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher : simplifier les tests d’autorisation multi-session dans Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
