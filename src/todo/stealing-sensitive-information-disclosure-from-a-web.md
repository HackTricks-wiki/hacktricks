# Voler des informations sensibles depuis une page web

{{#include ../banners/hacktricks-training.md}}

Si une **page web affiche des informations sensibles en fonction de la session actuelle**—telles que des cookies, des données de compte ou des informations de carte bancaire—un attaquant peut tenter de les exfiltrer. Les principales techniques incluent :

- [**CORS bypass**](../pentesting-web/cors-bypass.md) : Une mauvaise configuration de CORS peut permettre à une origine malveillante de lire des réponses sensibles via des requêtes cross-origin.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html) : Une vulnérabilité XSS dans l’origine cible peut permettre à du JavaScript injecté de lire et d’exfiltrer les informations.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html) : Lorsque l’injection de scripts n’est pas possible, des éléments HTML injectés peuvent tout de même capturer du contenu sensible.
- [**Clickjacking**](../pentesting-web/clickjacking.md) : Si les protections contre l’encadrement sont absentes, un attaquant peut inciter un utilisateur à interagir avec la page sensible. L’étude de cas liée présente cette technique.<sup>[[1]](#references)</sup>

## References

- [1] [Le servlet d’exemple Apache entraîne une divulgation d’informations](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
