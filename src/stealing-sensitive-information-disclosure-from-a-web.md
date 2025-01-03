# Vol de la divulgation d'informations sensibles à partir d'un Web

{{#include ./banners/hacktricks-training.md}}

Si à un moment donné vous trouvez une **page web qui vous présente des informations sensibles basées sur votre session** : Peut-être qu'elle reflète des cookies, ou imprime des détails de carte de crédit ou toute autre information sensible, vous pouvez essayer de les voler.\
Voici les principales méthodes que vous pouvez essayer d'atteindre :

- [**CORS bypass**](pentesting-web/cors-bypass.md) : Si vous pouvez contourner les en-têtes CORS, vous pourrez voler les informations en effectuant une requête Ajax pour une page malveillante.
- [**XSS**](pentesting-web/xss-cross-site-scripting/) : Si vous trouvez une vulnérabilité XSS sur la page, vous pourrez peut-être en abuser pour voler les informations.
- [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/) : Si vous ne pouvez pas injecter de balises XSS, vous pourrez toujours voler les informations en utilisant d'autres balises HTML régulières.
- [**Clickjaking**](pentesting-web/clickjacking.md) : S'il n'y a pas de protection contre cette attaque, vous pourrez peut-être tromper l'utilisateur pour qu'il vous envoie les données sensibles (un exemple [ici](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ./banners/hacktricks-training.md}}
