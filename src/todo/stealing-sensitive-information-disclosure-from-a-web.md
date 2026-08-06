# Voler des informations sensibles divulguées par un site Web

{{#include ../banners/hacktricks-training.md}}

Si, à un moment donné, vous trouvez une **page Web qui vous présente des informations sensibles en fonction de votre session** : Peut-être qu'elle renvoie les cookies, ou affiche des informations de carte bancaire ou toute autre information sensible, vous pouvez essayer de les voler.\
Voici les principales méthodes que vous pouvez tenter pour y parvenir :

- [**CORS bypass**](../pentesting-web/cors-bypass.md) : Si vous pouvez contourner les en-têtes CORS, vous pourrez voler les informations en effectuant une requête Ajax depuis une page malveillante.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html) : Si vous trouvez une vulnérabilité XSS sur la page, vous pourrez peut-être l'exploiter pour voler les informations.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html) : Si vous ne pouvez pas injecter de balises XSS, vous pourrez peut-être tout de même voler les informations en utilisant d'autres balises HTML classiques.
- [**Clickjaking**](../pentesting-web/clickjacking.md) : S'il n'existe aucune protection contre cette attaque, vous pourrez peut-être tromper l'utilisateur pour qu'il vous envoie les données sensibles (un exemple [ici](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Références

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
