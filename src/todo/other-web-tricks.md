# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

À plusieurs reprises, le back-end fait confiance au **Host header** pour effectuer certaines actions. Par exemple, il peut utiliser sa valeur comme **domaine auquel envoyer un password reset**. Ainsi, lorsque vous recevez un e-mail contenant un lien pour réinitialiser votre mot de passe, le domaine utilisé est celui que vous avez indiqué dans le Host header. Vous pouvez alors demander le password reset d'autres utilisateurs et remplacer le domaine par un domaine que vous contrôlez afin de voler leurs codes de password reset. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Notez qu'il est possible que vous n'ayez même pas besoin d'attendre que l'utilisateur clique sur le lien de password reset pour obtenir le token, car il est possible que **des spam filters ou d'autres appareils/bots intermédiaires cliquent dessus pour l'analyser**.

### Session booleans

Parfois, lorsque vous terminez correctement une vérification, le back-end **ajoute simplement un boolean avec la valeur "True" à un attribut de sécurité de votre session**. Ensuite, un autre endpoint vérifie si vous avez réussi ce contrôle.\
Cependant, si vous **réussissez le contrôle** et que votre session reçoit cette valeur "True" dans l'attribut de sécurité, vous pouvez essayer **d'accéder à d'autres ressources** qui **dépendent du même attribut**, mais auxquelles vous **ne devriez pas avoir les permissions** d'accéder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Essayez de vous enregistrer avec un utilisateur qui existe déjà. Essayez également d'utiliser des caractères équivalents (points, nombreux espaces et Unicode).

### Takeover emails

Enregistrez une adresse e-mail, puis modifiez-la avant de la confirmer. Ensuite, si le nouvel e-mail de confirmation est envoyé à la première adresse e-mail enregistrée, vous pouvez takeover n'importe quelle adresse e-mail. Ou, si vous pouvez activer la seconde adresse e-mail en confirmant la première, vous pouvez également takeover n'importe quel compte.

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Les développeurs peuvent oublier de désactiver diverses options de debugging dans l'environnement de production. Par exemple, la méthode HTTP `TRACE` est conçue à des fins de diagnostic. Si elle est activée, le serveur web répond aux requêtes utilisant la méthode `TRACE` en renvoyant dans la réponse la requête exacte qui a été reçue. Ce comportement est souvent inoffensif, mais peut parfois entraîner une divulgation d'informations, comme le nom de headers d'authentification internes qui peuvent être ajoutés aux requêtes par des reverse proxies.![Image pour le post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image pour le post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Comment j'ai pu takeover le compte de n'importe quel utilisateur avec une injection de Host Header](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
