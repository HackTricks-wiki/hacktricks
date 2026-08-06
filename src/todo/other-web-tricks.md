# Autres astuces Web

{{#include ../banners/hacktricks-training.md}}

### Host header

À plusieurs reprises, le back-end fait confiance au **Host header** pour effectuer certaines actions. Par exemple, il peut utiliser sa valeur comme **domaine auquel envoyer une réinitialisation de mot de passe**. Ainsi, lorsque vous recevez un e-mail contenant un lien pour réinitialiser votre mot de passe, le domaine utilisé est celui que vous avez placé dans le Host header. Ensuite, vous pouvez demander la réinitialisation du mot de passe d'autres utilisateurs et modifier le domaine pour utiliser un domaine que vous contrôlez afin de voler leurs codes de réinitialisation de mot de passe. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Notez qu'il est possible que vous n'ayez même pas besoin d'attendre que l'utilisateur clique sur le lien de réinitialisation du mot de passe pour obtenir le token, car **les filtres anti-spam ou d'autres appareils/bots intermédiaires peuvent cliquer dessus pour l'analyser**.

### Booléens de session

Parfois, lorsque vous terminez correctement une vérification, le back-end **ajoute simplement un booléen ayant la valeur "True" à un attribut de sécurité de votre session**. Ensuite, un autre endpoint saura si vous avez réussi cette vérification.\
Cependant, si vous **réussissez la vérification** et que votre session reçoit cette valeur "True" dans l'attribut de sécurité, vous pouvez essayer **d'accéder à d'autres ressources** qui **dépendent du même attribut**, mais auxquelles vous **ne devriez pas avoir les permissions** d'accéder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Fonctionnalité d'inscription

Essayez de vous inscrire en tant qu'utilisateur déjà existant. Essayez également d'utiliser des caractères équivalents (points, nombreux espaces et Unicode).

### Prise de contrôle d'e-mails

Enregistrez une adresse e-mail, puis modifiez-la avant de la confirmer. Ensuite, si le nouvel e-mail de confirmation est envoyé à la première adresse e-mail enregistrée, vous pouvez prendre le contrôle de n'importe quelle adresse e-mail. Ou, si vous pouvez activer la deuxième adresse e-mail en confirmant la première, vous pouvez également prendre le contrôle de n'importe quel compte.

### Accéder au servicedesk interne d'entreprises utilisant atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Méthode TRACE

Les développeurs peuvent oublier de désactiver diverses options de debug dans l'environnement de production. Par exemple, la méthode HTTP `TRACE` est conçue à des fins de diagnostic. Si elle est activée, le serveur Web répond aux requêtes utilisant la méthode `TRACE` en renvoyant dans la réponse la requête exacte qui a été reçue. Ce comportement est souvent inoffensif, mais peut parfois entraîner une divulgation d'informations, comme le nom des en-têtes d'authentification internes qui peuvent être ajoutés aux requêtes par des reverse proxies.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Références

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
