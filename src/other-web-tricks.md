# Autres astuces Web

{{#include ./banners/hacktricks-training.md}}


### En-tête d'hôte

Plusieurs fois, le back-end fait confiance à l'**en-tête d'hôte** pour effectuer certaines actions. Par exemple, il pourrait utiliser sa valeur comme le **domaine pour envoyer une réinitialisation de mot de passe**. Donc, lorsque vous recevez un e-mail avec un lien pour réinitialiser votre mot de passe, le domaine utilisé est celui que vous avez mis dans l'en-tête d'hôte. Ensuite, vous pouvez demander la réinitialisation du mot de passe d'autres utilisateurs et changer le domaine pour un contrôlé par vous afin de voler leurs codes de réinitialisation de mot de passe. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Notez qu'il est possible que vous n'ayez même pas besoin d'attendre que l'utilisateur clique sur le lien de réinitialisation du mot de passe pour obtenir le jeton, car peut-être même **les filtres anti-spam ou d'autres dispositifs/bots intermédiaires cliqueront dessus pour l'analyser**.


### Booléens de session

Parfois, lorsque vous complétez correctement une vérification, le back-end **ajoute simplement un booléen avec la valeur "True" à un attribut de sécurité de votre session**. Ensuite, un point de terminaison différent saura si vous avez réussi à passer cette vérification.\
Cependant, si vous **passez la vérification** et que votre session se voit attribuer cette valeur "True" dans l'attribut de sécurité, vous pouvez essayer d'**accéder à d'autres ressources** qui **dépendent du même attribut** mais auxquelles vous **ne devriez pas avoir accès**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Fonctionnalité d'enregistrement

Essayez de vous enregistrer en tant qu'utilisateur déjà existant. Essayez également d'utiliser des caractères équivalents (points, beaucoup d'espaces et Unicode).

### Prise de contrôle des e-mails

Enregistrez un e-mail, avant de le confirmer, changez l'e-mail, puis, si le nouvel e-mail de confirmation est envoyé au premier e-mail enregistré, vous pouvez prendre le contrôle de n'importe quel e-mail. Ou si vous pouvez activer le deuxième e-mail confirmant le premier, vous pouvez également prendre le contrôle de n'importe quel compte.

### Accéder au service desk interne des entreprises utilisant Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Méthode TRACE

Les développeurs peuvent oublier de désactiver diverses options de débogage dans l'environnement de production. Par exemple, la méthode HTTP `TRACE` est conçue à des fins de diagnostic. Si elle est activée, le serveur web répondra aux requêtes utilisant la méthode `TRACE` en écho dans la réponse la requête exacte qui a été reçue. Ce comportement est souvent inoffensif, mais conduit parfois à une divulgation d'informations, comme le nom des en-têtes d'authentification internes qui peuvent être ajoutés aux requêtes par des proxies inverses.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)


{{#include ./banners/hacktricks-training.md}}
