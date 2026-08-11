# Autres astuces web

{{#include ../banners/hacktricks-training.md}}

## Host header

Les backends font parfois confiance au champ HTTP `Host` lors de la construction de liens absolus. Si un e-mail de réinitialisation de mot de passe utilise un host fourni par l'attaquant, demander une réinitialisation pour une victime peut envoyer un lien contenant un token via un domaine contrôlé par l'attaquant. Testez également les champs forwarded-host, la gestion des `Host` en double et les cibles de requête en forme absolue à chaque étape du proxy.<sup>[[1]](#references)</sup>

> [!WARNING]
> Le clic d'un utilisateur peut ne pas être nécessaire : **les scanners de sécurité des e-mails, les services d'aperçu ou d'autres intermédiaires peuvent demander automatiquement le lien contrôlé par l'attaquant**, divulguant ainsi le token de réinitialisation.

## Booléens de session

Certaines applications enregistrent une vérification terminée sous forme de booléen dans la session, puis permettent à un autre endpoint de se fier à ce flag. Après avoir légitimement réussi la vérification pour une ressource, testez si le même flag autorise incorrectement un autre utilisateur, objet ou workflow. Il s'agit d'une faille d'autorisation/réutilisation d'état de second ordre, et pas simplement d'un IDOR.<sup>[[2]](#references)</sup>

## Fonctionnalité d'inscription

Essayez de vous inscrire en tant qu'utilisateur déjà existant. Essayez également d'utiliser des caractères équivalents (points, nombreux espaces et Unicode).

## Confusion d'état lors du changement d'e-mail

Enregistrez une adresse e-mail, puis modifiez-la avant de la confirmer. Vérifiez si la confirmation de la nouvelle adresse est envoyée à l'ancienne adresse, ou si la confirmation de l'ancien token active la nouvelle adresse. Les tokens de confirmation doivent être liés au compte exact, à l'adresse en attente, à l'objectif et à l'état actuel.

## Services desks Atlassian exposés


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## Méthode TRACE

La méthode HTTP `TRACE` demande une retransmission de la requête reçue à des fins de diagnostic. La RFC 9110 exige que les destinataires omettent du contenu réfléchi les champs sensibles tels que les identifiants et les cookies, mais des implémentations non sécurisées ou des en-têtes ajoutés par des intermédiaires peuvent tout de même divulguer les transformations internes de la requête. Les navigateurs empêchent les requêtes `TRACE` générées par des scripts ; l'attaque historique de cross-site tracing dépend donc également d'un autre moyen d'injecter des champs protégés.<sup>[[3]](#references)</sup>![Image showing a TRACE response](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Comment j'ai pu prendre le contrôle du compte de n'importe quel utilisateur avec une injection de Host Header](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Un vecteur d'attaque moins connu : les attaques IDOR de second ordre](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
