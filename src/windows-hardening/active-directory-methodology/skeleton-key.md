# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Attaque Skeleton Key

L'**attaque Skeleton Key** est une technique sophistiquée qui permet aux attaquants de **contourner l'authentification Active Directory** en **injectant un mot de passe maître** dans le contrôleur de domaine. Cela permet à l'attaquant de **s'authentifier en tant que n'importe quel utilisateur** sans son mot de passe, lui **accordant ainsi un accès illimité** au domaine.

Elle peut être réalisée en utilisant [Mimikatz](https://github.com/gentilkiwi/mimikatz). Pour mener à bien cette attaque, **des droits d'administrateur de domaine sont nécessaires**, et l'attaquant doit cibler chaque contrôleur de domaine pour garantir une violation complète. Cependant, l'effet de l'attaque est temporaire, car **le redémarrage du contrôleur de domaine éradiquer le malware**, nécessitant une réimplémentation pour un accès durable.

**L'exécution de l'attaque** nécessite une seule commande : `misc::skeleton`.

## Atténuations

Les stratégies d'atténuation contre de telles attaques incluent la surveillance de certains ID d'événements qui indiquent l'installation de services ou l'utilisation de privilèges sensibles. En particulier, rechercher l'ID d'événement système 7045 ou l'ID d'événement de sécurité 4673 peut révéler des activités suspectes. De plus, exécuter `lsass.exe` en tant que processus protégé peut considérablement entraver les efforts des attaquants, car cela nécessite qu'ils utilisent un pilote en mode noyau, augmentant ainsi la complexité de l'attaque.

Voici les commandes PowerShell pour renforcer les mesures de sécurité :

- Pour détecter l'installation de services suspects, utilisez : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- En particulier, pour détecter le pilote de Mimikatz, la commande suivante peut être utilisée : `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Pour renforcer `lsass.exe`, il est recommandé de l'activer en tant que processus protégé : `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

La vérification après un redémarrage du système est cruciale pour s'assurer que les mesures de protection ont été appliquées avec succès. Cela peut être réalisé par : `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Références

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
