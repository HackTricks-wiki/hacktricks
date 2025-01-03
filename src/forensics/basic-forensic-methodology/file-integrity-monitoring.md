{{#include ../../banners/hacktricks-training.md}}

# Ligne de base

Une ligne de base consiste à prendre un instantané de certaines parties d'un système pour **le comparer avec un état futur afin de mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hachage de chaque fichier du système de fichiers pour pouvoir déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes d'utilisateurs créés, les processus en cours d'exécution, les services en cours d'exécution et toute autre chose qui ne devrait pas changer beaucoup, ou pas du tout.

## Surveillance de l'intégrité des fichiers

La Surveillance de l'intégrité des fichiers (FIM) est une technique de sécurité critique qui protège les environnements informatiques et les données en suivant les changements dans les fichiers. Elle implique deux étapes clés :

1. **Comparaison de la ligne de base :** Établir une ligne de base en utilisant des attributs de fichiers ou des sommes de contrôle cryptographiques (comme MD5 ou SHA-2) pour des comparaisons futures afin de détecter les modifications.
2. **Notification de changement en temps réel :** Recevoir des alertes instantanées lorsque des fichiers sont accédés ou modifiés, généralement par le biais d'extensions du noyau OS.

## Outils

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Références

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
