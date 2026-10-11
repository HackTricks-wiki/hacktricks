# Indicateurs d’escalade via les sessions SUSE et les services de disque

{{#include ../../banners/hacktricks-training.md}}

## Autorisation des sessions SSH via PAM

CVE-2025-6018 affectait les configurations PAM de SUSE 15 dans lesquelles une pile d’authentification SSH chargeait `pam_env` avant que la pile de session ne charge `pam_systemd`. Lorsque `pam_env` lisait le fichier `.pam_environment` d’un utilisateur, celui-ci pouvait fournir des valeurs `XDG_SEAT` et `XDG_VTNR` donnant à Polkit l’impression que la session SSH était physiquement active. Une action `allow_active=yes` pouvait alors devenir accessible à un utilisateur distant. Cela modifie l’autorisation de session ; cela ne garantit pas à lui seul l’accès root. SUSE a corrigé le comportement par défaut lié à l’environnement utilisateur dans `pam` et l’emplacement du module généré par `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Inspectez la chaîne d’inclusion effective de `/etc/pam.d/sshd`, l’ordre de `pam_env.so` et `pam_systemd.so`, ainsi que toute option explicite `user_readenv=1`. Un paquet `pam` corrigé modifie le comportement par défaut, mais une option explicite peut toujours demander la lecture de l’environnement utilisateur. Un paquet `pam-config` plus récent ne prouve pas qu’une pile PAM modifiée localement ou obsolète a été régénérée. Vérifiez ensemble la version du paquet du fournisseur et la configuration réelle.<sup>[[1]](#references)[[2]](#references)</sup>

## Voie d’accès au service de disque pour un utilisateur actif

CVE-2025-6019 était une voie d’escalade dans `libblockdev`, utilisé via `udisks2` : lors d’un redimensionnement XFS, un système de fichiers fourni par un attaquant pouvait être temporairement monté sans la restriction `nosuid` attendue. Cette voie nécessite un service D-Bus UDisks opérationnel, la prise en charge du redimensionnement XFS, une action Polkit pertinente accessible à l’appelant et une version vulnérable de la bibliothèque. CVE-2025-6018 permet notamment d’obtenir une session d’utilisateur actif, mais un utilisateur déjà actif peut accéder indépendamment à cette voie via le service de disque.<sup>[[3]](#references)</sup>

Pour un examen passif, vérifiez les métadonnées du service UDisks, la stratégie `org.freedesktop.udisks2.modify-device`, `xfs_growfs` et le paquet `libbd_fs2` installé. SUSE indique que la version `2.26-150400.3.5.1` de `libbd_fs2` corrige le problème pour openSUSE Leap 15.6 ; la version exacte corrigée dépend du produit. La présence d’une stratégie et d’un paquet constitue une piste, mais ne prouve pas qu’un appelant puisse monter ou redimensionner un périphérique. Évitez de modifier les montages ou d’appeler des méthodes D-Bus pendant l’énumération.<sup>[[3]](#references)</sup>

## References

- [1] [Avis SUSE CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Mise à jour de sécurité SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Avis SUSE CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
