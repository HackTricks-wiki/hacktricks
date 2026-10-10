# Indicateurs d’escalade liés aux sessions SUSE et aux services de disque

{{#include ../../banners/hacktricks-training.md}}

## Autorisation des sessions SSH via PAM

CVE-2025-6018 affectait les configurations PAM de SUSE 15 dans lesquelles une pile d’authentification SSH chargeait `pam_env` avant que la pile de session ne charge `pam_systemd`. Lorsque `pam_env` lisait le fichier `.pam_environment` d’un utilisateur, celui-ci pouvait fournir des valeurs `XDG_SEAT` et `XDG_VTNR` faisant apparaître une session SSH comme physiquement active auprès de Polkit. Une action `allow_active=yes` pouvait alors devenir accessible à un utilisateur distant. Cela modifie l’autorisation de session, mais ne garantit pas à lui seul un accès root. SUSE a corrigé le comportement par défaut lié à l’environnement utilisateur dans `pam`, ainsi que l’emplacement du module généré par `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Examinez la chaîne d’inclusion effective de `/etc/pam.d/sshd`, l’ordre de `pam_env.so` et `pam_systemd.so`, ainsi que toute option explicite `user_readenv=1`. Un paquet `pam` corrigé modifie le comportement par défaut, mais une option explicite peut toujours demander la lecture de l’environnement utilisateur. La présence d’un paquet `pam-config` plus récent ne prouve pas qu’une pile PAM modifiée localement ou obsolète a été régénérée. Vérifiez ensemble la version du paquet fournie par l’éditeur et la configuration réelle.<sup>[[1]](#references)[[2]](#references)</sup>

## Vecteur d’attaque du service de disque pour un utilisateur actif

CVE-2025-6019 était un vecteur d’escalade dans `libblockdev`, utilisé via `udisks2` : lors du redimensionnement d’un système de fichiers XFS, un système de fichiers fourni par un attaquant pouvait être temporairement monté sans la restriction `nosuid` attendue. Ce vecteur nécessite un service UDisks D-Bus utilisable, la prise en charge du redimensionnement XFS, une action Polkit pertinente accessible à l’appelant et un paquet de bibliothèque vulnérable. CVE-2025-6018 est un moyen d’obtenir une session d’utilisateur actif, mais un utilisateur déjà actif peut accéder au vecteur du service de disque indépendamment.<sup>[[3]](#references)</sup>

Pour un examen passif, vérifiez les métadonnées du service UDisks, la règle `org.freedesktop.udisks2.modify-device`, `xfs_growfs` et le paquet `libbd_fs2` installé. SUSE indique que la version `2.26-150400.3.5.1` de `libbd_fs2` corrige le problème pour openSUSE Leap 15.6 ; la version exacte contenant le correctif dépend du produit. La présence de la règle et du paquet constitue uniquement une piste, et ne prouve pas qu’un appelant peut monter ou redimensionner un périphérique. Évitez de modifier les montages ou d’appeler des méthodes D-Bus pendant l’énumération.<sup>[[3]](#references)</sup>

## References

- [1] [Avis de sécurité SUSE CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Mise à jour de sécurité SUSE pour pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Avis de sécurité SUSE CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
