# Matériel sur le noyau, LPE et CVE

{{#include ../../../banners/hacktricks-training.md}}

Ces études de cas couvrent différentes primitives d’escalade de privilèges locale. Vérifiez le produit ou le noyau concerné, la configuration et les prérequis indiqués dans chaque article avant d’appliquer une technique. Pour une énumération plus large de l’hôte, utilisez la [liste de contrôle d’escalade de privilèges Linux](../linux-privilege-escalation-checklist.md).

Pour Dirty Pipe (CVE-2022-0847), la [recherche originale](https://dirtypipe.cm4all.com/) indique que les correctifs upstream pour les versions stables sont disponibles à partir des versions 5.10.102, 5.15.25 et 5.16.11. Une version du noyau située dans une ancienne plage vulnérable est seulement un indice à examiner : les distributions peuvent rétroporter des correctifs sous des noms de versions différents, et le fichier cible concerné doit être lisible pour que la primitive d’écriture dans le page cache fonctionne. Écraser un exécutable SUID lisible est une voie possible vers l’élévation de privilèges si sa transition set-ID reste effective ; modifier `/etc/passwd`, puis s’authentifier, peut également dépendre de la pile PAM locale. Avant d’évaluer la faisabilité, vérifiez le paquet du noyau fourni par le vendeur, le noyau actif après redémarrage, les permissions de la cible, le montage `nosuid` et `no_new_privs`. N’effectuez pas de test d’écriture pendant l’énumération passive. Consultez [l’état spécifique à chaque version d’Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Découverte du service VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md) : exécution privilégiée via la recherche de chemin d’un processus non fiable.
- [Écrasement du page cache par AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md) : une voie d’écrasement du page cache du noyau.
- [Course TOCTOU des temporisateurs CPU POSIX et exploitation, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit) : expiration/suppression du temporisateur à la sortie d’une tâche, avec les prérequis liés au chemin IRQ et la recherche sur l’exploitation.
- [Course à la sortie de Linux ptrace et vol de descripteur de fichier via `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) : accès à un descripteur lors d’une course à la sortie d’un processus.

## Études de cas connexes sur l’exploitation binaire

La section Binary Exploitation approfondit les primitives d’exploitation, la disposition mémoire et le contournement des mesures d’atténuation pour ces cibles du noyau Linux :

- [Use-after-free de SKB hors bande AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md) : un bug de socket transformé en primitives de lecture et d’écriture du noyau.
- [Sous-dépassement de scatterlist avec écrivains concurrents AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md) : une course entre écrivains skcipher transformée en écriture dans le noyau.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md) : une primitive d’écriture de pointeur étendue aux tampons de pipe et aux workqueues.
- [Écriture hors limites dans les flux ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md) : exploitation du heap du noyau et contournement des mesures d’atténuation.
- [Contournement de KASLR de la linear map statique sur Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md) : découverte d’adresses pour l’exploitation du noyau arm64.
- [Contournement des privilèges GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md) : une voie GPU Android permettant d’accéder à la mémoire du noyau.
- [Use-after-free lié au délai d’expiration d’une tâche Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md) : un bug d’accélérateur Android exploité pour écrire dans le noyau.
{{#include ../../../banners/hacktricks-training.md}}
