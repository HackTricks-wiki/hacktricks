# Matériel sur le noyau, les LPE et les CVE

{{#include ../../../banners/hacktricks-training.md}}

Ces études de cas présentent différentes primitives d’escalade locale de privilèges. Avant d’appliquer une technique, vérifiez le produit ou le noyau concerné, la configuration et les prérequis indiqués dans chaque article. Pour une énumération plus générale de l’hôte, consultez la [liste de vérification d’escalade de privilèges Linux](../linux-privilege-escalation-checklist.md).

Pour Dirty Pipe (CVE-2022-0847), les [recherches d’origine](https://dirtypipe.cm4all.com/) identifient les correctifs upstream stable dans les versions 5.10.102, 5.15.25 et 5.16.11. Une version du noyau appartenant à une ancienne plage affectée constitue seulement une piste à examiner : les distributions peuvent rétroporter des correctifs sous des noms de version différents, et le fichier cible pertinent doit être lisible pour que la primitive d’écriture dans le page cache fonctionne. Écraser un exécutable SUID lisible est une voie possible vers l’obtention de privilèges si sa transition set-ID reste effective ; modifier `/etc/passwd`, puis s’authentifier, peut également dépendre de la pile PAM locale. Avant d’évaluer si l’exploitation est possible, vérifiez le paquet du noyau fourni par l’éditeur installé, le noyau actif après redémarrage, les permissions de la cible, l’option de montage `nosuid` et `no_new_privs`. Ne lancez pas de test d’écriture pendant une énumération passive. Consultez le [statut par version d’Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Découverte du service VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md) : exécution avec privilèges via la découverte de chemins de processus non fiables.
- [Écrasement du page cache via AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md) : une voie d’écrasement du page cache du noyau.
- [TOCTOU des minuteries CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md) : une race condition dans la gestion des minuteries.
- [Race condition à la sortie de `ptrace` sous Linux et vol de descripteur de fichier via `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) : accès aux descripteurs lors d’une race condition à la sortie d’un processus.

## Études de cas connexes sur l’exploitation binaire

La section Binary Exploitation approfondit les primitives d’exploitation, la disposition mémoire et les contournements des mesures d’atténuation pour ces cibles du noyau Linux :

- [Use-after-free de SKB hors bande AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md) : un bogue de socket transformé en primitives de lecture et d’écriture dans le noyau.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md) : une primitive d’écriture de pointeur étendue via les tampons de pipe et les workqueues.
- [Écriture hors limites dans les flux ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md) : exploitation du heap du noyau et contournements des mesures d’atténuation.
- [TOCTOU des minuteries CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md) : le traitement de la race condition du point de vue de l’exploitation binaire, également résumé ci-dessus.
- [Contournement de KASLR avec la linear map statique sur Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md) : découverte d’adresses pour l’exploitation du noyau arm64.
- [Contournement des privilèges GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md) : une voie d’accès à la mémoire du noyau via un GPU Android.
- [Use-after-free du délai d’expiration des tâches Bigwave sur Pixel](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md) : un bogue d’accélérateur Android exploité pour écrire dans le noyau.
{{#include ../../../banners/hacktricks-training.md}}
