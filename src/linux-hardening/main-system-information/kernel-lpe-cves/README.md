# Matériel sur le kernel, les LPE et les CVE

{{#include ../../../banners/hacktricks-training.md}}

Ces études de cas portent sur différentes primitives d’escalade locale de privilèges. Avant d’appliquer une technique, vérifiez le produit ou le kernel concerné, la configuration et les prérequis indiqués dans chaque article. Pour une énumération plus générale de l’hôte, consultez la [liste de vérification pour l’escalade de privilèges sous Linux](../linux-privilege-escalation-checklist.md).

Pour Dirty Pipe (CVE-2022-0847), la [recherche originale](https://dirtypipe.cm4all.com/) indique que les correctifs upstream stable ont été publiés dans les versions 5.10.102, 5.15.25 et 5.16.11. Une version du kernel appartenant à une ancienne plage affectée constitue uniquement une piste à examiner : les kernels des distributions peuvent intégrer des correctifs rétroportés sous d’autres noms de version, et le fichier cible concerné doit être lisible pour que la primitive d’écriture dans le page cache fonctionne. Écraser un exécutable SUID lisible est une voie possible vers l’élévation de privilèges lorsque sa transition set-ID reste effective ; modifier `/etc/passwd` puis s’authentifier peut également dépendre de la pile PAM locale. Avant d’évaluer la possibilité d’exploitation, vérifiez le paquet du kernel fourni par le vendeur installé, le kernel en cours d’exécution après le redémarrage, les permissions de la cible, l’option de montage `nosuid` et `no_new_privs`. N’effectuez pas de test d’écriture pendant une énumération passive. Consultez l’[état propre à chaque version d’Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Découverte du service VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md) : exécution avec privilèges via la découverte de chemins de processus non fiables.
- [Écrasement du page cache via AF_ALG et splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md) : une voie d’écrasement du page cache du kernel.
- [TOCTOU des timers CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md) : une race condition dans la gestion des timers.
- [Race condition à la sortie d’un processus avec ptrace sous Linux et vol de descripteur de fichier via `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) : accès à un descripteur lors d’une race condition à la sortie d’un processus.

## Études de cas connexes sur l’exploitation binaire

La section Binary Exploitation approfondit les primitives d’exploitation, la disposition mémoire et le contournement des mitigations pour ces cibles du kernel Linux :

- [Use-after-free de SKB hors bande AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md) : un bug de socket transformé en primitives de lecture et d’écriture dans le kernel.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md) : une primitive d’écriture de pointeur étendue via les buffers de pipe et les workqueues.
- [Écriture hors limites dans les flux ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md) : exploitation du heap du kernel et contournement des mitigations.
- [TOCTOU des timers CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md) : le traitement de la race condition des timers sous l’angle de l’exploitation binaire, également résumé ci-dessus.
- [Contournement de KASLR de la linear map statique sur Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md) : découverte d’adresses pour l’exploitation du kernel arm64.
- [Contournement des privilèges GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md) : une voie d’accès à la mémoire du kernel via un GPU Android.
- [Use-after-free du timeout de job Bigwave sur Pixel](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md) : un bug d’accélérateur Android exploité pour écrire dans le kernel.

{{#include ../../../banners/hacktricks-training.md}}
