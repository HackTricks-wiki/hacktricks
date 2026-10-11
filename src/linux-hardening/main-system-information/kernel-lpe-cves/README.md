# Matériel sur le kernel, les LPE et les CVE

{{#include ../../../banners/hacktricks-training.md}}

Ces études de cas couvrent différentes primitives d’escalade de privilèges locale. Consultez chaque article pour vérifier le produit ou le kernel concerné, la configuration et les prérequis avant d’appliquer une technique. Pour une énumération plus large de l’hôte, consultez la [checklist d’escalade de privilèges Linux](../linux-privilege-escalation-checklist.md).

Pour Dirty Pipe (CVE-2022-0847), la [recherche originale](https://dirtypipe.cm4all.com/) indique que les correctifs upstream stable sont disponibles dans les versions 5.10.102, 5.15.25 et 5.16.11. Une version du kernel appartenant à une ancienne plage affectée est uniquement une piste à examiner : les kernels des distributions peuvent inclure des correctifs rétroportés sous des noms de version différents, et le fichier cible doit être lisible pour que la primitive d’écriture dans le page cache fonctionne. Écraser un exécutable SUID lisible est une voie possible vers l’obtention de privilèges si sa transition set-ID reste effective ; modifier `/etc/passwd`, puis s’authentifier peut également dépendre de la pile PAM locale. Avant d’évaluer si la faille est exploitable, vérifiez le paquet du kernel fourni par le vendeur installé, le kernel en cours d’exécution après le redémarrage, les permissions de la cible, l’option de montage `nosuid` et `no_new_privs`. Ne lancez pas de test d’écriture pendant une énumération passive. Consultez [l’état propre à chaque version d’Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md) : exécution avec privilèges via la recherche de chemin de processus non fiable.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md) : une voie d’écrasement du page cache du kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md) : une race condition dans la gestion des timers.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) : accès aux descripteurs pendant une race condition sur la fin d’un processus.

## Études de cas connexes sur l’exploitation binaire

La section Binary Exploitation approfondit les primitives d’exploit, la disposition de la mémoire et les contournements des mitigations pour ces cibles du kernel Linux :

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md) : un bug de socket transformé en primitives de lecture et d’écriture dans le kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md) : une primitive d’écriture de pointeur étendue via les buffers de pipe et les workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md) : exploitation du heap du kernel et contournements des mitigations.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md) : le traitement de la race condition sur les timers du point de vue de l’exploitation binaire, également résumé ci-dessus.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md) : découverte d’adresses pour l’exploitation du kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md) : une voie d’accès à la mémoire du kernel via un GPU Android.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md) : un bug d’accélérateur Android exploité pour écrire dans le kernel.
{{#include ../../../banners/hacktricks-training.md}}
