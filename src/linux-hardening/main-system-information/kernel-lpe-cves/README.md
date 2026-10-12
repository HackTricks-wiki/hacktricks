# Kernel, LPE et CVE

{{#include ../../../banners/hacktricks-training.md}}

Ces études de cas couvrent différentes primitives d’escalade locale de privilèges. Vérifiez le produit ou le kernel concerné, la configuration et les prérequis indiqués dans chaque article avant d’appliquer une technique. Pour une énumération plus large de l’hôte, utilisez la [liste de contrôle d’escalade de privilèges Linux](../linux-privilege-escalation-checklist.md).

Pour Dirty Pipe (CVE-2022-0847), la [recherche originale](https://dirtypipe.cm4all.com/) indique que les correctifs upstream stable ont été publiés dans les versions 5.10.102, 5.15.25 et 5.16.11. Une version du kernel appartenant à une ancienne plage vulnérable constitue uniquement une piste à vérifier : les kernels des distributions peuvent intégrer des correctifs rétroportés sous des noms de version différents, et le fichier cible concerné doit être lisible pour que la primitive d’écriture dans le page cache soit exploitable. Écraser un exécutable SUID lisible est une voie possible vers l’élévation de privilèges si la transition set-ID reste effective ; modifier `/etc/passwd`, puis s’authentifier, peut également dépendre de la pile PAM locale. Vérifiez le paquet du kernel fourni par l’éditeur, le kernel en cours d’exécution après le redémarrage, les permissions de la cible, l’option de montage `nosuid` et `no_new_privs` avant d’évaluer si la vulnérabilité est exploitable. N’effectuez pas de test d’écriture pendant une énumération passive. Consultez le [statut spécifique à chaque version d’Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Découverte du service VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md) : exécution avec privilèges via la recherche d’un chemin de processus non fiable.
- [Écrasement du page cache par AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md) : une voie d’écrasement du page cache du kernel.
- [TOCTOU des timers CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md) : une race condition dans la gestion des timers.
- [Race condition de sortie ptrace Linux et vol de descripteur de fichier avec `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) : accès à un descripteur pendant une race condition de sortie de processus.

## Études de cas connexes sur le Binary Exploitation

La section Binary Exploitation approfondit les primitives d’exploit, la disposition mémoire et le contournement des mitigations pour ces cibles du kernel Linux :

- [Use-after-free de SKB hors bande AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md) : un bug de socket transformé en primitives de lecture et d’écriture dans le kernel.
- [Underflow de scatterlist dû à des écrivains concurrents AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md) : une race condition de l’écrivain skcipher transformée en écriture dans le kernel.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md) : une primitive d’écriture de pointeur étendue via les pipe buffers et les workqueues.
- [Écriture hors limites dans les streams ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md) : exploitation du kernel heap et contournements des mitigations.
- [TOCTOU des timers CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md) : l’analyse de la race condition sous l’angle du Binary Exploitation, également résumée ci-dessus.
- [Contournement de KASLR de la linear map statique arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md) : découverte d’adresses pour l’exploitation du kernel arm64.
- [Contournement des privilèges GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md) : une voie GPU Android permettant d’accéder à la mémoire du kernel.
- [Use-after-free lié au timeout de job Bigwave sur Pixel](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md) : un bug d’accélérateur Android exploité pour écrire dans le kernel.
{{#include ../../../banners/hacktricks-training.md}}
