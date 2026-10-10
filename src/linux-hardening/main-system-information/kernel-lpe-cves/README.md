# Material sobre Kernel, LPE e CVE

{{#include ../../../banners/hacktricks-training.md}}

Estes estudos de caso abordam diferentes primitivas de local privilege escalation. Antes de aplicar uma técnica, verifique o produto ou kernel afetado, a configuração e os pré-requisitos em cada artigo. Para uma enumeração mais ampla do host, use o [checklist de privilege escalation no Linux](../linux-privilege-escalation-checklist.md).

Para Dirty Pipe (CVE-2022-0847), a [pesquisa original](https://dirtypipe.cm4all.com/) identifica correções upstream estáveis nas versões 5.10.102, 5.15.25 e 5.16.11. Uma versão do kernel em um intervalo afetado mais antigo é apenas uma pista para revisão: kernels de distribuições podem incluir correções retroportadas com nomes de release diferentes, e o arquivo de destino relevante precisa ser legível para que a primitiva de escrita no page cache funcione. Sobrescrever um executável SUID legível é um possível caminho para obter privilégios quando a transição set-ID continua efetiva; modificar `/etc/passwd` e depois autenticar-se também pode depender da pilha PAM local. Antes de avaliar a possibilidade de exploração, verifique o pacote do kernel da distribuição instalado, o kernel em execução após a reinicialização, as permissões do destino, a opção `nosuid` do mount e `no_new_privs`. Não execute uma prova de escrita durante a enumeração passiva. Consulte o [status específico da release do Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Descoberta de serviço do VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): execução privilegiada por meio da descoberta de caminhos de processos não confiáveis.
- [Sobrescrita do page cache via splice em AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): um caminho de sobrescrita do page cache do kernel.
- [TOCTOU em timers de CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): uma condição de corrida no tratamento de timers.
- [Corrida de saída do Linux ptrace e roubo de descritor de arquivo com `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): acesso a descritores durante uma condição de corrida na saída de um processo.

## Estudos de caso relacionados a Binary Exploitation

A seção Binary Exploitation aprofunda as primitivas de exploit, o layout de memória e os bypasses de mitigação para estes alvos do kernel Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): um bug de socket desenvolvido em primitivas de leitura e escrita no kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): uma primitiva de escrita de ponteiro estendida por meio de buffers de pipe e workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploração do heap do kernel e bypasses de mitigação.
- [TOCTOU em timers de CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): a abordagem de Binary Exploitation para a condição de corrida nos timers, também resumida acima.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): descoberta de endereços para exploração do kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): um caminho pela GPU Android para acessar a memória do kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): um bug de acelerador Android usado para escrever no kernel.
{{#include ../../../banners/hacktricks-training.md}}
