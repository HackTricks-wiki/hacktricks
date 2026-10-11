# Material sobre kernel, LPE e CVEs

{{#include ../../../banners/hacktricks-training.md}}

Estes estudos de caso abordam primitivas distintas de escalonamento local de privilégios. Antes de aplicar uma técnica, verifique o produto ou kernel afetado, a configuração e os pré-requisitos descritos em cada artigo. Para uma enumeração mais ampla do host, use a [lista de verificação de escalonamento de privilégios no Linux](../linux-privilege-escalation-checklist.md).

Para Dirty Pipe (CVE-2022-0847), a [pesquisa original](https://dirtypipe.cm4all.com/) identifica correções upstream nas versões estáveis 5.10.102, 5.15.25 e 5.16.11. Uma versão do kernel em um intervalo afetado mais antigo é apenas um ponto de partida para análise: kernels de distribuições podem incluir correções retroportadas com nomes de versão diferentes, e o arquivo de destino relevante precisa ser legível para que a primitiva de escrita no page cache funcione. Sobrescrever um executável SUID legível é uma possível via de escalonamento de privilégios quando a transição de set-ID continua efetiva; modificar `/etc/passwd` e depois autenticar também pode depender da pilha PAM local. Antes de avaliar a possibilidade de exploração, verifique o pacote de kernel do fornecedor instalado, o kernel em execução após a reinicialização, as permissões do destino, a opção de montagem `nosuid` e `no_new_privs`. Não execute um teste de escrita durante a enumeração passiva. Consulte o [status específico de cada versão do Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Descoberta de serviços do VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): execução privilegiada por meio da descoberta de caminhos de processo não confiáveis.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): um caminho de sobrescrita do page cache do kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): uma race condition no tratamento de timers.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): acesso a descritores durante uma race condition de encerramento de processo.

## Estudos de caso relacionados sobre exploração de binários

A seção Binary Exploitation aprofunda as primitivas de exploração, o layout de memória e os bypasses de mitigação para estes alvos do kernel Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): um bug de socket desenvolvido em primitivas de leitura e escrita no kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): uma primitiva de escrita de ponteiro ampliada por meio de buffers de pipe e workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploração do heap do kernel e bypasses de mitigação.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): a análise de exploração de binários da race condition dos timers, também resumida acima.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): descoberta de endereços para exploração do kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): um caminho pela GPU Android para acessar a memória do kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): um bug de acelerador Android usado para escrever no kernel.
{{#include ../../../banners/hacktricks-training.md}}
