# Material sobre Kernel, LPE e CVEs

{{#include ../../../banners/hacktricks-training.md}}

Estes estudos de caso abordam primitivas distintas de escalonamento local de privilégios. Antes de aplicar uma técnica, verifique o produto ou kernel afetado, a configuração e os pré-requisitos em cada artigo. Para uma enumeração mais ampla do host, consulte a [lista de verificação de escalonamento de privilégios no Linux](../linux-privilege-escalation-checklist.md).

Para Dirty Pipe (CVE-2022-0847), a [pesquisa original](https://dirtypipe.cm4all.com/) identifica as correções upstream estáveis nas versões 5.10.102, 5.15.25 e 5.16.11. Uma versão do kernel em uma faixa afetada mais antiga é apenas um indício para investigação: kernels de distribuições podem receber correções retroportadas com nomes de versão diferentes, e o arquivo de destino relevante precisa ser legível para que a primitiva de escrita no page-cache funcione. Sobrescrever um executável SUID legível é uma possível via para obter privilégios quando a transição set-ID continua efetiva; modificar `/etc/passwd` e depois autenticar-se também pode depender da pilha PAM local. Antes de avaliar a possibilidade de exploração, verifique o pacote de kernel do fornecedor instalado, o kernel em execução após a reinicialização, as permissões do destino, a opção de montagem `nosuid` e `no_new_privs`. Não execute uma sonda de escrita durante a enumeração passiva. Consulte o [status específico por versão do Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Descoberta de serviços do VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): execução privilegiada por meio da descoberta de caminhos de processos não confiáveis.
- [Sobrescrita do page-cache por splice com AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): uma via de sobrescrita do page-cache do kernel.
- [Race TOCTOU em timers de CPU POSIX e exploração, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): expiração/exclusão de timers durante a saída de uma task, incluindo pré-requisitos do caminho IRQ e pesquisa sobre exploração.
- [Race na saída de `ptrace` do Linux e roubo de descritores de arquivo com `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): acesso a descritores durante uma race de saída de processo.

## Estudos de caso relacionados de exploração binária

A seção Binary Exploitation aprofunda as primitivas de exploração, o layout de memória e os bypasses de mitigação para estes alvos do kernel Linux:

- [Use-after-free de SKB out-of-band em AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): um bug de socket convertido em primitivas de leitura e escrita no kernel.
- [Underflow de scatterlist por writer concorrente em AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): uma race de writer skcipher convertida em uma escrita no kernel.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): uma primitiva de escrita por ponteiro ampliada por meio de buffers de pipe e workqueues.
- [Escrita out-of-bounds em streams do ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploração do heap do kernel e bypasses de mitigação.
- [Bypass de KASLR no mapeamento linear estático do Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): descoberta de endereços para exploração do kernel arm64.
- [Bypass de privilégios da GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): uma via da GPU Android para acessar a memória do kernel.
- [Use-after-free por timeout de job do Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): um bug de acelerador Android usado para escrever no kernel.
{{#include ../../../banners/hacktricks-training.md}}
