# Vulnerabilidades do Kernel do macOS

{{#include ../../../banners/hacktricks-training.md}}

A exploração recente do kernel do macOS envolve menos "carregar uma kext unsigned trivial e obter ring-0" e mais abusar de **parsers Mach/MIG**, **user clients do IOKit**, **races data-only dentro do XNU** e **daemons com entitlements específicos** que ainda podem reabrir a attack surface do kernel. Para fazer o reversing das interfaces concretas, consulte também as páginas sobre [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces que ainda importam

- **Handlers Mach/MIG** em system daemons e serviços voltados ao kernel: descritores malformados, dados out-of-line (OOL) e fluxos stateful com múltiplas mensagens.
- **User clients do IOKit**: parsing específico por selector, métodos protegidos por entitlements e bibliotecas/wrappers e daemons que ocultam o call graph real.
- **Primitives data-only do XNU**: races em torno de credenciais, ponteiros protegidos por SMR, zonas somente leitura e outros locais onde a corrupção altera a policy sem primeiro obter controle de RIP/PC.
- **Código de kernel de terceiros / auxiliar**: kexts legadas são mais raras, mas frotas enterprise, sistemas Apple Silicon com segurança reduzida e bundles `.fs` / helper de vendors ainda criam caminhos de alto valor adjacentes ao kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Em [**este report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) vários bugs da OTA/update-chain são combinados para alcançar o comprometimento do kernel abusando do pipeline de software update e de capacidades relacionadas ao rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

As [**releases de segurança de março de 2024 do macOS**](https://support.apple.com/en-us/120895) da Apple corrigiram dois problemas que foram **actively exploited**:

- **CVE-2024-23225 – Kernel**: um bug de memory corruption onde um attacker com arbitrary kernel read/write podia bypassar as proteções de memória do kernel.
- **CVE-2024-23296 – RTKit**: um segundo bug de memory corruption com a mesma public impact statement.

Os detalhes públicos da root cause ainda são escassos, mas o par é um bom lembrete de que as exploit chains modernas da Apple frequentemente precisam de **mais do que "apenas" kernel R/W**: o trabalho de post-exploitation contra proteções de memória, código adjacente a coprocessadores ou trust boundaries secundários é frequentemente onde a chain real é estabilizada.

Triagem rápida de patches:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

O [**write-up do TRAVERTINE**](https://jprx.io/cve-2025-24118/) de Joseph Ravichandran é um excelente estudo de caso moderno do XNU, pois não se trata de um **buffer overflow** clássico:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` é um **ponteiro protegido por SMR** armazenado em um objeto `proc_ro` **somente leitura**.
- Os escritores devem atualizar esse ponteiro **atomicamente**.
- `kauth_cred_proc_update()` usava `zalloc_ro_mut(...)` para modificar `p_ucred`; no x86_64, esse caminho acaba chegando a `memcpy` / `rep movsb`, permitindo que um leitor concorrente observe um **ponteiro parcialmente atualizado**.
- O bug se transforma em uma **data-only privilege escalation**: se o ponteiro de credencial corrompido resolver para um objeto de credencial válido diferente, a thread atual poderá herdar um estado mais privilegiado sem antes obter um **control-flow hijack** evidente.

Padrão mínimo de acionamento:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Heurística útil de auditoria: sempre que um caminho do kernel combinar **leitores SMR**, **mutação de zonas somente leitura** e **metadados de credenciais ou tarefas**, verifique se as atualizações usam as variantes atômicas `zalloc_ro_mut_*` em vez de helpers baseados em cópia.

---

## 2024-2025: bypass do SIP que reabre caminhos de carregamento do kernel (CVE-2024-44243)

A Microsoft mostrou que o `storagekitd` poderia ser abusado para **bypass do SIP** e, em seguida, tornar código de kernel de terceiros relevante novamente em máquinas que, de outra forma, pareceriam estar "post-kext". A ideia principal é:<sup>[[2]](#references)</sup>

1. Soltar ou sobrescrever um bundle `.fs` malicioso em `/Library/Filesystems`.
2. Acionar o `storagekitd` pelo Disk Utility ou pelo `diskutil`.
3. Permitir que o daemon com privilégios especiais execute os executáveis do bundle **sem remover corretamente os privilégios / validar o caminho**.
4. Usar o bypass do SIP resultante para alterar o estado protegido do sistema de arquivos e, na demonstração da Microsoft, sobrescrever a lista de exclusão de extensões do kernel.

Para pesquisadores de kernel, a lição importante é que a **superfície de ataque do kernel pode ser reintroduzida a partir de daemons de gerenciamento em userland**, mesmo quando o carregamento direto de kexts de terceiros é fortemente restrito.

Triagem útil:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing e fluxo de trabalho de pesquisa

Se você está ativamente procurando essa classe de bugs, o trabalho público recente está apontando na mesma direção:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) ainda é uma das melhores referências para pesquisa de kernel na era do Apple Silicon. Ele usa **reescrita binária estática** para recuperar a cobertura, desativa caminhos protegidos por **entitlement** durante os testes e infere a estrutura das interfaces a partir de wrappers de userspace.<sup>[[4]](#references)</sup>
- O [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) do Project Zero mostra um fluxo de trabalho muito prático para **rebasear um kext / fileset em userspace**, permitindo que código com uso intenso de parsers seja fuzzed em uma velocidade muito maior antes de reproduzi-lo no dispositivo.<sup>[[5]](#references)</sup>
- Para alvos com uso intenso de Mach, crie harnesses em torno de **layouts de mensagens reais e máquinas de estado com múltiplas chamadas**, em vez de usar apenas blobs de selector individuais. Pesquisas recentes sobre CoreAudio/Mach do Project Zero e palestras de conferências, como **Fuzzing at Mach Speed**, mostram por que sequências de mensagens com estado continuam sendo eficazes.

Comandos locais rápidos que você realmente usará bastante:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Guia rápido de enumeração
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Referências

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Análise do CVE-2024-44243, um bypass do System Integrity Protection do macOS por meio de extensões do kernel](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - O pesadelo da atualização OTA da Apple: contornando a verificação de assinatura e obtendo controle do kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: fuzzing de extensões do kernel do macOS em Apple Silicon por meio da exploração de mitigações (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Fuzzing simples de extensões do kernel do macOS em userspace com IDA e TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
