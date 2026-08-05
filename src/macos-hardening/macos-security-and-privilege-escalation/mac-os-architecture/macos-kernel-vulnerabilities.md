# Vulnerabilidades do Kernel do macOS

{{#include ../../../banners/hacktricks-training.md}}

A exploração recente do kernel do macOS envolve menos "carregar um kext trivial não assinado e obter ring-0" e mais abusar de **parsers Mach/MIG**, **IOKit user clients**, **races somente de dados dentro do XNU** e **daemons com entitlements específicos** que ainda podem reabrir a superfície de ataque do kernel. Para fazer reverse engineering das interfaces concretas, consulte também as páginas sobre [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Superfícies de ataque que ainda importam

- **Handlers Mach/MIG** em daemons do sistema e serviços voltados ao kernel: descritores malformados, dados out-of-line (OOL) e fluxos com estado compostos por várias mensagens.
- **IOKit user clients**: parsing específico por selector, métodos protegidos por entitlements e bibliotecas wrapper/daemons que ocultam o call graph real.
- **Primitivas somente de dados do XNU**: races envolvendo credenciais, ponteiros protegidos por SMR, zones somente leitura e outros locais onde a corrupção altera a política sem primeiro obter controle de RIP/PC.
- **Código de kernel de terceiros / auxiliar**: kexts legados são mais raros, mas frotas corporativas, sistemas Apple Silicon com segurança reduzida e bundles `.fs` / helper de fornecedores ainda criam caminhos de alto valor adjacentes ao kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), vários bugs da cadeia de OTA/update são combinados para alcançar o comprometimento do kernel abusando do pipeline de atualização de software e de capacidades relacionadas ao rootless.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: cadeia de bypass das proteções do kernel in-the-wild (CVE-2024-23225 & CVE-2024-23296)

As [**versões de segurança do macOS de março de 2024**](https://support.apple.com/en-us/120895) da Apple corrigiram dois problemas que foram **explorados ativamente**:

- **CVE-2024-23225 – Kernel**: um bug de corrupção de memória no qual um atacante com leitura/escrita arbitrária no kernel poderia contornar as proteções de memória do kernel.
- **CVE-2024-23296 – RTKit**: um segundo bug de corrupção de memória com a mesma declaração pública de impacto.

Os detalhes públicos da causa-raiz ainda são escassos, mas o par é um bom lembrete de que as modernas exploit chains da Apple frequentemente precisam de **mais do que "apenas" R/W no kernel**: o trabalho de post-exploitation contra proteções de memória, código adjacente a coprocessadores ou limites secundários de confiança é frequentemente o ponto em que a cadeia real é estabilizada.

Triagem rápida de patches:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

O [**write-up do TRAVERTINE**](https://jprx.io/cve-2025-24118/) de Joseph Ravichandran é um excelente estudo de caso moderno do XNU porque não se trata de um **classic buffer overflow**:<sup>[1]</sup>

- `proc_ro.p_ucred` é um **SMR-protected pointer** armazenado em um objeto `proc_ro` **read-only**.
- Os writers precisam atualizar esse pointer **atomically**.
- `kauth_cred_proc_update()` usava `zalloc_ro_mut(...)` para modificar `p_ucred`; no x86_64, esse caminho eventualmente chega a `memcpy` / `rep movsb`, portanto um reader concorrente pode observar um **torn pointer**.
- O bug se transforma em uma **data-only privilege escalation**: se o credential pointer corrompido apontar para um credential object válido diferente, a thread atual poderá herdar um estado mais privilegiado sem antes obter um evidente control-flow hijack.

Padrão mínimo de trigger:
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
Heurística útil de auditoria: sempre que um caminho do kernel combinar **SMR readers**, **mutação de zona somente leitura** e **metadados de credenciais ou tarefas**, verifique se as atualizações usam as variantes atômicas `zalloc_ro_mut_*` em vez de helpers baseados em cópia.

---

## 2024-2025: bypass de SIP que reabre caminhos de carregamento do kernel (CVE-2024-44243)

A Microsoft demonstrou que o `storagekitd` poderia ser abusado para **bypass de SIP** e, em seguida, tornar o código de kernel de terceiros relevante novamente em máquinas que, de outra forma, pareceriam "post-kext". A ideia principal é:<sup>[2]</sup>

1. Soltar ou sobrescrever um bundle `.fs` malicioso em `/Library/Filesystems`.
2. Acionar o `storagekitd` por meio do Disk Utility ou do `diskutil`.
3. Fazer com que o daemon com privilégios especiais gere executáveis do bundle **sem remover corretamente os privilégios / validar o caminho**.
4. Usar o bypass de SIP resultante para alterar o estado protegido do sistema de arquivos e, na demonstração da Microsoft, substituir a lista de exclusão de extensões do kernel.

Para pesquisadores de kernel, a lição importante é que a **superfície de ataque do kernel pode ser reintroduzida a partir de daemons de gerenciamento em userland**, mesmo quando o carregamento direto de kexts de terceiros é fortemente restrito.

Triage útil:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow de fuzzing e pesquisa

Se você estiver procurando ativamente por essa classe de bugs, o trabalho público recente está apontando na mesma direção:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) ainda é uma das melhores referências para pesquisas de kernel na era do Apple Silicon. Ele usa **static binary rewriting** para recuperar a cobertura, desabilita caminhos **entitlement-gated** durante os testes e infere a estrutura das interfaces a partir de wrappers no userspace.<sup>[4]</sup>
- O [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) do Project Zero mostra um workflow muito prático para **rebasing de um kext / fileset no userspace**, permitindo que códigos com muitos parsers sejam fuzzed em uma velocidade muito maior antes da reprodução no dispositivo.<sup>[5]</sup>
- Para alvos com muito Mach, crie harnesses em torno de **layouts de mensagens reais e state machines com múltiplas chamadas**, não apenas blobs de seletores individuais. Pesquisas recentes sobre CoreAudio/Mach do Project Zero e palestras de conferências, como **Fuzzing at Mach Speed**, mostram por que sequências de mensagens stateful continuam sendo eficazes.

Comandos locais rápidos que você realmente usará com frequência:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Guia rápido de enumeraçãoિકેટ
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
- [2] [Microsoft Security Blog - Análise do CVE-2024-44243, um bypass do System Integrity Protection do macOS por meio de kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - O pesadelo da atualização OTA da Apple: contornando a verificação de assinatura e obtendo controle do kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing de kernel extensions do macOS em Apple Silicon por meio da exploração de mitigações (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Fuzzing simples de kernel extensions do macOS em userspace com IDA e TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
