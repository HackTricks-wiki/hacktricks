# Vulnerabilidades do Kernel do macOS

{{#include ../../../banners/hacktricks-training.md}}

A exploração recente do kernel do macOS tem menos relação com "carregar uma kext trivial não assinada e obter ring-0" e mais com abusar de **parsers Mach/MIG**, **IOKit user clients**, **races data-only dentro do XNU** e **daemons com entitlements específicos** que ainda podem reabrir a attack surface do kernel. Para fazer o reverse engineering das interfaces concretas, consulte também as páginas sobre [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces que ainda importam

- **Handlers Mach/MIG** em system daemons e serviços voltados ao kernel: descritores malformados, dados out-of-line (OOL) e fluxos stateful com múltiplas mensagens.
- **IOKit user clients**: parsing específico de cada selector, métodos protegidos por entitlements e wrapper libraries/daemons que ocultam o call graph real.
- **Primitivas data-only do XNU**: races em torno de credenciais, ponteiros protegidos por SMR, zonas read-only e outros locais onde a corrupção altera a policy sem antes obter controle de RIP/PC.
- **Código de kernel de terceiros / auxiliar**: kexts legadas são mais raras, mas fleets corporativas, sistemas Apple Silicon com segurança reduzida e bundles `.fs` / helper de vendors ainda criam caminhos de alto valor adjacentes ao kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Em [**este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) vários bugs da cadeia de OTA/update são combinados para alcançar o comprometimento do kernel abusando do pipeline de software update e de capacidades relacionadas ao rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: cadeia de bypass das proteções do kernel in-the-wild (CVE-2024-23225 & CVE-2024-23296)

As [**versões de segurança do macOS de março de 2024**](https://support.apple.com/en-us/120895) da Apple corrigiram dois problemas que foram **ativamente explorados**:

- **CVE-2024-23225 – Kernel**: um bug de memory corruption em que um atacante com arbitrary kernel read/write poderia fazer bypass das proteções de memória do kernel.
- **CVE-2024-23296 – RTKit**: um segundo bug de memory corruption com a mesma declaração pública de impacto.

Os detalhes públicos da causa-raiz ainda são escassos, mas o par é um bom lembrete de que as exploit chains modernas da Apple frequentemente precisam de **mais do que "apenas" kernel R/W**: o trabalho de post-exploitation contra proteções de memória, código adjacente a coprocessors ou trust boundaries secundários costuma ser onde a chain real é estabilizada.

Triagem rápida de patches:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + condição de corrida de credenciais somente leitura (CVE-2025-24118)

O [**texto do TRAVERTINE** de Joseph Ravichandran](https://jprx.io/cve-2025-24118/) é um excelente estudo de caso moderno do XNU porque **não** se trata de um buffer overflow clássico:

- `proc_ro.p_ucred` é um **ponteiro protegido por SMR** armazenado em um objeto `proc_ro` **somente leitura**.
- Os escritores precisam atualizar esse ponteiro **atomicamente**.
- `kauth_cred_proc_update()` usava `zalloc_ro_mut(...)` para modificar `p_ucred`; no x86_64, esse caminho acaba chegando a `memcpy` / `rep movsb`, portanto um leitor concorrente pode observar um **ponteiro parcialmente atualizado**.
- O bug se transforma em uma **escalada de privilégios somente de dados**: se o ponteiro de credencial corrompido resolver para um objeto de credencial válido diferente, a thread atual poderá herdar um estado mais privilegiado sem primeiro obter um hijack óbvio do fluxo de controle.

Padrão mínimo de disparo:
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
Heurística útil de auditoria: sempre que um caminho do kernel combinar **SMR readers**, **mutação de read-only zone** e **metadados de credenciais ou de task**, verifique se as atualizações usam as variantes atômicas `zalloc_ro_mut_*` em vez de helpers baseados em cópia.

---

## 2024-2025: SIP bypass que reabre caminhos de carregamento do kernel (CVE-2024-44243)

A Microsoft mostrou que o `storagekitd` poderia ser abusado para **bypass de SIP** e, em seguida, tornar o código de kernel de terceiros relevante novamente em máquinas que, de outra forma, pareceriam "post-kext". A ideia principal é:

1. Soltar ou sobrescrever um bundle `.fs` malicioso em `/Library/Filesystems`.
2. Acionar o `storagekitd` por meio do Disk Utility ou do `diskutil`.
3. Permitir que o daemon com privilégios especiais inicie executáveis do bundle **sem remover corretamente os privilégios / validar o path**.
4. Usar o bypass de SIP resultante para alterar o estado protegido do sistema de arquivos e, na demonstração da Microsoft, substituir a lista de exclusão de extensões do kernel.

Para pesquisadores de kernel, a lição importante é que a **attack surface do kernel pode ser reintroduzida a partir de daemons de gerenciamento em userland**, mesmo quando o carregamento direto de kexts de terceiros é fortemente restrito.

Triagem útil:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing e fluxo de pesquisa

Se você está procurando ativamente essa classe de bugs, o trabalho público recente aponta na mesma direção:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) continua sendo uma das melhores referências para pesquisa de kernel na era do Apple Silicon. Ele usa **static binary rewriting** para recuperar coverage, desativa caminhos protegidos por **entitlement** durante os testes e infere a estrutura da interface a partir de wrappers de userspace.
- O [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html), do Project Zero, mostra um workflow muito prático para **rebasing de uma kext / fileset em userspace**, permitindo que códigos focados em parsers sejam fuzzed em uma velocidade muito maior antes da reprodução no dispositivo.
- Para targets focados em Mach, crie harnesses em torno de **layouts de mensagens reais e máquinas de estado com múltiplas chamadas**, e não apenas blobs de selectors individuais. Pesquisas recentes sobre CoreAudio/Mach do Project Zero e palestras de conferências, como **Fuzzing at Mach Speed**, mostram por que sequências de mensagens stateful continuam trazendo resultados.

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
## Lista rápida de Enumeration
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

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Análise do CVE-2024-44243, um bypass do System Integrity Protection do macOS por meio de extensões do kernel.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
