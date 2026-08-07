# Vulnerabilidades do Kernel do macOS

{{#include ../../../banners/hacktricks-training.md}}

A exploração recente do kernel do macOS tem menos relação com "carregar uma kext unsigned trivial e obter ring-0" e mais com abusar de **parsers Mach/MIG**, **IOKit user clients**, **races data-only dentro do XNU** e **daemons com entitlements específicos** que ainda podem reabrir a attack surface do kernel. Para fazer o reversing das interfaces concretas, consulte também as páginas sobre [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces que ainda importam

- **Handlers Mach/MIG** em system daemons e serviços voltados ao kernel: descritores malformados, dados out-of-line (OOL) e fluxos stateful com várias mensagens.
- **IOKit user clients**: parsing específico de cada selector, métodos protegidos por entitlements e wrapper libraries/daemons que ocultam o call graph real.
- **Primitivas data-only do XNU**: races em torno de credenciais, ponteiros protegidos por SMR, read-only zones e outros locais onde a corrupção altera a policy sem primeiro obter controle de RIP/PC.
- **Código de kernel de terceiros / auxiliar**: kexts legadas são mais raras, mas fleets empresariais, sistemas Apple Silicon com reduced security e bundles `.fs` / helper de vendors ainda criam caminhos de alto valor adjacentes ao kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Em [**este report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), vários bugs da OTA/update chain são combinados para alcançar o comprometimento do kernel abusando do software update pipeline e de capabilities relacionadas ao rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

As [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) da Apple corrigiram dois problemas que foram **actively exploited**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: um bug de memory corruption em que um atacante com arbitrary kernel read/write podia ignorar as kernel memory protections.
- **CVE-2024-23296 – RTKit**: um segundo bug de memory corruption com a mesma public impact statement.

Os detalhes públicos da causa-raiz ainda são escassos, mas o par é um bom lembrete de que as exploit chains modernas da Apple frequentemente precisam de **mais do que "apenas" kernel R/W**: o trabalho de post-exploitation contra memory protections, código adjacente a coprocessors ou secondary trust boundaries costuma ser onde a chain real é estabilizada.

Triagem rápida de patches:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + corrida de credenciais read-only (CVE-2025-24118)

O [**write-up do TRAVERTINE**](https://jprx.io/cve-2025-24118/) de Joseph Ravichandran é um excelente estudo de caso moderno do XNU, pois **não** se trata de um buffer overflow clássico:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` é um **ponteiro protegido por SMR** armazenado em um objeto `proc_ro` **somente leitura**.
- Os writers devem atualizar esse ponteiro **atomicamente**.
- `kauth_cred_proc_update()` usava `zalloc_ro_mut(...)` para modificar `p_ucred`; no x86_64, esse caminho acaba chegando a `memcpy` / `rep movsb`, portanto um reader concorrente pode observar um **ponteiro parcialmente gravado**.
- O bug se transforma em uma **elevação de privilégios baseada apenas em dados**: se o ponteiro de credenciais corrompido resolver para um objeto de credenciais válido diferente, a thread atual poderá herdar um estado mais privilegiado sem antes obter um hijack óbvio do fluxo de controle.

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
Heurística útil de auditoria: sempre que um caminho do kernel combinar **SMR readers**, **mutação de zona somente leitura** e **metadados de credenciais ou tarefas**, verifique se as atualizações usam as variantes atômicas `zalloc_ro_mut_*`, em vez de helpers baseados em cópia.

---

## 2024-2025: SIP bypass que reabre caminhos de carregamento do kernel (CVE-2024-44243)

A Microsoft mostrou que `storagekitd` poderia ser abusado para **bypass do SIP** e, em seguida, tornar o código de kernel de terceiros relevante novamente em máquinas que, de outra forma, pareceriam estar no estado "post-kext". A ideia principal é:<sup>[[2]](#references)</sup>

1. Soltar ou sobrescrever um bundle `.fs` malicioso em `/Library/Filesystems`.
2. Acionar `storagekitd` por meio do Disk Utility ou do `diskutil`.
3. Permitir que o daemon com privilégios especiais inicie executáveis do bundle **sem remover corretamente os privilégios / validar o path**.
4. Usar o bypass do SIP resultante para alterar o estado protegido do sistema de arquivos e, na demonstração da Microsoft, sobrescrever a lista de exclusão de kernel extensions.

Para pesquisadores de kernel, a lição importante é que a **superfície de ataque do kernel pode ser reintroduzida a partir de daemons de gerenciamento em userland**, mesmo quando o carregamento direto de kexts de terceiros é fortemente restrito.

Triagem útil:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow de fuzzing e pesquisa

Se você estiver procurando ativamente por essa classe de bugs, o trabalho público recente está apontando na mesma direção:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) ainda é uma das melhores referências para pesquisa de kernel na era do Apple Silicon. Ele usa **static binary rewriting** para recuperar a cobertura, desabilita caminhos **entitlement-gated** durante os testes e infere a estrutura das interfaces a partir de wrappers do userspace.<sup>[[4]](#references)</sup>
- O [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) do Project Zero mostra um workflow muito prático para fazer **rebasing de um kext / fileset no userspace**, permitindo que código com muitos parsers seja submetido a fuzzing em uma velocidade muito maior antes da reprodução no dispositivo.<sup>[[5]](#references)</sup>
- Para alvos com muito Mach, crie harnesses em torno de **layouts de mensagens reais e máquinas de estado com múltiplas chamadas**, e não apenas blobs de seletores individuais. Pesquisas recentes sobre CoreAudio/Mach do Project Zero e palestras de conferências, como **Fuzzing at Mach Speed**, mostram por que sequências de mensagens com estado continuam sendo vantajosas.

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
- [2] [Microsoft Security Blog - Analisando CVE-2024-44243, um bypass do System Integrity Protection do macOS por meio de extensões do kernel](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - O pesadelo da atualização OTA da Apple: contornando a verificação de assinatura e fazendo Pwning do kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing de extensões do kernel do macOS no Apple Silicon por meio da exploração de mitigações (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Fuzzing simples de extensões do kernel do macOS no userspace com IDA e TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Sobre o conteúdo de segurança do macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
