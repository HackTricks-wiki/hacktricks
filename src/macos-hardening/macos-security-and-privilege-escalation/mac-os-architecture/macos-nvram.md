# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

**NVRAM** (Non-Volatile Random-Access Memory) armazena o firmware e o estado do early boot fora do filesystem normal do macOS. Seu impacto na segurança depende tanto da variável quanto da arquitetura de boot:

| Variável | Finalidade / relevância para a segurança |
|---|---|
| `boot-args` | Argumentos oferecidos ao kernel. Argumentos de debug ou que reduzem a segurança são filtrados, a menos que a boot policy permita seu uso. |
| `csr-active-config` | Bitmask do SIP em Macs Intel. No Apple silicon, a policy equivalente é armazenada no `LocalPolicy` por volume, e não é considerada confiável diretamente a partir dessa variável. |
| `efi-boot-device` / `efi-boot-device-data` | Destino de boot do EFI em Macs Intel. |
| `boot-volume` | Estado de seleção do boot-volume no Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Exemplos de configurações persistentes comuns. |

A distinção importante é entre **dados armazenados na NVRAM** e uma **security policy aceita pela boot chain**. No Apple silicon, o Secure Enclave assina uma `LocalPolicy` por grupo de boot-volume; um nonce armazenado no Secure Storage Component fornece proteção anti-replay. Consequentemente, alterar uma propriedade da NVRAM com nome semelhante não reescreve, por si só, a boot policy aceita.<sup>[[1]](#references)[[4]](#references)</sup>

## Acesso à NVRAM a partir do User Space

### Leitura e coleta de baseline
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
Não classifique toda chave desconhecida como maliciosa. Hardware, recoveryOS, atualizações, Find My e falhas de inicialização criam variáveis dependentes do modelo e da versão. Compare uma captura com uma baseline anterior do **mesmo Mac** e trate blobs binários inesperados, alterações na seleção de inicialização ou argumentos que reduzam a segurança como indícios, não como prova de comprometimento.

### Gravando NVRAM

Root pode criar ou alterar muitas variáveis comuns, mas as variáveis protegidas também dependem do namespace da variável, do SIP, das regras do kernel específicas de cada variável e de entitlements restritos da Apple. Portanto, o sucesso de `sudo` para uma chave personalizada inofensiva **não** prova que o processo possa modificar `boot-args`, o SIP ou variáveis da região do sistema.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Evite `nvram -c` durante os testes: ele solicita a exclusão de todas as variáveis que podem ser excluídas e pode alterar o comportamento de inicialização/recuperação. Algumas variáveis são exclusivas do kernel, protegidas por entitlement, ocultas durante a leitura ou só podem ser excluídas durante uma redefinição da NVRAM.

## Entitlements da NVRAM e `CS_NVRAM_UNRESTRICTED`

No momento da execução, o XNU mapeia `com.apple.rootless.restricted-nvram-variables.heritable` para a flag de processo **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Isso não equivale à verificação comum de UID efetivo 0. Também existem entitlements privados mais restritos para determinadas variáveis ou operações.

Inspecione os entitlements em vez de depender da linha genérica de flags exibida por `codesign`:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Ao auditar um helper privilegiado, rastreie a **identidade real do cliente e o caminho da solicitação**. Um bug de confused-deputy em um serviço com entitlement pode ser mais útil do que invocar `nvram` diretamente, mas a variável/operação acessível ainda pode ser restringida pelo XNU.

## Estado do SIP no Intel vs `LocalPolicy` no Apple Silicon

### Intel: `csr-active-config`

No Intel, `csr-active-config` codifica as exceções `CSR_ALLOW_*`. As posições de bits normalmente relevantes são:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Leia a configuração efetiva com `csrutil status`; a saída bruta de `nvram` pode usar bytes little-endian codificados em porcentagem. Consulte [macOS SIP](../macos-security-protections/macos-sip.md) para conhecer as implicações de proteção e bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: inspecionar a política de inicialização aceita

No Apple silicon, `sip0` na `LocalPolicy` assinada pelo Secure Enclave contém os bits da política do SIP anteriormente armazenados na NVRAM. Os outros campos de política relevantes são `sip1` (permitir uma falha na verificação do root-hash do SSV), `sip2` (não bloquear a memória do kernel com CTRR) e `sip3` (desativar a allowlist de `boot-args` do iBoot). Esses campos só podem ser modificados a partir de um One True recoveryOS (1TR emparelhado); ativar `sip3` também exige um downgrade para Permissive Security.<sup>[[4]](#references)</sup>

Use apenas as operações de exibição durante a enumeração:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Não use opções de alteração de política do `bputil` durante uma auditoria. Um comprometimento normal do macOS não deve conseguir ativar silenciosamente os campos acima: o caminho de downgrade exige deliberadamente acesso físico ao 1TR emparelhado e autenticação do proprietário.<sup>[[4]](#references)</sup>

## Implicações de Segurança

### `boot-args` como Amplificador Pós-Comprometimento

Argumentos como opções de debugging do kernel, `kcsuffix=development` ou `amfi_get_out_of_my_way=1` podem enfraquecer etapas posteriores do boot, mas somente quando a plataforma os aceita. No Apple silicon, em Full ou Reduced Security, o iBoot filtra argumentos que reduzem a segurança; argumentos irrestritos exigem o downgrade da política `sip3` descrito acima. No Intel, a restrição de NVRAM do SIP impede de forma semelhante tratar um root shell como controle automático de `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Consulte [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) e [kernel debugging](macos-kernel-extensions.md) em vez de presumir que um argumento histórico se comporta de forma idêntica em todas as versões do macOS.

### Execução de `rc.trampoline` respaldada pelo NVRAM

Pesquisas recentes documentaram um consumidor concreto de dados do NVRAM: o binário de plataforma da Apple `/System/Library/CoreServices/rc.trampoline`. Quando o launchd detecta o argumento de inicialização `rc.trampoline=1`, essa tarefa de inicialização lê a propriedade `apple-trusted-trampoline` de `IODeviceTree:/options`, grava-a em um executável temporário, inicia-o suspenso, verifica seu estado de code-signing, remove o arquivo e então retoma sua execução. A tarefa de inicialização bloqueia o launchd até que o processo filho termine.<sup>[[5]](#references)</sup>

Este é um **primitivo de persistência pós-downgrade, não um bypass do SIP**. O caminho demonstrado exigia que o SIP estivesse desativado para que a tarefa de inicialização fosse executada e `boot-args` pudesse ser definido. A pesquisa também observou um limite aproximado de 390 KB para o tamanho do valor. Sua utilidade está no fato de que bytes executáveis podem permanecer fora do sistema de arquivos normal e ser materializados durante a inicialização depois que um atacante já obteve o downgrade de segurança necessário.<sup>[[5]](#references)</sup>

Procure ambos os artefatos necessários e o evento do launchd:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Variáveis NVRAM personalizadas arbitrárias são, de outra forma, apenas **armazenamento**: elas não executam nada, a menos que o firmware, um componente de inicialização da Apple ou um mecanismo separado de persistência as consuma. Essa distinção evita superestimar um marcador como `nvram attacker-config=...` como execução de código no firmware.

## Script de enumeração

<details>
<summary>Auditoria da NVRAM e da política de inicialização do Apple silicon</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Guia de Segurança das Plataformas Apple — Processo de inicialização](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Atualizações de Segurança da Apple — CVEs relacionados ao NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Segurança do Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Segurança das Plataformas Apple — Conteúdo de um arquivo LocalPolicy para um Mac com Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Além dos bons e antigos LaunchAgents — Persistir através do NVRAM com apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
