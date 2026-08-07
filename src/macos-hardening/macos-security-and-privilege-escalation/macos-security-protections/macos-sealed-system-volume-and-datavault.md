# Volume de Sistema Selado (SSV) do macOS & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volume de Sistema Selado (SSV)

### Informações Básicas

A partir do **macOS Big Sur (11.0)**, o volume do sistema é selado criptograficamente usando uma **árvore de hashes de snapshot do APFS**. Isso é chamado de **Sealed System Volume (SSV)**. A partição do sistema é montada **somente para leitura**, e qualquer modificação rompe o selo, que é verificado durante a inicialização.<sup>[[11]](#references)</sup>

O SSV fornece:
- **Detecção de adulteração** — qualquer modificação em binários ou frameworks do sistema pode ser detectada por meio do selo criptográfico rompido
- **Proteção contra rollback** — o processo de inicialização verifica a integridade do snapshot do sistema
- **Prevenção de rootkits** — até mesmo o root não pode modificar arquivos persistentemente no volume do sistema (sem romper o selo)

### Verificando o Status do SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### Entitlements de SSV Writers

Certos binários do sistema da Apple possuem entitlements que permitem modificar ou gerenciar o sealed system volume:

| Entitlement | Finalidade |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Reverter o system volume para um snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Criar um novo sealed snapshot após atualizações do sistema |
| `com.apple.rootless.install.heritable` | Escrever em caminhos protegidos pelo SIP (herdado pelos processos filhos) |
| `com.apple.rootless.install` | Escrever em caminhos protegidos pelo SIP |

### Encontrando SSV Writers
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Attack Scenarios

#### Snapshot Rollback Attack

Se um atacante comprometer um binário com `com.apple.private.apfs.revert-to-snapshot`, ele poderá **reverter o volume do sistema para um estado anterior à atualização**, restaurando vulnerabilidades conhecidas:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> O rollback de um snapshot efetivamente **desfaz atualizações de segurança**, restaurando vulnerabilidades anteriormente corrigidas no kernel e no sistema. Esta é uma das operações mais perigosas possíveis no macOS moderno.

#### Substituição de binário do sistema

Com o bypass do SIP + capacidade de escrita no SSV, um atacante pode:

1. Montar o volume do sistema com acesso de leitura e escrita
2. Substituir um daemon do sistema ou uma biblioteca de framework por uma versão trojanizada
3. Selar novamente o snapshot (ou aceitar o selo quebrado se o SIP já estiver degradado)
4. O rootkit persiste após reinicializações e fica invisível para ferramentas de detecção em userland

### CVEs do mundo real

| CVE | Descrição |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass do SIP abusando do entitlement `com.apple.rootless.install.heritable` do `system_installd` para executar scripts pós-instalação arbitrários ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass do SIP: o `system_installd` preparava o script pós-instalação em uma pasta protegida pelo SIP dentro de `/tmp`, mas o próprio `/tmp` não é protegido pelo SIP; portanto, a pasta podia ser substituída montando uma imagem sobre ela ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — condição de corrida copy-on-write no XNU que permite escritas em arquivos somente leitura pertencentes ao root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informações básicas

O **DataVault** é a camada de proteção da Apple para bancos de dados sensíveis do sistema. Mesmo o **root não pode acessar arquivos protegidos pelo DataVault** — somente processos com entitlements específicos podem lê-los ou modificá-los.<sup>[[4]](#references)</sup> Os armazenamentos protegidos incluem:

| Banco de dados protegido | Caminho | Conteúdo |
|---|---|---|
| TCC (sistema) | `/Library/Application Support/com.apple.TCC/TCC.db` | Decisões de privacidade do TCC em todo o sistema |
| TCC (usuário) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decisões de privacidade do TCC por usuário |
| Keychain (sistema) | `/Library/Keychains/System.keychain` | Keychain do sistema |
| Keychain (usuário) | `~/Library/Keychains/login.keychain-db` | Keychain do usuário |

A proteção do DataVault é aplicada no **nível do sistema de arquivos** usando atributos estendidos e flags de proteção do volume, verificados pelo kernel.

### Entitlements do controlador do DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Encontrando controladores do DataVault
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Cenários de ataque

#### Modificação direta do banco de dados do TCC

Se um atacante comprometer um binário controlador do DataVault (por exemplo, por meio de injeção de código em um processo com `com.apple.private.tcc.manager`), ele poderá **modificar diretamente o banco de dados do TCC** para conceder a qualquer aplicativo qualquer permissão do TCC:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> A modificação do database do TCC é o **ultimate privacy bypass** — concede qualquer permissão silenciosamente, sem qualquer user prompt ou indicador visível. Historicamente, várias cadeias de privilege escalation no macOS terminaram com gravações no database do TCC como payload final.

#### Acesso ao Database do Keychain

O DataVault também protege os arquivos de suporte do keychain. Um controller do DataVault comprometido pode:

1. Ler os arquivos brutos do database do keychain
2. Extrair itens criptografados do keychain
3. Tentar a descriptografia offline usando a senha do usuário ou chaves recuperadas

### CVEs do Mundo Real Envolvendo Bypass de DataVault/TCC

| CVE | Description |
|---|---|
| CVE-2024-44131 | FileProvider symlink race permitindo que um helper privilegiado alcance dados protegidos pelo TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Como root, **criar um novo usuário cujo `NFSHomeDirectory` aponte para um `TCC.db` controlado pelo atacante**; no login, o `tccd` o consome e as permissões concedidas são aplicadas, alcançando os dados de outros usuários ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": alterar o home dir do usuário para plantar um TCC.db controlado pelo atacante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Falha de conclusão do Bundle permitindo que um app **herde as permissões do TCC de um donor bundle** sem um prompt; explorada in the wild pelo **XCSSET** para tirar screenshots do desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | O `tccd` construía o caminho do DB a partir de `$HOME`, portanto `launchctl setenv HOME` o redirecionava para um `TCC.db` controlado pelo atacante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | O `coreaudiod` possuía `com.apple.private.tcc.manager` **e** tinha a library validation desativada, portanto um plug-in HAL colocado em `/Library/Audio/Plug-Ins/HAL` poderia conceder direitos arbitrários do TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## References

- [1] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technical Analysis: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Uncovering macOS Malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
