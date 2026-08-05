# Sealed System Volume e DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informações básicas

A partir do **macOS Big Sur (11.0)**, o volume do sistema é selado criptograficamente usando uma **árvore de hashes de snapshot do APFS**. Isso é chamado de **Sealed System Volume (SSV)**. A partição do sistema é montada como **somente leitura**, e qualquer modificação quebra o selo, que é verificado durante a inicialização.

O SSV fornece:
- **Detecção de adulteração** — qualquer modificação em binários ou frameworks do sistema pode ser detectada por meio do selo criptográfico quebrado
- **Proteção contra rollback** — o processo de inicialização verifica a integridade do snapshot do sistema
- **Prevenção de Rootkits** — nem mesmo o root pode modificar arquivos persistentemente no volume do sistema (sem quebrar o selo)

### Verificando o status do SSV
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
### Entitlements de Escritores do SSV

Certos binários do sistema da Apple possuem entitlements que permitem modificar ou gerenciar o volume do sistema selado:

| Entitlement | Finalidade |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Reverter o volume do sistema para um snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Criar um novo snapshot selado após atualizações do sistema |
| `com.apple.rootless.install.heritable` | Escrever em paths protegidos pelo SIP (herdado por processos filhos) |
| `com.apple.rootless.install` | Escrever em paths protegidos pelo SIP |

### Encontrando Escritores do SSV
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
### Cenários de Ataque

#### Ataque de Rollback de Snapshot

Se um atacante comprometer um binário com `com.apple.private.apfs.revert-to-snapshot`, ele poderá **reverter o volume do sistema para um estado anterior à atualização**, restaurando vulnerabilidades conhecidas:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> O rollback de um snapshot efetivamente **desfaz atualizações de segurança**, restaurando vulnerabilidades do kernel e do sistema que já haviam sido corrigidas. Esta é uma das operações mais perigosas possíveis no macOS moderno.

#### Substituição de binários do sistema

Com o bypass do SIP + capacidade de escrita no SSV, um atacante pode:

1. Montar o volume do sistema com acesso de leitura e escrita
2. Substituir um daemon do sistema ou uma biblioteca de framework por uma versão trojanizada
3. Reassinar o snapshot (ou aceitar a assinatura quebrada se o SIP já estiver degradado)
4. O rootkit persiste após reinicializações e fica invisível para ferramentas de detecção em userland

### CVEs do mundo real

| CVE | Descrição |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass do SIP abusando do entitlement `com.apple.rootless.install.heritable` do `system_installd` para executar scripts arbitrários de pós-instalação ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Bypass do SIP: o `system_installd` preparava o script de pós-instalação em uma pasta protegida pelo SIP dentro de `/tmp`, mas o próprio `/tmp` não é protegido pelo SIP, portanto a pasta podia ser substituída montando uma imagem sobre ela ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race condition de copy-on-write no XNU que permite escritas em arquivos somente leitura pertencentes ao root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Informações básicas

O **DataVault** é a camada de proteção da Apple para bancos de dados sensíveis do sistema. Mesmo o **root não pode acessar arquivos protegidos pelo DataVault** — somente processos com entitlements específicos podem lê-los ou modificá-los.<sup>[[1]](#references)</sup> Os armazenamentos protegidos incluem:

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
### Cenários de Ataque

#### Modificação Direta do Banco de Dados TCC

Se um atacante comprometer um binário controlador do DataVault (por exemplo, por meio de code injection em um processo com `com.apple.private.tcc.manager`), poderá **modificar diretamente o banco de dados TCC** para conceder qualquer permissão TCC a qualquer aplicação:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> A modificação do banco de dados do TCC é o **bypass definitivo de privacidade** — concede qualquer permissão silenciosamente, sem qualquer prompt do usuário ou indicador visível. Historicamente, várias cadeias de privilege escalation do macOS terminaram com gravações no banco de dados do TCC como payload final.

#### Acesso ao banco de dados do Keychain

O DataVault também protege os arquivos de suporte do keychain. Um controlador DataVault comprometido pode:

1. Ler os arquivos brutos do banco de dados do keychain
2. Extrair itens criptografados do keychain
3. Tentar a descriptografia offline usando a senha do usuário ou chaves recuperadas

### CVEs do mundo real envolvendo bypass de DataVault/TCC

| CVE | Descrição |
|---|---|
| CVE-2024-44131 | Condição de corrida com symlink no FileProvider que permite a um helper privilegiado acessar dados protegidos pelo TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Como root, **criar um novo usuário cujo `NFSHomeDirectory` aponta para um `TCC.db` controlado pelo atacante**; no login, o `tccd` o consome e as concessões são aplicadas, permitindo acessar dados de outros usuários ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": alterar o diretório home do usuário para inserir um TCC.db controlado pelo atacante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Falha de conclusão de bundle que permite a um aplicativo **herdar as concessões de TCC de um bundle doador** sem um prompt; explorada in the wild pelo **XCSSET** para capturar screenshots da área de trabalho ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | O `tccd` construía o caminho do banco de dados a partir de `$HOME`, portanto `launchctl setenv HOME` o redirecionava para um `TCC.db` controlado pelo atacante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | O `coreaudiod` possuía `com.apple.private.tcc.manager` **e** desativava a validação de bibliotecas, portanto um plug-in HAL inserido em `/Library/Audio/Plug-Ins/HAL` poderia conceder direitos arbitrários de TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Referências

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
