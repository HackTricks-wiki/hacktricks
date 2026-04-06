# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informações Básicas

A partir do **macOS Big Sur (11.0)**, o volume do sistema é selado criptograficamente usando um **APFS snapshot hash tree**. Isso é chamado de **Sealed System Volume (SSV)**. A partição do sistema é montada **read-only** e qualquer modificação quebra o selo, que é verificado durante o boot.

O SSV fornece:
- **Detecção de adulteração** — qualquer modificação em binários/frameworks do sistema é detectável pelo selo criptográfico quebrado
- **Proteção contra rollback** — o processo de boot verifica a integridade do snapshot do sistema
- **Prevenção de rootkits** — até mesmo root não pode modificar persistentemente arquivos no volume do sistema (sem quebrar o selo)

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
### Entitlements de SSV Writer

Alguns binários do sistema Apple possuem entitlements que lhes permitem modificar ou gerenciar o sealed system volume:

| Entitlement | Finalidade |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Reverter o volume do sistema para um snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Criar um novo sealed snapshot após atualizações do sistema |
| `com.apple.rootless.install.heritable` | Escrever em caminhos protegidos por SIP (herdado por processos filhos) |
| `com.apple.rootless.install` | Escrever em caminhos protegidos por SIP |

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
### Cenários de Ataque

#### Snapshot Rollback Attack

Se um attacker comprometer um binary com `com.apple.private.apfs.revert-to-snapshot`, ele pode **reverter o volume do sistema para um estado anterior à atualização**, restaurando vulnerabilidades conhecidas:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback effectively **undoes security updates**, restoring previously-patched kernel and system vulnerabilities. This is one of the most dangerous operations possible on modern macOS.

#### Substituição de Binários do Sistema

Com bypass de SIP + capacidade de escrita em SSV, um atacante pode:

1. Montar o volume do sistema em leitura-gravação
2. Substituir um daemon do sistema ou uma biblioteca de framework por uma versão trojanizada
3. Re-selar o snapshot (ou aceitar o selo quebrado se o SIP já estiver degradado)
4. O rootkit persiste entre reinicializações e é invisível às ferramentas de detecção em userland

### CVEs do Mundo Real

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass allowing SSV modification via `system_installd` |
| CVE-2022-22583 | SSV bypass through PackageKit's snapshot handling |
| CVE-2022-46689 | Race condition allowing writes to SIP-protected files |

---

## DataVault

### Informações Básicas

**DataVault** é a camada de proteção da Apple para bancos de dados sensíveis do sistema. Mesmo o **root não pode acessar arquivos protegidos por DataVault** — apenas processos com entitlements específicos podem lê-los ou modificá-los. Armazenamentos protegidos incluem:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

A proteção do DataVault é aplicada no **nível do sistema de arquivos** usando atributos estendidos e flags de proteção do volume, verificados pelo kernel.

### Entitlements do DataVault Controller
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Encontrando Controladores do DataVault
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

Se um atacante comprometer um binário do controlador DataVault (por exemplo, via injeção de código em um processo com `com.apple.private.tcc.manager`), ele pode **modificar diretamente o banco de dados TCC** para conceder a qualquer aplicativo qualquer permissão TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> A modificação da base de dados TCC é o **bypass definitivo da privacidade** — concede qualquer permissão silenciosamente, sem qualquer prompt do utilizador ou indicador visível. Historicamente, múltiplas cadeias de escalada de privilégios no macOS terminaram com gravações na base de dados TCC como payload final.

#### Acesso à Base de Dados do Keychain

O DataVault também protege os ficheiros de suporte do Keychain. Um controlador DataVault comprometido pode:

1. Ler os ficheiros brutos da base de dados do Keychain
2. Extrair itens encriptados do Keychain
3. Tentar desencriptação offline usando a senha do utilizador ou chaves recuperadas

### CVEs Reais Envolvendo DataVault/TCC Bypass

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## Referências

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
