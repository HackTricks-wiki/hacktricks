# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Informações básicas

A partir do **macOS Big Sur (11.0)**, o volume do sistema é selado criptograficamente usando uma **árvore de hashes de snapshot APFS**. Isso é chamado de **Sealed System Volume (SSV)**. A partição do sistema é montada como **somente leitura**, e qualquer modificação rompe o selo, que é verificado durante a inicialização.<sup>[[11]](#references)</sup>

O SSV fornece:
- **Detecção de adulteração** — qualquer modificação nos binários/frameworks do sistema altera a raiz da Merkle-tree e invalida o selo assinado pela Apple
- **Autenticação durante a inicialização** — a cadeia de inicialização verifica o snapshot do sistema selecionado antes que ele se torne o sistema de arquivos raiz
- **Resistência a rootkits** — mesmo o root não pode substituir arquivos persistentemente no snapshot autenticado do sistema sem desativar a raiz autenticada ou comprometer um caminho de atualização autorizado

O SSV protege o volume **System**, não o volume gravável **Data** emparelhado a ele. Firmlinks mesclam ambos os volumes no namespace visível em `/`, portanto, um caminho que aparenta ser gravável não prova que o objeto subjacente pertence ao snapshot selado. FileVault e Data Protection protegem a confidencialidade dos dados em repouso; são mecanismos separados da integridade do SSV.<sup>[[11]](#references)</sup>

### Verificando o status do SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```
### Visão efetiva do sistema: SSV + grafts de Cryptex

Nas versões recentes do macOS, nem todo executável visível abaixo de `/System` necessariamente vem do snapshot SSV inicializado. **Cryptexes** são imagens de disco APFS autenticadas separadamente, cujo conteúdo é grafted sobre diretórios selecionados; portanto, as Rapid Security Responses podem substituir componentes sensíveis à segurança sem reconstruir o SSV base. Ao fazer triagem de persistence ou comparar o código do sistema, faça o inventário dos mounts ativos e do armazenamento de Cryptex do Preboot, em vez de calcular hashes apenas do snapshot base:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
A cadeia de inicialização e os detalhes do Rapid Security Response são abordados em [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); esta seção se concentra no próprio limite do SSV.

### Entitlements de processos que escrevem no SSV

Alguns binários de sistema da Apple têm entitlements que permitem modificar ou gerenciar o sealed system volume:

| Entitlement | Finalidade |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Reverter o volume do sistema para um snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Criar um novo snapshot selado após atualizações do sistema |
| `com.apple.rootless.install.heritable` | Escrever em caminhos protegidos pelo SIP (herdado por processos filhos) |
| `com.apple.rootless.install` | Escrever em caminhos protegidos pelo SIP |

### Encontrando processos que escrevem no SSV
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

#### Ataque de Reversão de Snapshot

Se um invasor comprometer um binário com `com.apple.private.apfs.revert-to-snapshot`, poderá **reverter o volume do sistema para um estado anterior à atualização**, restaurando vulnerabilidades conhecidas:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> O rollback do snapshot efetivamente **desfaz as atualizações de segurança**, restaurando vulnerabilidades anteriormente corrigidas no kernel e no sistema. Esta é uma das operações mais perigosas possíveis no macOS moderno.

#### Substituição de Binários do Sistema

Com o bypass do SIP + capacidade de escrita no SSV, um atacante pode:

1. Montar o volume do sistema com permissões de leitura e escrita
2. Substituir um daemon do sistema ou uma biblioteca de framework por uma versão trojanizada
3. Selar novamente o snapshot (ou aceitar o selo quebrado se o SIP já estiver degradado)
4. O rootkit persiste após reinicializações e fica invisível para ferramentas de detecção em userland

### CVEs do Mundo Real

| CVE | Descrição |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass do SIP abusando do entitlement `com.apple.rootless.install.heritable` do `system_installd` para executar scripts arbitrários de pós-instalação ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass do SIP: o `system_installd` preparava o script de pós-instalação em uma pasta protegida pelo SIP sob `/tmp`, mas o próprio `/tmp` não é protegido pelo SIP, portanto a pasta podia ser substituída montando uma imagem sobre ela ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race condition de copy-on-write no XNU que permite escritas em arquivos somente leitura pertencentes ao root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informações Básicas

**DataVault** é uma proteção de filesystem controlada por entitlement para arquivos e diretórios sensíveis. A flag BSD `UF_DATAVAULT` (`0x00000080`) marca um objeto como exigindo um entitlement tanto para leitura quanto para escrita; ao contrário do DAC normal, simplesmente tornar-se **root** ou receber Full Disk Access não satisfaz essa verificação enquanto a proteção estiver aplicada.<sup>[[4]](#references)[[13]](#references)</sup>

Não use “DataVault” como sinônimo de todo banco de dados protegido. Os bancos de dados do TCC são regidos pelo TCC/FDA e por políticas específicas do SIP (consulte [macOS TCC](macos-tcc/README.md)), enquanto o acesso a itens do keychain também depende das ACLs do Keychain e de proteção criptográfica (consulte [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Exemplos reais de DataVault geralmente aparecem como stores pertencentes a serviços abaixo de `/private/var/folders/.../0/`, como o store do Screen Time; a flag fica visível como `datavault` nas flags de arquivos BSD quando o diretório pai pode ser consultado com `stat`.

### Entitlements de Controladores do DataVault

| Entitlement | Limite |
|---|---|
| `com.apple.rootless.datavault.controller` | Acessar e gerenciar objetos `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gerenciar decisões do TCC; este é um limite de privacidade relacionado, mas separado |
| `com.apple.private.tcc.allow` | Bypass de serviços TCC selecionados nomeados no valor do entitlement |
| `com.apple.rootless.storage.TCC` | Escrever no store do TCC protegido pelo SIP |

Um processo que combine um entitlement de controlador do DataVault com funcionalidades de FDA, backup, indexação ou IPC é especialmente interessante: procure uma primitiva de confused deputy que copie um objeto protegido para um caminho comum, em vez de tentar abrir o vault diretamente.<sup>[[14]](#references)</sup>

### Encontrando Controladores do DataVault
```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
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

#### Modificação direta do banco de dados do TCC (limite separado do TCC)

Se um atacante comprometer um processo gerenciador do TCC (por exemplo, por meio de injeção de código em um processo que contenha `com.apple.private.tcc.manager`), ele poderá **modificar diretamente o banco de dados do TCC** para conceder qualquer permissão do TCC a qualquer aplicativo:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> A modificação do banco de dados do TCC é o **ultimate privacy bypass** — concede qualquer permissão silenciosamente, sem qualquer prompt do usuário ou indicador visível. Historicamente, várias cadeias de privilege escalation do macOS terminaram com gravações no banco de dados do TCC como payload final.

#### Acesso ao banco de dados do Keychain

O acesso bruto a um banco de dados que sustenta um keychain não equivale ao acesso a secrets em plaintext. Se outro boundary de privilégio permitir que um atacante copie o banco de dados, o material de chave e as ACLs dos itens ainda terão de ser atacados; consulte a página dedicada do [macOS Keychain](../../macos-red-teaming/macos-keychain.md) em vez de presumir que um entitlement de DataVault-controller seja suficiente.

#### Boundary de cópia de backup: Time Machine

Uma análise de 2026 demonstrou um padrão geral útil: o `backupd` possui tanto `com.apple.rootless.datavault.controller` quanto Full Disk Access para poder copiar stores protegidos. Na configuração testada, `/private/var/folders` estava incluído no Time Machine, e a cópia montada do backup não aplicava o boundary ativo do DataVault. O researcher usou isso para localizar o store SQLite do Screen Time e ler seu PIN de restrições em plaintext sem abrir o vault ativo. Trate isso como um **copy-boundary attack**: enumere deputies de backup, exportação, migração, indexação e diagnóstico que possam materializar dados do vault sob um mount ou path mais fraco.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Esse comportamento depende da versão e do layout do backup. Valide-o na build-alvo e lembre-se de que um destino do Time Machine criptografado protege a cópia apenas enquanto estiver bloqueado; depois de montado, seus controles de acesso passam a fazer parte da superfície de ataque.

### CVEs do mundo real envolvendo bypass de DataVault/TCC

| CVE | Descrição |
|---|---|
| CVE-2024-44131 | Race condition de symlink do FileProvider que permite a um helper privilegiado acessar dados protegidos pelo TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Como root, **criar um novo usuário cujo `NFSHomeDirectory` aponte para um `TCC.db` controlado pelo atacante**; no login, o `tccd` o consome e as permissões são aplicadas, permitindo acessar os dados de outros usuários ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": alterar o diretório home do usuário para inserir um TCC.db controlado pelo atacante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Falha na conclusão do bundle que permite a um app **herdar as permissões TCC de um bundle doador** sem solicitar confirmação; explorada in the wild pelo **XCSSET** para capturar screenshots do desktop ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | O `tccd` construía o caminho do DB a partir de `$HOME`, portanto `launchctl setenv HOME` o redirecionava para um `TCC.db` controlado pelo atacante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | O `coreaudiod` possuía `com.apple.private.tcc.manager` **e** desativava a validação de bibliotecas, portanto um plug-in HAL inserido em `/Library/Audio/Plug-Ins/HAL` poderia conceder direitos TCC arbitrários ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [A Microsoft encontra uma nova vulnerabilidade do macOS, Shrootless, que poderia ignorar a System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Análise técnica: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vale a pena fazer malfeito](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: bypass de TCC rouba dados do iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Investigando malware do macOS: ignorando o TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nova vulnerabilidade do macOS, "powerdir", poderia permitir acesso não autorizado aos dados do usuário](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Bypass de TCC zero-day descoberto no malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: ignorando o framework Transparency, Consent, and Control (TCC) do macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Toque a música e ignore o TCC, também conhecido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [O pesadelo das atualizações OTA da Apple (snapshots APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — exploração do TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [`stat.h` do XNU — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Como ignorar sua própria senha do Screen Time — análise do código-fonte e do Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
