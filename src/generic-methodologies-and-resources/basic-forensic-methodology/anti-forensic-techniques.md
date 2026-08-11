# Técnicas Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Um atacante pode ter interesse em **alterar os timestamps dos arquivos** para evitar ser detectado.\
É possível encontrar os timestamps dentro da MFT nos atributos `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Ambos os atributos têm 4 timestamps: **Modification**, **access**, **creation** e **MFT registry modification** (MACE ou MACB).

O **Windows Explorer** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Essa ferramenta **modifica** as informações de timestamp dentro de **`$STANDARD_INFORMATION`**, mas **não** as informações dentro de **`$FILE_NAME`**. Portanto, é possível **identificar** **atividades** **suspeitas**.

### Usnjrnl

O **USN Journal** (Update Sequence Number Journal) é um recurso do NTFS (Windows NT file system) que acompanha as alterações no volume. A ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar essas alterações.

![TimeStomp - Anti-forensic Tool - Usnjrnl: O USN Journal (Update Sequence Number Journal) é um recurso do NTFS (Windows NT file system) que acompanha as alterações no volume. A...](<../../images/image (801).png>)

A imagem anterior mostra o **output** exibido pela **ferramenta**, onde é possível observar que algumas **alterações foram realizadas** no arquivo.

### $LogFile

**Todas as alterações de metadados em um file system são registradas** em um processo conhecido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Os metadados registrados são mantidos em um arquivo chamado `**$LogFile**`, localizado no diretório raiz de um file system NTFS. Ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) podem ser usadas para analisar esse arquivo e identificar alterações.

![Usnjrnl - $LogFile: Todas as alterações de metadados em um file system são registradas em um processo conhecido como write-ahead logging. Os metadados registrados são mantidos em um arquivo chamado $LogFile , localizado no diretório raiz...](<../../images/image (137).png>)

Novamente, no output da ferramenta, é possível ver que **algumas alterações foram realizadas**.

Usando a mesma ferramenta, é possível identificar **em que momento os timestamps foram modificados**:

![Usnjrnl - $LogFile: Usando a mesma ferramenta, é possível identificar em que momento os timestamps foram modificados](<../../images/image (1089).png>)

- CTIME: Hora de criação do arquivo
- ATIME: Hora de modificação do arquivo
- MTIME: Modificação do registro MFT do arquivo
- RTIME: Hora de acesso do arquivo

### Comparação entre `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra forma de identificar arquivos modificados suspeitos seria comparar o horário em ambos os atributos, procurando por **inconsistências**.

### Nanoseconds

Os timestamps do **NTFS** têm uma **precisão** de **100 nanoseconds**. Portanto, encontrar arquivos com timestamps como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

### SetMace - Anti-forensic Tool

Essa ferramenta pode modificar ambos os atributos `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário que um sistema operacional ativo modifique essas informações.

## Ocultação de dados

O NFTS usa um cluster e o tamanho mínimo de informação. Isso significa que, se um arquivo ocupar um cluster e meio, a **metade restante nunca será usada** até que o arquivo seja excluído. Assim, é possível **ocultar dados nesse slack space**.

Existem ferramentas como o slacker que permitem ocultar dados nesse espaço "oculto". No entanto, uma análise do `$logfile` e do `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![SetMace - Anti-forensic Tool - Data Hiding: Existem ferramentas como o slacker que permitem ocultar dados nesse espaço "oculto". No entanto, uma análise do $logfile e do $usnjrnl pode mostrar que...](<../../images/image (1060).png>)

Assim, é possível recuperar o slack space usando ferramentas como o FTK Imager. Observe que esse tipo de ferramenta pode salvar o conteúdo ofuscado ou até mesmo criptografado.

## UsbKill

Esta é uma ferramenta que **desliga o computador se alguma alteração nas portas USB** for detectada.\
Uma forma de descobrir isso seria inspecionar os processos em execução e **analisar cada script Python em execução**.

## Live Linux Distributions

Essas distros são **executadas dentro da memória RAM**. A única forma de detectá-las é **caso o file system NTFS esteja montado com permissões de escrita**. Se estiver montado apenas com permissões de leitura, não será possível detectar a intrusão.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Configuração do Windows

É possível desabilitar vários métodos de logging do Windows para dificultar muito a investigação forense.

### Desabilitar Timestamps - UserAssist

Esta é uma chave do registro que mantém as datas e os horários em que cada executável foi executado pelo usuário.

Desabilitar o UserAssist requer duas etapas:

1. Defina duas chaves do registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas como zero, para indicar que queremos desabilitar o UserAssist.
2. Limpe as subárvores do registro semelhantes a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Desabilitar Timestamps - Prefetch

Isso salva informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, isso também pode ser útil para práticas forenses.

- Execute `regedit`
- Selecione o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Clique com o botão direito em `EnablePrefetcher` e `EnableSuperfetch`
- Selecione Modify em cada um deles para alterar o valor de 1 (ou 3) para 0
- Reinicie

### Desabilitar Timestamps - Last Access Time

Sempre que uma pasta é aberta a partir de um volume NTFS em um servidor Windows NT, o sistema registra o horário para **atualizar um campo de timestamp em cada pasta listada**, chamado de last access time. Em um volume NTFS muito utilizado, isso pode afetar o desempenho.

1. Abra o Registry Editor (Regedit.exe).
2. Navegue até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procure por `NtfsDisableLastAccessUpdate`. Se não existir, adicione este DWORD e defina seu valor como 1, o que desabilitará o processo.
4. Feche o Registry Editor e reinicie o servidor.

### Excluir histórico de USB

Todas as **entradas de dispositivos USB** são armazenadas no Windows Registry, na chave de registro **USBSTOR**, que contém subchaves criadas sempre que você conecta um dispositivo USB ao seu PC ou laptop. Você pode encontrar essa chave aqui H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Excluir isso** excluirá o histórico de USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para garantir que você os excluiu (e para excluí-los).

Outro arquivo que armazena informações sobre os dispositivos USB é o arquivo `setupapi.dev.log`, dentro de `C:\Windows\INF`. Ele também deve ser excluído.

### Desabilitar Shadow Copies

**Liste** as shadow copies com `vssadmin list shadowstorage`\
**Exclua-as** executando `vssadmin delete shadow`

Você também pode excluí-las pela GUI seguindo as etapas propostas em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desabilitar as shadow copies [etapas daqui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abra o programa Services digitando "services" na caixa de pesquisa de texto após clicar no botão Iniciar do Windows.
2. Na lista, localize "Volume Shadow Copy", selecione-o e acesse Properties clicando com o botão direito.
3. Escolha Disabled no menu suspenso "Startup type" e confirme a alteração clicando em Apply e OK.

Também é possível modificar no registro quais arquivos serão copiados na shadow copy em `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescrever arquivos excluídos

- Você pode usar uma **ferramenta do Windows**: `cipher /w:C`. Isso fará com que o cipher remova todos os dados do espaço em disco não utilizado disponível na unidade C.
- Você também pode usar ferramentas como [**Eraser**](https://eraser.heidi.ie)

### Excluir logs de eventos do Windows

- Windows + R --> eventvwr.msc --> Expanda "Windows Logs" --> Clique com o botão direito em cada categoria e selecione "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Desabilitar logs de eventos do Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Na seção de serviços, desabilite o serviço "Windows Event Log"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Desabilitar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Adulteração avançada de Logging e rastreamento (2023-2025)

### PowerShell ScriptBlock/Module Logging

Versões recentes do Windows 10/11 e do Windows Server mantêm **artefatos forenses detalhados do PowerShell** em
`Microsoft-Windows-PowerShell/Operational` (eventos 4104/4105/4106).
Atacantes podem desabilitá-los ou apagá-los on-the-fly:
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
Os defensores devem monitorar alterações nessas chaves do registro e a remoção em grande volume de eventos do PowerShell.

### ETW (Event Tracing for Windows) Patch

Os produtos de segurança de endpoint dependem fortemente do ETW. Um método de evasão popular em 2024 consiste em aplicar um patch em `ntdll!EtwEventWrite`/`EtwEventWriteFull` na memória, fazendo com que cada chamada do ETW retorne `STATUS_SUCCESS` sem emitir o evento:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
PoCs públicos (por exemplo, `EtwTiSwallow`) implementam a mesma primitiva em PowerShell ou C++.
Como o patch é **local ao processo**, EDRs executados dentro de outros processos podem não detectá-lo.<sup>[[5]](#references)</sup>
Detecção: compare o `ntdll` na memória com o arquivo em disco ou faça o hook antes do user-mode.

### Revitalização de Alternate Data Streams (ADS)

Campanhas de malware em 2023 (por exemplo, loaders do **FIN12**) foram observadas armazenando binários de segundo estágio
dentro de ADS para permanecerem fora do alcance dos scanners tradicionais:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumere os streams com `dir /R`, `Get-Item -Stream *` ou o `streams64.exe` da Sysinternals.
Copiar o arquivo hospedeiro para FAT/exFAT ou via SMB removerá o stream oculto e poderá ser usado
por investigadores para recuperar o payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver é agora usado rotineiramente para **anti-forensics** em intrusões de ransomware.
A ferramenta open-source **AuKill** carrega um driver assinado, porém vulnerável (`procexp152.sys`), para
suspender ou encerrar o EDR e os sensores forenses **antes da criptografia e da destruição dos logs**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
O driver é removido posteriormente, deixando o mínimo de artefatos.<sup>[[1]](#references)</sup>
Mitigações: habilite a lista de bloqueio de drivers vulneráveis da Microsoft (HVCI/SAC)
e gere alertas para a criação de serviços de kernel a partir de caminhos graváveis pelo usuário.

---

## Anti-Forensics no Linux: Self-Patching e Cloud C2 (2023–2025)

### Self-patching de serviços comprometidos para reduzir a detecção (Linux)
Os adversários estão cada vez mais fazendo “self-patching” em um serviço logo após explorá-lo, tanto para impedir uma nova exploração quanto para suprimir detecções baseadas em vulnerabilidades. A ideia é substituir componentes vulneráveis pelos binários/JARs legítimos mais recentes do upstream, fazendo com que os scanners informem que o host está atualizado, enquanto a persistência e o C2 permanecem.<sup>[[3]](#references)</sup>

Exemplo: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Após a exploração, os invasores baixaram JARs legítimos do Maven Central (repo1.maven.org), excluíram os JARs vulneráveis da instalação do ActiveMQ e reiniciaram o broker.
- Isso encerrou o RCE inicial, mantendo outros pontos de acesso (cron, alterações na configuração do SSH, implantes C2 separados).

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
Dicas de forense/hunting
- Revise os diretórios de serviços em busca de substituições não programadas de binários/JARs:
- Debian/Ubuntu: `dpkg -V activemq` e compare os hashes/caminhos dos arquivos com os mirrors do repositório.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Procure versões de JAR presentes no disco que não pertençam ao package manager ou links simbólicos atualizados fora do processo normal.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime com a janela do comprometimento.
- Shell history/process telemetry: evidências de `curl`/`wget` para `repo1.maven.org` ou outros artifact CDNs imediatamente após a exploração inicial.
- Change management: valide quem aplicou o “patch” e por quê, não apenas se uma versão corrigida está presente.

### C2 de Cloud-service com bearer tokens e stagers anti-analysis
O tradecraft observado combinava múltiplos caminhos de C2 de longa duração e empacotamento anti-analysis:<sup>[[3]](#references)</sup>
- Loaders ELF do PyInstaller protegidos por senha para dificultar sandboxing e análise estática (por exemplo, PYZ criptografado e extração temporária em `/_MEI*`).
- Indicadores: ocorrências em `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefatos de runtime: extração para `/tmp/_MEI*` ou caminhos personalizados de `--runtime-tmpdir`.
- C2 baseado no Dropbox usando OAuth Bearer tokens hardcoded
- Marcadores de rede: `api.dropboxapi.com` / `content.dropboxapi.com` com `Authorization: Bearer <token>`.
- Faça hunting em proxy/NetFlow/Zeek/Suricata por HTTPS de saída para domínios do Dropbox a partir de workloads de servidores que normalmente não sincronizam arquivos.
- C2 paralelo/de backup via tunneling (por exemplo, Cloudflare Tunnel `cloudflared`), mantendo o controle caso um canal seja bloqueado.
- IOCs de host: processos/unidades `cloudflared`, configuração em `~/.cloudflared/*.json`, saída na porta 443 para as edges da Cloudflare.

### Persistence e “hardening rollback” para manter o acesso (exemplos Linux)
Os atacantes frequentemente combinam self-patching com caminhos de acesso duráveis:<sup>[[3]](#references)</sup>
- Cron/Anacron: edições no stub `0anacron` em cada diretório `/etc/cron.*/` para execução periódica.
- Faça hunting:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Hardening rollback da configuração SSH: habilitação de logins de root e alteração dos shells padrão de contas com poucos privilégios.
- Faça hunting para habilitação de login de root:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Faça hunting por shells interativos suspeitos em contas do sistema (por exemplo, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Artefatos de beacon aleatórios, com nomes curtos (8 caracteres alfabéticos), gravados no disco e que também se conectam ao cloud C2:
- Faça hunting:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Os defensores devem correlacionar esses artefatos com a exposição externa e os eventos de patching dos serviços para descobrir a self-remediation anti-forensic usada para ocultar a exploração inicial.

## References

- [1] [Sophos X-Ops – AuKill: Um driver vulnerável weaponized para desabilitar o EDR (março de 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Aplicando patch em EtwEventWrite para stealth: detecção e hunting (junho de 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Aplicando patch para persistence: como o malware Linux DripDropper se move pela cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE do Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ocultando seu .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
