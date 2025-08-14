# Técnicas Anti-Forense

{{#include ../../banners/hacktricks-training.md}}

## Carimbos de Data/Hora

Um atacante pode estar interessado em **alterar os carimbos de data/hora dos arquivos** para evitar ser detectado.\
É possível encontrar os carimbos de data/hora dentro do MFT nos atributos `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Ambos os atributos têm 4 carimbos de data/hora: **Modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

**Windows explorer** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

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

1. Defina duas chaves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas para zero, a fim de sinalizar que queremos desativar o UserAssist.
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

Todas as **Entradas de Dispositivos USB** são armazenadas no Registro do Windows sob a chave de registro **USBSTOR**, que contém subchaves que são criadas sempre que você conecta um dispositivo USB ao seu PC ou Laptop. Você pode encontrar esta chave aqui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Excluindo isso**, você excluirá o histórico USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para ter certeza de que as excluiu (e para excluí-las).

Outro arquivo que salva informações sobre os USBs é o arquivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Este também deve ser excluído.

### Desativar Cópias de Sombra

**Liste** as cópias de sombra com `vssadmin list shadowstorage`\
**Exclua**-as executando `vssadmin delete shadow`

Você também pode excluí-las via GUI seguindo os passos propostos em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar cópias de sombra [passos a partir daqui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

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
Enumere fluxos com `dir /R`, `Get-Item -Stream *` ou Sysinternals `streams64.exe`. Copiar o arquivo host para FAT/exFAT ou via SMB removerá o fluxo oculto e pode ser usado por investigadores para recuperar a carga útil.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver agora é rotineiramente usado para **anti-forensics** em intrusões de ransomware. A ferramenta de código aberto **AuKill** carrega um driver assinado, mas vulnerável (`procexp152.sys`), para suspender ou encerrar sensores EDR e forenses **antes da criptografia e destruição de logs**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
O driver é removido posteriormente, deixando artefatos mínimos.  
Mitigações: habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (HVCI/SAC) e alertar sobre a criação de serviços do kernel a partir de caminhos graváveis pelo usuário.

---

## Referências

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (Março 2023)  
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr  
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (Junho 2024)  
https://redcanary.com/blog/etw-patching-detection  

{{#include ../../banners/hacktricks-training.md}}
