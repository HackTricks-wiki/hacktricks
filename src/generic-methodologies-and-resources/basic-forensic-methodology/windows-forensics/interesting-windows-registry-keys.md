# Chaves Interessantes do Registro do Windows

{{#include ../../../banners/hacktricks-training.md}}

As hives do Registro do Windows são uma das formas mais rápidas de passar de _o que aconteceu?_ para _qual usuário, quando e de onde?_. Para análise ao vivo, prefira `CurrentControlSet`; para análise offline de hives, primeiro resolva qual `ControlSet00x` estava ativo, em vez de definir `ControlSet001` diretamente.

### Informações sobre a Versão e o Proprietário do Windows

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edição/build do Windows, horário de instalação, proprietário registrado, nome do produto e outros metadados do build.
- `SYSTEM\Select`: mapeia `Current`, `Default` e `LastKnownGood` para os valores reais de `ControlSet00x` usados pelo sistema.

### Nome do Computador

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname atual.

### Configuração do Fuso Horário

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuso horário configurado e valores relacionados ao horário de verão.

### Rastreamento de Horários de Acesso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica se os timestamps de último acesso do NTFS estão sendo atualizados.
- Para habilitá-lo, use: `fsutil behavior set disablelastaccess 0`

### Detalhes do Desligamento

- `SYSTEM\CurrentControlSet\Control\Windows`: horário do último desligamento.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: sistemas mais antigos também podem expor contadores de desligamento.

### Configuração de Rede

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs das interfaces, concessões DHCP, dados de gateway e DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nome/SSID do perfil de rede, além dos horários da primeira e da última conexão.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` e `...\Unmanaged\{GUID}`: dados de correlação do perfil, como endereço MAC do gateway e sufixo DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: pastas compartilhadas locais publicadas pelo host.

### Acesso Remoto e Histórico de Compartilhamentos de Rede

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU de RDP de saída (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: histórico de RDP de saída por host. As subchaves geralmente armazenam `UsernameHint`, e o horário de `LastWrite` da chave é um pivot útil.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unidades de rede mapeadas, compartilhamentos UNC e pontos de montagem de mídias removíveis associados a um usuário específico.

### Programas que Iniciam Automaticamente e Persistência Agendada

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` e `...\Tasks\{GUID}`: metadados de tarefas agendadas. Se uma tarefa existir aqui, mas o valor `SD` estiver ausente de `Tree\<TaskName>`, suspeite de adulteração de tarefas no estilo Tarrask e correlacione-a com `C:\Windows\System32\Tasks\<TaskName>`.

### Pesquisas, Caminhos Digitados e MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termos de pesquisa do File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: caminhos do Explorer digitados manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: os últimos 26 comandos do `Win + R`. `MRUList` preserva a ordem deles.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documentos e pastas abertos recentemente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: arquivos recentes do Office.

### Rastreamento de Atividades do Usuário

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: histórico de execução iniciada pela GUI. Os nomes dos valores são codificados em ROT13, e os dados binários incluem contadores de execução e o horário da última execução.<sup>[[1]](#references)</sup>
- Trate `UserAssist` como evidência de forte apoio, não como uma conclusão isolada: ele rastreia principalmente aplicativos ou arquivos `.lnk` iniciados pelo Explorer e pode não registrar execuções pela linha de comando ou por serviços. No Windows 10+, algumas entradas não significam necessariamente que o processo foi executado completamente.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` e `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: rastros modernos de execução do Windows 10/11 com atribuição de SID e horário da última execução. Eles são especialmente úteis para binários executados localmente, mas entradas antigas podem expirar rapidamente, e execuções a partir de compartilhamentos de rede/mídias removíveis são menos confiáveis.
- Para artefatos de execução mais abrangentes, como Prefetch, Amcache, ShimCache e SRUM, consulte a [visão geral de forensics do Windows](README.md#programs-executed).

### Shellbags

- Os Shellbags são armazenados tanto em `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` quanto em `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- As entradas de `NTUSER.DAT` são especialmente úteis para navegação UNC/rede, enquanto `UsrClass.dat` é onde o Windows Vista+ normalmente armazena Shellbags de pastas locais/removíveis.
- Eles podem mostrar a existência e a navegação por pastas, além das preferências de visualização, mesmo depois que a pasta foi excluída. O acesso a arquivos compactados semelhante ao do Explorer também pode deixar rastros de Shellbag.<sup>[[1]](#references)</sup>
- Nem todo Shellbag comprova acesso bem-sucedido à pasta; portanto, corrobore com LNKs, Jump Lists, timestamps ou mapeamentos de volume.
- Use o **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ou o **SBECmd** para analisá-los.

### Informações sobre USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventário principal de dispositivos USB de armazenamento em massa (fornecedor, produto, revisão, número de série/instância do dispositivo).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventário mais amplo de dispositivos USB, incluindo dispositivos que não são de armazenamento.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: em builds recentes do Windows 10/11, este é um local de alto valor para timestamps do ciclo de vida por dispositivo, como instalação, primeira instalação, última conexão e última remoção.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: mapeia volumes e identificadores de dispositivos para letras de unidade / GUIDs de volume. Somente o último mapeamento de uma determinada letra de unidade pode permanecer.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot útil para números de série de volumes e metadados de mídias anteriores.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: histórico específico do usuário de interações com letras de unidade e compartilhamentos.<sup>[[2]](#references)</sup>
- Telefones e tablets modernos conectados via MTP/PTP podem **não** aparecer em `USBSTOR`. Verifique também `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` e `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Para associar um dispositivo a um usuário, faça pivot a partir dos identificadores do dispositivo ou do volume para artefatos por usuário, como Shellbags, LNKs, Jump Lists, `RecentDocs` e `MountPoints2`.<sup>[[2]](#references)</sup>

## Referências

- [1] [Guia de Referência Rápida de Forensics do Registro do Windows 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Forensics de Dispositivos USB no Windows 10 e 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
