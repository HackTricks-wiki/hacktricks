# Chaves Interessantes do Registro do Windows

{{#include ../../../banners/hacktricks-training.md}}

As hives do Registro do Windows são uma das formas mais rápidas de passar de _o que aconteceu?_ para _qual usuário, quando e de onde?_. Para análise em tempo real, prefira `CurrentControlSet`; para análise offline de hives, primeiro determine qual `ControlSet00x` estava ativo, em vez de usar `ControlSet001` por padrão.

### Informações da Versão do Windows e do Proprietário

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edição/build do Windows, horário de instalação, proprietário registrado, nome do produto e outros metadados da build.
- `SYSTEM\Select`: mapeia `Current`, `Default` e `LastKnownGood` para os valores reais de `ControlSet00x` usados pelo sistema.

### Nome do Computador

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: nome do host atual.

### Configuração do Fuso Horário

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuso horário configurado e valores relacionados ao horário de verão.

### Rastreamento do Horário de Acesso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica se os timestamps de último acesso do NTFS estão sendo atualizados.
- Para habilitar, use: `fsutil behavior set disablelastaccess 0`

### Detalhes do Desligamento

- `SYSTEM\CurrentControlSet\Control\Windows`: horário do último desligamento.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: sistemas mais antigos também podem expor contadores de desligamento.

### Configuração de Rede

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs das interfaces, leases DHCP, gateway e dados de DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nome/SSID do perfil de rede, além dos horários da primeira e da última conexão.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` e `...\Unmanaged\{GUID}`: dados de correlação do perfil, como endereço MAC do gateway e sufixo DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: pastas compartilhadas locais publicadas pelo host.

### Acesso Remoto e Histórico de Compartilhamentos de Rede

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU do RDP de saída (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: histórico de RDP de saída por host. As subchaves geralmente armazenam `UsernameHint`, e o horário `LastWrite` da chave é um ponto de partida útil.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unidades de rede mapeadas, compartilhamentos UNC e pontos de montagem de mídias removíveis associados a um usuário específico.

### Programas Iniciados Automaticamente e Persistência Agendada

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` e `...\Tasks\{GUID}`: metadados de tarefas agendadas. Se houver uma tarefa aqui, mas o valor `SD` estiver ausente de `Tree\<TaskName>`, suspeite de adulteração oculta de tarefa no estilo Tarrask e correlacione com `C:\Windows\System32\Tasks\<TaskName>`.

### Pesquisas, Caminhos Digitados e MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termos de pesquisa do Explorador de Arquivos.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: caminhos digitados manualmente no Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: os últimos 26 comandos de `Win + R`. `MRUList` preserva a ordem.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documentos e pastas abertos recentemente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: arquivos recentes do Office.

### Rastreamento de Atividade do Usuário

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: histórico de execução iniciada pela GUI. Os nomes dos valores são codificados com ROT13, e os dados binários incluem contadores de execução e o horário da última execução.<sup>[[1]](#references)</sup>
- Considere `UserAssist` uma evidência de apoio forte, não uma conclusão definitiva: ele rastreia principalmente aplicativos ou arquivos `.lnk` iniciados pelo Explorer e pode não registrar execuções pela linha de comando ou por serviços. No Windows 10+, algumas entradas não significam necessariamente que o processo foi executado por completo.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` e `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: rastros de execução em versões modernas do Windows 10/11, com atribuição por SID e horário da última execução. São especialmente úteis para binários executados localmente, mas entradas antigas podem expirar rapidamente, e execuções a partir de compartilhamentos de rede/mídias removíveis são menos confiáveis.
- Para outros artefatos de execução, como Prefetch, Amcache, ShimCache e SRUM, consulte a [visão geral de forense do Windows](./#programs-executed).

### Shellbags

- Shellbags são armazenados em `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` e em `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- As entradas de `NTUSER.DAT` são especialmente úteis para navegação UNC/em rede, enquanto `UsrClass.dat` é onde o Windows Vista+ costuma armazenar shellbags de pastas locais/removíveis.
- Elas podem indicar a existência e a navegação por pastas, além das preferências de exibição de pastas, mesmo depois que a pasta foi excluída. O acesso a arquivos compactados por ferramentas semelhantes ao Explorer também pode deixar rastros de shellbags.<sup>[[1]](#references)</sup>
- Nem toda shellbag comprova acesso bem-sucedido à pasta; por isso, corrobore com LNKs, Jump Lists, timestamps ou mapeamentos de volume.
- Use **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ou **SBECmd** para analisá-las.

### Informações de USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventário principal de dispositivos de armazenamento em massa USB (fabricante, produto, revisão, número de série/instância do dispositivo).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventário mais amplo de dispositivos USB, incluindo dispositivos que não são de armazenamento.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: em builds recentes do Windows 10/11, este é um local de alto valor para timestamps do ciclo de vida de cada dispositivo, como instalação, primeira instalação, última conexão e última remoção.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: mapeia volumes e identificadores de dispositivos para letras de unidade / GUIDs de volume. Apenas o último mapeamento de uma determinada letra de unidade pode permanecer.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: ponto de partida útil para números de série de volumes e metadados de mídias anteriores.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: histórico de interação do usuário com letras de unidade e compartilhamentos.<sup>[[2]](#references)</sup>
- Telefones e tablets modernos conectados via MTP/PTP podem **não** aparecer em `USBSTOR`. Verifique também `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` e `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Para associar um dispositivo a um usuário, use identificadores de dispositivo ou volume para chegar a artefatos por usuário, como shellbags, LNKs, Jump Lists, `RecentDocs` e `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Folha de consulta de forense do Registro do Windows 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Forense de dispositivos USB no Windows 10 e 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
