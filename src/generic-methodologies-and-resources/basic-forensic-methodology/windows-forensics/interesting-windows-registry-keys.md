# Chaves Interessantes do Windows Registry

{{#include ../../../banners/hacktricks-training.md}}

Os hives do Windows Registry são uma das maneiras mais rápidas de passar de _o que aconteceu?_ para _qual usuário, quando e de onde?_. Para análise ao vivo, prefira `CurrentControlSet`; para análise offline de hive, primeiro resolva qual `ControlSet00x` estava ativo em vez de hardcode `ControlSet001`.

### Versão do Windows e Informações do Proprietário

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edição/build do Windows, tempo de instalação, proprietário registrado, nome do produto e outros metadados de build.
- `SYSTEM\Select`: mapeia `Current`, `Default` e `LastKnownGood` para os valores reais `ControlSet00x` usados pelo sistema.

### Nome do Computador

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname atual.

### Configuração de Fuso Horário

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuso horário configurado e valores relacionados a DST.

### Rastreamento de Tempo de Acesso

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indica se os timestamps de último acesso do NTFS estão sendo atualizados.
- Para habilitar, use: `fsutil behavior set disablelastaccess 0`

### Detalhes de Desligamento

- `SYSTEM\CurrentControlSet\Control\Windows`: último horário de desligamento.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: sistemas mais antigos também podem expor contadores de desligamento.

### Configuração de Rede

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs da interface, leases DHCP, gateway e dados de DNS.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nome do perfil de rede/SSID mais horários do primeiro e último conexão.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` e `...\Unmanaged\{GUID}`: dados de correlação do perfil, como endereço MAC do gateway e sufixo DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: pastas compartilhadas locais publicadas pelo host.

### Acesso Remoto e Histórico de Compartilhamentos de Rede

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: lista MRU de RDP de saída (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: histórico de RDP de saída por host. Subkeys geralmente armazenam `UsernameHint`, e o tempo `LastWrite` da key é um pivô útil.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: unidades de rede mapeadas, compartilhamentos UNC e pontos de montagem de mídia removível vinculados a um usuário específico.

### Programas que Iniciam Automaticamente e Persistência Agendada

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` e `...\Tasks\{GUID}`: metadados de tarefas agendadas. Se uma task existir aqui, mas o valor `SD` estiver ausente de `Tree\<TaskName>`, suspeite de manipulação oculta de task no estilo Tarrask e correlacione com `C:\Windows\System32\Tasks\<TaskName>`.

### Buscas, Paths Digitados e MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termos de busca do File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths do Explorer digitados manualmente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: os últimos 26 comandos de `Win + R`. `MRUList` preserva a ordem.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documentos e pastas abertos recentemente.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: arquivos recentes do Office.

### Rastreamento de Atividade do Usuário

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: histórico de execução guiada pela interface. Os nomes dos valores são codificados em ROT13, e os dados binários incluem contadores de execução e o último horário de execução.
- Trate `UserAssist` como evidência de suporte forte, não como veredito isolado: ele rastreia principalmente apps ou arquivos `.lnk` iniciados via Explorer e pode perder execução por linha de comando ou serviço. No Windows 10+, algumas entradas não significam necessariamente que o processo foi executado بالكامل.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` e `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: rastros modernos de execução no Windows 10/11 com atribuição de SID e horário da última execução. São especialmente úteis para binários executados localmente, mas entradas antigas podem expirar rapidamente e execuções a partir de compartilhamentos de rede/mídia removível são menos confiáveis.
- Para artefatos de execução mais amplos, como Prefetch, Amcache, ShimCache e SRUM, veja o principal [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags são armazenados tanto em `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` quanto em `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Entradas de `NTUSER.DAT` são especialmente úteis para navegação UNC/rede, enquanto `UsrClass.dat` é onde o Windows Vista+ normalmente armazena shellbags de pastas locais/removíveis.
- Elas podem mostrar existência de pastas, navegação e preferências de visualização de pastas mesmo depois que a pasta foi deletada. O acesso no estilo Explorer a arquivos de arquivo compactado também pode deixar rastros de shellbag.
- Nem toda shellbag prova acesso bem-sucedido à pasta, então corrobore com LNKs, Jump Lists, timestamps ou mapeamentos de volume.
- Use **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ou **SBECmd** para analisá-las.

### Informações de USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventário principal de dispositivos USB de armazenamento em massa (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventário mais amplo de dispositivos USB, incluindo dispositivos sem armazenamento.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: em builds recentes do Windows 10/11, este é um ponto de alto valor para timestamps do ciclo de vida por dispositivo, como install, first install, last arrival e last removal.
- `HKLM\SYSTEM\MountedDevices`: mapeia volumes e identificadores de dispositivo para letras de unidade / volume GUIDs. Apenas o último mapeamento de uma determinada letra de unidade pode sobreviver.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivô útil para números de série de volume e metadados anteriores da mídia.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: histórico específico do usuário de interação com letras de unidade e compartilhamentos.
- Celulares e tablets modernos conectados via MTP/PTP podem **não** aparecer em `USBSTOR`. Verifique também `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` e `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Para vincular um dispositivo a um usuário, faça pivô de identificadores de dispositivo ou volume para artefatos por usuário, como shellbags, LNKs, Jump Lists, `RecentDocs` e `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
