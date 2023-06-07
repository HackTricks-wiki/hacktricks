# Chaves de Registro do Windows Interessantes

## Chaves de Registro do Sistema Windows

### Versão

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Versão do Windows, Service Pack, hora da instalação e proprietário registrado.

### Nome do Host

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: Nome do host.

### Fuso horário

* **`System\ControlSet001\Control\TimeZoneInformation`**: Fuso horário.

### Último horário de acesso

* **`System\ControlSet001\Control\Filesystem`**: Último horário de acesso (por padrão, está desativado com `NtfsDisableLastAccessUpdate=1`, se `0`, então está ativado).
  * Para ativá-lo: `fsutil behavior set disablelastaccess 0`

### Horário de desligamento

* `System\ControlSet001\Control\Windows`: Horário de desligamento.
* `System\ControlSet001\Control\Watchdog\Display`: Contagem de desligamentos (apenas XP).

### Informações de Rede

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: Interfaces de rede.
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: Primeira e última vez que uma conexão de rede foi realizada e conexões através de VPN.
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (para XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: Tipo de rede (0x47-wireless, 0x06-cable, 0x17-3G) e categoria (0-Pública, 1-Privada/Doméstica, 2-Domínio/Trabalho) e últimas conexões.

### Pastas Compartilhadas

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: Pastas compartilhadas e suas configurações. Se o **Cache do Lado do Cliente** (CSCFLAGS) estiver habilitado, uma cópia dos arquivos compartilhados será salva nos clientes e no servidor em `C:\Windows\CSC`.
  * CSCFlag=0 -> Por padrão, o usuário precisa indicar os arquivos que deseja armazenar em cache.
  * CSCFlag=16 -> Armazenamento automático de documentos. "Todos os arquivos e programas que os usuários abrem da pasta compartilhada estão automaticamente disponíveis offline" com a opção "otimizar para desempenho" desmarcada.
  * CSCFlag=32 -> Como as opções anteriores, mas com a opção "otimizar para desempenho" marcada.
  * CSCFlag=48 -> Cache desativado.
  * CSCFlag=2048: Esta configuração está disponível apenas no Win 7 e 8 e é a configuração padrão até você desativar o "Compartilhamento Simples de Arquivos" ou usar a opção de compartilhamento "avançada". Também parece ser a configuração padrão para o "Grupo Doméstico".
  * CSCFlag=768 -> Esta configuração foi vista apenas em dispositivos de impressão compartilhados.

### Programas de Inicialização Automática

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Pes
