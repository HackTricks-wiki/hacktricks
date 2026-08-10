# Volatility - Folha de dicas

Se você precisa de uma ferramenta que automatize a análise de memória com diferentes níveis de varredura e execute vários plugins do Volatility3 em paralelo, pode usar autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
Se você quiser algo **rápido e insano** que execute vários plugins do Volatility em paralelo, pode usar: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalação

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{{#tabs}}
{{#tab name="Method1"}}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{{#endtab}}

{{#tab name="Method 2"}}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{{#endtab}}
{{#endtabs}}

## Comandos do Volatility

Acesse a documentação oficial em [referência de comandos do Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Uma observação sobre plugins “list” versus “scan”

Os plugins `list` percorrem estruturas mantidas pelo kernel, portanto são rápidos, mas podem não encontrar objetos que o malware desvinculou. Plugins `scan`, como `psscan`, pesquisam assinaturas de objetos na memória; eles podem recuperar processos encerrados ou desvinculados, mas são mais lentos e podem produzir falsos positivos quando as estruturas residuais estão danificadas.<sup>[[8]](#references)</sup>

## Perfis de SO

### Volatility3

O Volatility 3 requer tabelas de símbolos para o sistema operacional alvo. O README do projeto lista pacotes para Windows, Mac e Linux; coloque-os em `volatility3/symbols` ou em um diretório `symbols` ao lado do executável. Símbolos do Windows ausentes podem ser obtidos e gerados automaticamente, enquanto as tabelas do Mac e Linux podem precisar ser produzidas separadamente.<sup>[[9]](#references)</sup>

Pacotes de tabelas de símbolos para os vários sistemas operacionais estão disponíveis para **download** em:

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Perfil externo

Você pode obter a lista de perfis compatíveis executando:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Se você quiser usar um **novo perfil que baixou** (por exemplo, um de Linux), precisará criar em algum lugar a seguinte estrutura de pastas: _plugins/overlays/linux_ e colocar dentro dessa pasta o arquivo zip que contém o perfil. Em seguida, obtenha o número dos perfis usando:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Você pode **baixar profiles do Linux e do Mac** em [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

No trecho anterior, você pode ver que o profile se chama `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, e pode usá-lo para executar algo como:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Descobrir Perfil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Diferenças entre imageinfo e kdbgscan**

As [notas de identificação de imagens de Andrea Fortuna](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/) explicam que `imageinfo` produz sugestões de perfil, enquanto `kdbgscan` procura assinaturas KDBG e aplica verificações de consistência para identificar perfis candidatos e endereços KDBG. Sua saída depende, em parte, de o Volatility conseguir localizar um DTB; portanto, passe um perfil conhecido ou sugerido ao executá-lo.<sup>[[1]](#references)</sup>

Quando vários candidatos forem retornados, compare suas contagens de processos e módulos: um candidato com zero processos ou módulos é menos confiável do que um com listas preenchidas. Considere isso uma verificação de consistência, não uma prova de que o perfil está correto.<sup>[[1]](#references)</sup>
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

`KdDebuggerDataBlock`, conhecido pelo Volatility como KDBG, é uma estrutura `_KDDEBUGGER_DATA64` que inclui `PsActiveProcessHead`, o início da lista de processos usada para a enumeração de processos.<sup>[[2]](#references)</sup>

## Informações do SO
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
O plugin `banners.Banners` pode ser usado no **vol3 para tentar encontrar linux banners** no dump.

## Hashes/Senhas

Extraia hashes SAM, [credenciais armazenadas em cache do domínio](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) e [segredos lsa](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{{#endtab}}
{{#endtabs}}

## Dump de Memória

O dump de memória de um processo **extrairá tudo** do estado atual do processo. O módulo **procdump** apenas **extrairá** o **código**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## Processos

### Listar processos

Tente encontrar processos **suspeitos** (por nome) ou **processos** filhos **inesperados** (por exemplo, um cmd.exe como filho de iexplorer.exe).\
Pode ser interessante **comparar** o resultado de pslist com o de psscan para identificar processos ocultos.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{{#endtab}}
{{#endtabs}}

### Despejar proc

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

### Linha de comando

Algo suspeito foi executado?

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{{#endtab}}
{{#endtabs}}

Os comandos executados em `cmd.exe` são gerenciados pelo **`conhost.exe`** (ou **`csrss.exe`** em sistemas anteriores ao Windows 7). Isso significa que, se **`cmd.exe`** for encerrado por um atacante antes que um memory dump seja obtido, ainda será possível recuperar o histórico de comandos da sessão a partir da memória do **`conhost.exe`**. Para isso, se for detectada atividade incomum nos módulos do console, a memória do processo **`conhost.exe`** associado deverá ser extraída. Em seguida, pesquisando por **strings** nesse dump, as linhas de comando usadas na sessão poderão ser potencialmente extraídas.

### Ambiente

Obtenha as variáveis de ambiente de cada processo em execução. Pode haver alguns valores interessantes.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{{#endtab}}
{{#endtabs}}

### Privilégios de token

Verifique se há tokens de privilégios em serviços inesperados.\
Pode ser interessante listar os processos que usam algum token privilegiado.

{{#tabs}}
{{#tab name="vol3"}}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}
{{#endtabs}}

### SIDs

Verifique cada SSID pertencente a um processo.\
Pode ser interessante listar os processos que usam um SID de privilégios (e os processos que usam algum SID de serviço).

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{{#endtab}}
{{#endtabs}}

### Handles

É útil saber para quais outros arquivos, chaves, threads, processos... um **processo possui um handle** (abriu)

{{#tabs}}
{{#tab name="vol3"}}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{{#endtab}}
{{#endtabs}}

### DLLs

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{{#endtab}}
{{#endtabs}}

### Strings por processo

O Volatility permite verificar a qual processo uma string pertence.

{{#tabs}}
{{#tab name="vol3"}}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{{#endtab}}
{{#endtabs}}

Também permite pesquisar strings dentro de um processo usando o módulo yarascan:

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{{#endtab}}
{{#endtabs}}

### UserAssist

Os valores do registro `UserAssist` registram programas iniciados pelo Windows Explorer, incluindo contagens de execução e timestamps da última execução; os lançamentos pela linha de comando não são registrados nessas chaves.<sup>[[3]](#references)</sup>

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{{#endtab}}
{{#endtabs}}

## Serviços

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Rede

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{{#endtab}}
{{#endtabs}}

## Hive do Registro

### Exibir hives disponíveis

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{{#endtab}}
{{#endtabs}}

### Obter um valor

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{{#endtab}}
{{#endtabs}}

### Dump
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Sistema de arquivos

### Montagem

{{#tabs}}
{{#tab name="vol3"}}
```bash
#See vol2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{{#endtab}}
{{#endtabs}}

### Scan/dump

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{{#endtab}}
{{#endtabs}}

### Tabela Mestra de Arquivos

{{#tabs}}
{{#tab name="vol3"}}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{{#endtab}}
{{#endtabs}}

No NTFS, o MFT tem pelo menos uma entrada por arquivo no volume, incluindo a si próprio. Os metadados e o conteúdo dos arquivos são armazenados nas entradas do MFT ou em locais descritos por essas entradas; consulte a [documentação da Microsoft](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table).<sup>[[4]](#references)</sup>

### SSL Keys/Certs

{{#tabs}}
{{#tab name="vol3"}}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Malware

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{{#endtab}}
{{#endtabs}}

### Varredura com yara

Use este script para baixar e mesclar todas as regras de malware do yara do github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Crie o diretório _**rules**_ e execute-o. Isso criará um arquivo chamado _**malware_rules.yar**_ que contém todas as regras de malware do yara.

{{#tabs}}
{{#tab name="vol3"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{{#endtab}}
{{#endtabs}}

## DIVERSOS

### Plugins externos

Se quiser usar plugins externos, certifique-se de que as pastas relacionadas aos plugins sejam o primeiro parâmetro utilizado.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{{#endtab}}
{{#endtabs}}

#### Autoruns

Baixe-o em [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns).
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{{#endtab}}
{{#endtabs}}

### Links simbólicos

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{{#endtab}}
{{#endtabs}}

### Bash

É possível **ler da memória o histórico do bash.** Você também poderia extrair o arquivo _.bash_history_, mas, se ele estivesse desativado, ficaria feliz por poder usar este módulo do volatility.

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp linux.bash.Bash
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{{#endtab}}
{{#endtabs}}

### Linha do tempo

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{{#endtab}}
{{#endtabs}}

### Drivers

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{{#endtab}}
{{#endtabs}}

### Obter área de transferência
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Obter histórico do IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Obter texto do Notepad
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
Envie o conteúdo do arquivo ou a imagem da screenshot para que eu possa traduzi-lo.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Registro Mestre de Inicialização (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Em sistemas baseados em BIOS, o MBR no setor 0 contém o código de inicialização principal e a tabela de partições. A Microsoft documenta que `bootsect /mbr` atualiza o código sem alterar essa tabela.<sup>[[7]](#references)</sup>

## References

- [1] [Volatility, minha própria cheatsheet (Parte 1): Identificação da imagem](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Encontrando o Kernel Debugger Block](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Chaves UserAssist do Windows](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (sistemas de arquivos locais) - aplicativos Win32](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [PC baseado em UEFI, MBR protetivo: o que é? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial: plugins do Volatility para análise de malware](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)
- [7] [Opções de linha de comando do Bootsect](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bootsect-command-line-options?view=windows-11)
- [8] [Tutorial - plugins do Volatility e análise de malware](https://tomchop.me/posts/volatility-plugin-malware-analysis/)
- [9] [README do Volatility 3](https://github.com/volatilityfoundation/volatility3/blob/develop/README.md)
{{#include ../../../banners/hacktricks-training.md}}
