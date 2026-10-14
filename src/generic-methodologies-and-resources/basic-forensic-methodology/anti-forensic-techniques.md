# Técnicas anti-forenses

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Um atacante pode querer **alterar os timestamps dos arquivos** para evitar ser detectado.\
É possível encontrar os timestamps na MFT, nos atributos `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Ambos os atributos têm 4 timestamps: **modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

O **Windows Explorer** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

### TimeStomp - Ferramenta anti-forense

Essa ferramenta **modifica** as informações de timestamp em **`$STANDARD_INFORMATION`**, **mas** **não** as informações em **`$FILE_NAME`**. Portanto, é possível **identificar atividades suspeitas**.

### Usnjrnl

O **USN Journal** (Update Sequence Number Journal) é um recurso do NTFS (sistema de arquivos Windows NT) que mantém o registro das alterações no volume. A ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar essas alterações.

![TimeStomp - Ferramenta anti-forense - Usnjrnl: O USN Journal (Update Sequence Number Journal) é um recurso do NTFS (sistema de arquivos Windows NT) que mantém o registro das alterações no volume. A...](<../../images/image (801).png>)

A imagem anterior mostra a **saída** da **ferramenta**, onde é possível observar que **algumas alterações foram feitas** no arquivo.

### $LogFile

**Todas as alterações de metadados em um sistema de arquivos são registradas** em um processo conhecido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Os metadados registrados são mantidos em um arquivo chamado `**$LogFile**`, localizado no diretório raiz de um sistema de arquivos NTFS. Ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) podem ser usadas para analisar esse arquivo e identificar alterações.

![Usnjrnl - $LogFile: Todas as alterações de metadados em um sistema de arquivos são registradas em um processo conhecido como write-ahead logging. Os metadados registrados são mantidos em um arquivo chamado $LogFile , localizado no diretório raiz...](<../../images/image (137).png>)

Novamente, na saída da ferramenta é possível ver que **algumas alterações foram feitas**.

Usando a mesma ferramenta, é possível identificar **quando os timestamps foram modificados**:

![Usnjrnl - $LogFile: Usando a mesma ferramenta, é possível identificar quando os timestamps foram modificados](<../../images/image (1089).png>)

- CTIME: horário de criação do arquivo
- ATIME: horário de modificação do arquivo
- MTIME: modificação do registro MFT do arquivo
- RTIME: horário de acesso ao arquivo

### Comparação entre `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra maneira de identificar arquivos modificados suspeitos é comparar os horários nos dois atributos e procurar por **inconsistências**.

### Nanossegundos

Os timestamps **NTFS** têm **precisão** de **100 nanossegundos**. Portanto, encontrar arquivos com timestamps como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

### SetMace - Ferramenta anti-forense

Essa ferramenta pode modificar os dois atributos, `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário que o sistema operacional esteja em execução para modificar essas informações.

## Ocultação de dados

O NFTS usa clusters e o tamanho mínimo das informações. Isso significa que, se um arquivo ocupar um cluster e meio, **a metade restante nunca será usada** até que o arquivo seja excluído. Assim, é possível **ocultar dados nesse slack space**.

Há ferramentas como o slacker que permitem ocultar dados nesse espaço "oculto". No entanto, uma análise de `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![SetMace - Ferramenta anti-forense - Ocultação de dados: Há ferramentas como o slacker que permitem ocultar dados nesse espaço "oculto". No entanto, uma análise de $logfile e $usnjrnl pode mostrar que...](<../../images/image (1060).png>)

Assim, é possível recuperar o slack space usando ferramentas como o FTK Imager. Observe que esse tipo de ferramenta pode salvar o conteúdo ofuscado ou até mesmo criptografado.

## UsbKill

Essa ferramenta **desliga o computador se detectar qualquer alteração nas portas USB**.\
Uma maneira de descobri-la é inspecionar os processos em execução e **verificar cada script Python em execução**.

## Distribuições Linux Live

Essas distribuições são **executadas na memória RAM**. Só é possível detectá-las **se o sistema de arquivos NTFS estiver montado com permissões de escrita**. Se estiver montado apenas com permissões de leitura, não será possível detectar a intrusão.

## Exclusão segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Autodeleção tardia no Windows

Uma imagem do Windows em execução pode ficar bloqueada enquanto seu processo estiver ativo. Um processo pode delegar a exclusão a um `cmd.exe` filho, usar `choice` como temporizador e encerrar antes que o shell execute `del`. O atraso permite que o processo original libere seu identificador de imagem; é necessário colocar o caminho completo entre aspas se ele contiver espaços.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Quando esta string for fornecida diretamente como argumento para `cmd.exe`, em vez de ser digitada em outro prompt interativo do `cmd`, use `&` em vez de `^&` e `>nul` em vez de `^>nul`. Isso remove a entrada do diretório; **não é uma eliminação segura** e não remove rastros de execução, tarefas, diário do sistema de arquivos ou outros vestígios forenses. Procure processos `cmd.exe` filhos de curta duração cuja linha de comando combine `choice /T`, `Del` e o caminho da imagem do processo pai.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Configuração do Windows

É possível desativar vários métodos de registro do Windows para dificultar muito a investigação forense.

### Desativar registros de data e hora - UserAssist

Esta chave do registro mantém as datas e horas em que cada executável foi executado pelo usuário.

Desativar o UserAssist requer duas etapas:

1. Defina duas chaves do registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, como zero para indicar que queremos desativar o UserAssist.
2. Limpe as subárvores do registro que correspondam a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Desativar registros de data e hora - Prefetch

Isso salva informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, essas informações também podem ser úteis em práticas forenses.

- Execute `regedit`
- Selecione o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Clique com o botão direito em `EnablePrefetcher` e `EnableSuperfetch`
- Selecione Modificar em cada um deles para alterar o valor de 1 (ou 3) para 0
- Reinicie

### Desativar registros de data e hora - Último horário de acesso

Sempre que uma pasta é aberta em um volume NTFS de um servidor Windows NT, o sistema atualiza um campo de registro de data e hora em cada pasta listada, chamado de último horário de acesso. Em um volume NTFS muito usado, isso pode afetar o desempenho.

1. Abra o Editor do Registro (Regedit.exe).
2. Navegue até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procure `NtfsDisableLastAccessUpdate`. Se não existir, adicione este DWORD e defina seu valor como 1 para desativar o processo.
4. Feche o Editor do Registro e reinicie o servidor.

### Excluir histórico de USB

Todas as **entradas de dispositivos USB** são armazenadas no Registro do Windows, na chave de registro **USBSTOR**, que contém subchaves criadas sempre que você conecta um dispositivo USB ao seu PC ou laptop. Você pode encontrar essa chave em H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Ao excluí-la**, você excluirá o histórico de USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para garantir que elas foram excluídas (e para excluí-las).

Outro arquivo que salva informações sobre os dispositivos USB é o arquivo `setupapi.dev.log`, dentro de `C:\Windows\INF`. Ele também deve ser excluído.

### Desativar cópias de sombra

**Liste** as cópias de sombra com `vssadmin list shadowstorage`\
**Exclua-as** executando `vssadmin delete shadow`

Você também pode excluí-las pela GUI, seguindo as etapas propostas em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar cópias de sombra [siga as etapas daqui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abra o programa Serviços digitando "services" na caixa de pesquisa de texto após clicar no botão Iniciar do Windows.
2. Na lista, encontre "Volume Shadow Copy", selecione-o e acesse Propriedades clicando com o botão direito.
3. Escolha Desativado no menu suspenso "Tipo de inicialização" e confirme a alteração clicando em Aplicar e OK.

Também é possível modificar no registro a configuração dos arquivos que serão copiados na cópia de sombra: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescrever arquivos excluídos

- Você pode usar uma **ferramenta do Windows**: `cipher /w:C` Isso fará com que o cipher remova todos os dados do espaço em disco disponível e não utilizado na unidade C.
- Você também pode usar ferramentas como o [**Eraser**](https://eraser.heidi.ie)

### Excluir logs de eventos do Windows

- Windows + R --> eventvwr.msc --> Expanda "Logs do Windows" --> Clique com o botão direito em cada categoria e selecione "Limpar Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Desativar logs de eventos do Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Na seção de serviços, desative o serviço "Windows Event Log"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Desativar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Adulteração avançada de logs e rastros (2023-2025)

### Registro de ScriptBlock/Module do PowerShell

Versões recentes do Windows 10/11 e do Windows Server mantêm **artefatos forenses detalhados do PowerShell** em
`Microsoft-Windows-PowerShell/Operational` (eventos 4104/4105/4106).  
Atacantes podem desativá-los ou apagá-los em tempo real:

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

Os defensores devem monitorar alterações nessas chaves do Registro e a remoção em grande volume de eventos do PowerShell.

### Patch do ETW (Event Tracing for Windows)

Os produtos de segurança de endpoint dependem bastante do ETW. Um método popular de evasão em 2024 consiste em aplicar um patch em `ntdll!EtwEventWrite`/`EtwEventWriteFull` na memória, fazendo com que toda chamada ETW retorne `STATUS_SUCCESS` sem emitir o evento:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

PoCs públicos (por exemplo, `EtwTiSwallow`) implementam a mesma primitiva em PowerShell ou C++.  
Como o patch é **local ao processo**, EDRs em execução dentro de outros processos podem não detectá-lo.<sup>[[5]](#references)</sup>  
Detecção: compare o `ntdll` na memória com o arquivo no disco ou instale um hook antes do user mode.

### Ressurgimento de Alternate Data Streams (ADS)

Campanhas de malware em 2023 (por exemplo, loaders do **FIN12**) foram observadas armazenando binários de segundo estágio dentro de ADS para escapar dos scanners tradicionais:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumere os streams com `dir /R`, `Get-Item -Stream *` ou Sysinternals `streams64.exe`.
Copiar o arquivo host para FAT/exFAT ou via SMB remove o stream oculto e pode ser usado
por investigadores para recuperar o payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver é agora usado rotineiramente para **anti-forensics** em invasões de ransomware.  
A ferramenta open-source **AuKill** carrega um driver assinado, mas vulnerável (`procexp152.sys`), para
suspender ou encerrar sensores de EDR e forenses **antes da criptografia e da destruição de logs**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

O driver é removido em seguida, deixando artefatos mínimos.<sup>[[1]](#references)</sup>  
Mitigações: habilite a lista de bloqueio de drivers vulneráveis da Microsoft (HVCI/SAC)
e alerte sobre a criação de serviços de kernel a partir de caminhos graváveis pelo usuário.

---

## Linux Anti-Forensics: Self-Patching e C2 na nuvem (2023–2025)

### Self-patching de serviços comprometidos para reduzir a detecção (Linux)
Adversários cada vez mais fazem “self-patch” em um serviço logo após explorá-lo, tanto para impedir uma nova exploração quanto para suprimir detecções baseadas em vulnerabilidades. A ideia é substituir componentes vulneráveis pelos binários/JARs legítimos mais recentes do upstream, para que os scanners informem que o host está corrigido enquanto a persistência e o C2 permanecem ativos.<sup>[[3]](#references)</sup>

Exemplo: RCE do Apache ActiveMQ OpenWire (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Após a exploração, os atacantes buscaram JARs legítimos no Maven Central (repo1.maven.org), excluíram os JARs vulneráveis da instalação do ActiveMQ e reiniciaram o broker.
- Isso encerrou a RCE inicial, mantendo outros pontos de acesso (cron, alterações na configuração do SSH, implantes de C2 separados).

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

Dicas de forense/caça
- Revise os diretórios de serviços em busca de substituições não programadas de binários/JARs:
  - Debian/Ubuntu: `dpkg -V activemq` e compare hashes/caminhos dos arquivos com os mirrors do repositório.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Procure versões de JARs presentes no disco que não sejam gerenciadas pelo gerenciador de pacotes, ou links simbólicos atualizados fora de banda.
- Linha do tempo: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime com a janela de comprometimento.
- Histórico do shell/telemetria de processos: evidências de `curl`/`wget` para `repo1.maven.org` ou outros CDNs de artefatos logo após a exploração inicial.
- Gestão de mudanças: valide quem aplicou o “patch” e por quê, não apenas se há uma versão corrigida instalada.

### C2 em serviços de nuvem com bearer tokens e stagers anti-análise
O tradecraft observado combinava vários caminhos de C2 de longa duração e empacotamento anti-análise:<sup>[[3]](#references)</sup>
- Loaders ELF do PyInstaller protegidos por senha para dificultar o sandboxing e a análise estática (por exemplo, PYZ criptografado, extração temporária em `/_MEI*`).
  - Indicadores: resultados de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefatos de execução: extração para `/tmp/_MEI*` ou caminhos personalizados de `--runtime-tmpdir`.
- C2 com suporte do Dropbox usando tokens OAuth Bearer embutidos no código
  - Indicadores de rede: `api.dropboxapi.com` / `content.dropboxapi.com` com `Authorization: Bearer <token>`.
  - Procure em proxy/NetFlow/Zeek/Suricata por tráfego HTTPS de saída para domínios do Dropbox originado em cargas de trabalho de servidores que normalmente não sincronizam arquivos.
- C2 paralelo/de backup via tunelamento (por exemplo, Cloudflare Tunnel `cloudflared`), mantendo o controle caso um canal seja bloqueado.
  - IOCs de host: processos/unidades `cloudflared`, configuração em `~/.cloudflared/*.json`, conexões de saída na porta 443 para edges da Cloudflare.

### Persistência e “reversão do hardening” para manter o acesso (exemplos de Linux)
Os atacantes frequentemente combinam autorreparação de patches com caminhos de acesso persistentes:<sup>[[3]](#references)</sup>
- Cron/Anacron: alterações no stub `0anacron` em cada diretório `/etc/cron.*/` para execução periódica.
  - Busca:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Reversão do hardening da configuração do SSH: habilitar logins de root e alterar os shells padrão de contas com poucos privilégios.
  - Procure por habilitação de login de root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Procure shells interativos suspeitos em contas do sistema (por exemplo, `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Artefatos beacon aleatórios com nomes curtos (8 caracteres alfabéticos) gravados em disco que também se comunicam com C2 na nuvem:
  - Procure:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Os defensores devem correlacionar esses artefatos com a exposição externa e os eventos de aplicação de patches nos serviços para descobrir a autorremediação anti-forense usada para ocultar a exploração inicial.

## Execução de shell incorporado estático

Um script wrapper com um interpretador incorporado e implementações de comandos pode executar operações de shell compatíveis dentro de um único executável, em vez de iniciar `/bin/sh` e processos separados para cada utilitário. HimitsuShell cria esse tipo de binário estático com musl. Ao contrário dos [wrappers SHc](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), seus comandos integrados não precisam iniciar o shell do host nem um processo separado para cada utilitário. Comandos não compatíveis podem recorrer ao shell do sistema.<sup>[[9]](#references)</sup>

Isso reduz a visibilidade dos processos de shell e dos processos filhos `execve`.<sup>[[9]](#references)</sup> O processo wrapper e suas chamadas de sistema continuam observáveis por meio de tracepoints do kernel; portanto, a alegação do projeto de que é invisível até mesmo ao rastreamento do kernel não deve ser interpretada literalmente.<sup>[[9]](#references)[[11]](#references)</sup>

Para a compilação x86_64 documentada, mantenha o nome de entrada `launcher.sh` e copie-o para o contêiner antes de compilar. O resultado é `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

O `compile.sh` público criptografa o script com AES-256-CTR, criptografa o valor de expiração e as chaves/IVs intermediárias com AES-256-CBC, converte os arquivos criptografados em arrays C usando `xxd -i` e os vincula a `lib.bc` com `-static -s`. A chave e o IV finais também são incorporados, portanto isso oferece resistência à extração estática casual, mas não é um segredo impossível de recuperar.<sup>[[10]](#references)</sup>

Os passes padrão do LLVM são `-sobf` e `-sub`. Edite `/var/work/compile.sh` antes de compilar para habilitar alternativas documentadas, como flattening de fluxo de controle (`fla`) ou fluxo de controle falso (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Teste a compatibilidade dos scripts antes de confiar neste wrapper: o projeto tem como alvo a sintaxe de shell POSIX, avisa que scripts Bash/Zsh podem falhar e informa que comandos fora do conjunto integrado invocam o shell do sistema.<sup>[[9]](#references)</sup>

Para analisar o fluxo de controle achatado, consulte [bypassing flattened control flow with a narrow execution slice](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: Um driver vulnerável armado para desativar EDR (março de 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite para furtividade: detecção e hunting (junho de 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching para persistência: como o malware Linux DripDropper se move pela cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE no Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ocultando seu .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Revelando uma variante do SectopRAT incorporada em software legítimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – comando choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – comando del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [README do HimitsuShell](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Script de build do HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Histogramas de eventos do kernel Linux e rastreamento de chamadas de sistema](https://docs.kernel.org/trace/histogram.html)
