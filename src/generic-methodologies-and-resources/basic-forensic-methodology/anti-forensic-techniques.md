# Técnicas antiforenses

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Um atacante pode ter interesse em **alterar os timestamps dos arquivos** para evitar ser detectado.\
É possível encontrar os timestamps na MFT, nos atributos `$STANDARD_INFORMATION` \_\_ e \_\_ `$FILE_NAME`.

Ambos os atributos têm 4 timestamps: **modificação**, **acesso**, **criação** e **modificação do registro da MFT** (MACE ou MACB).

O **Explorador do Windows** e outras ferramentas exibem as informações de **`$STANDARD_INFORMATION`**.

### TimeStomp - Ferramenta antiforense

Essa ferramenta **modifica** as informações de timestamp em **`$STANDARD_INFORMATION`**, **mas não** as informações em **`$FILE_NAME`**. Portanto, é possível **identificar atividades suspeitas**.

### Usnjrnl

O **USN Journal** (Update Sequence Number Journal) é um recurso do NTFS (sistema de arquivos Windows NT) que mantém o controle das alterações no volume. A ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite examinar essas alterações.

![TimeStomp - Ferramenta antiforense - Usnjrnl: O USN Journal (Update Sequence Number Journal) é um recurso do NTFS (sistema de arquivos Windows NT) que mantém o controle das alterações no volume. A...](<../../images/image (801).png>)

A imagem anterior mostra a **saída** da **ferramenta**, onde é possível observar que **algumas alterações foram realizadas** no arquivo.

### $LogFile

**Todas as alterações de metadados em um sistema de arquivos são registradas** em um processo conhecido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Os metadados registrados são mantidos em um arquivo chamado `**$LogFile**`, localizado no diretório raiz de um sistema de arquivos NTFS. Ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) podem ser usadas para analisar esse arquivo e identificar alterações.

![Usnjrnl - $LogFile: Todas as alterações de metadados em um sistema de arquivos são registradas em um processo conhecido como write-ahead logging. Os metadados registrados são mantidos em um arquivo chamado $LogFile , localizado na raiz...](<../../images/image (137).png>)

Novamente, na saída da ferramenta é possível ver que **algumas alterações foram realizadas**.

Com a mesma ferramenta, é possível identificar **para que horário os timestamps foram alterados**:

![Usnjrnl - $LogFile: Com a mesma ferramenta, é possível identificar para que horário os timestamps foram alterados](<../../images/image (1089).png>)

- CTIME: horário de criação do arquivo
- ATIME: horário de modificação do arquivo
- MTIME: horário de modificação do registro da MFT do arquivo
- RTIME: horário de acesso ao arquivo

### Comparação entre `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra maneira de identificar arquivos modificados suspeitos é comparar os horários nos dois atributos e procurar **inconsistências**.

### Nanosegundos

Os timestamps do **NTFS** têm **precisão** de **100 nanosegundos**. Portanto, encontrar arquivos com timestamps como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

### SetMace - Ferramenta antiforense

Essa ferramenta pode modificar ambos os atributos, `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, desde o Windows Vista, é necessário que um SO em execução modifique essas informações.

## Ocultação de dados

O NFTS usa clusters e o tamanho mínimo de informação. Isso significa que, se um arquivo ocupar um cluster e meio, a **metade restante nunca será usada** até que o arquivo seja excluído. Portanto, é possível **ocultar dados nesse espaço residual**.

Há ferramentas como slacker que permitem ocultar dados nesse espaço "oculto". No entanto, uma análise de `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![SetMace - Ferramenta antiforense - Ocultação de dados: Há ferramentas como slacker que permitem ocultar dados nesse espaço "oculto". No entanto, uma análise de $logfile e $usnjrnl pode mostrar que...](<../../images/image (1060).png>)

Assim, é possível recuperar o espaço residual usando ferramentas como o FTK Imager. Observe que esse tipo de ferramenta pode salvar o conteúdo ofuscado ou até mesmo criptografado.

## UsbKill

Essa ferramenta **desliga o computador se detectar qualquer alteração nas portas USB**.\
Uma maneira de descobri-la é inspecionar os processos em execução e **verificar cada script Python em execução**.

## Distribuições Linux Live

Essas distros são **executadas na memória RAM**. A única maneira de detectá-las é **se o sistema de arquivos NTFS estiver montado com permissões de gravação**. Se estiver montado apenas com permissões de leitura, não será possível detectar a intrusão.

## Exclusão segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Autexclusão tardia no Windows

Uma imagem do Windows em execução pode ficar bloqueada enquanto seu processo estiver ativo. Um processo pode delegar a exclusão a um processo filho `cmd.exe`, usar `choice` como temporizador e encerrar antes que o shell execute `del`. O atraso permite que o processo original libere seu identificador de imagem; é necessário colocar o caminho completo entre aspas quando ele contém espaços.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Quando esta string é fornecida diretamente como argumento para `cmd.exe`, em vez de ser digitada em outro prompt interativo do `cmd`, use `&` em vez de `^&` e `>nul` em vez de `^>nul`. Isso remove a entrada do diretório; **não é uma eliminação segura** e não remove vestígios de execução, tarefas, diário do sistema de arquivos ou outros vestígios forenses. Procure processos filhos de `cmd.exe` de curta duração cuja linha de comando combine `choice /T`, `Del` e o caminho da imagem do processo pai.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Configuração do Windows

É possível desativar vários métodos de registro de logs do Windows para tornar a investigação forense muito mais difícil.

### Desativar timestamps - UserAssist

Esta é uma chave do Registro que mantém as datas e os horários em que cada executável foi executado pelo usuário.

Desativar o UserAssist requer duas etapas:

1. Defina duas chaves do Registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas como zero para indicar que queremos desativar o UserAssist.
2. Limpe as subárvores do Registro que se parecem com `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Desativar timestamps - Prefetch

Isso salva informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, essas informações também podem ser úteis em práticas forenses.

- Execute `regedit`
- Selecione o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Clique com o botão direito em `EnablePrefetcher` e `EnableSuperfetch`
- Selecione Modificar em cada um deles para alterar o valor de 1 (ou 3) para 0
- Reinicie

### Desativar timestamps - Last Access Time

Sempre que uma pasta é aberta em um volume NTFS em um servidor Windows NT, o sistema **atualiza um campo de timestamp em cada pasta listada**, chamado de horário do último acesso. Em um volume NTFS muito utilizado, isso pode afetar o desempenho.

1. Abra o Editor do Registro (Regedit.exe).
2. Navegue até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procure `NtfsDisableLastAccessUpdate`. Se não existir, adicione esse DWORD e defina seu valor como 1 para desativar o processo.
4. Feche o Editor do Registro e reinicie o servidor.

### Excluir histórico de USB

Todas as **entradas de dispositivos USB** são armazenadas no Registro do Windows, na chave do Registro **USBSTOR**, que contém subchaves criadas sempre que você conecta um dispositivo USB ao seu PC ou laptop. Você pode encontrar essa chave aqui: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Ao excluí-la**, você apagará o histórico de USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para ter certeza de que as excluiu (e para excluí-las).

Outro arquivo que salva informações sobre dispositivos USB é o arquivo `setupapi.dev.log`, localizado em `C:\Windows\INF`. Ele também deve ser excluído.

### Desativar cópias de sombra

**Liste** as cópias de sombra com `vssadmin list shadowstorage`\
**Exclua-as** executando `vssadmin delete shadow`

Você também pode excluí-las pela GUI seguindo as etapas propostas em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar as cópias de sombra, siga [estas etapas](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abra o programa Serviços digitando "services" na caixa de pesquisa de texto após clicar no botão Iniciar do Windows.
2. Na lista, encontre "Volume Shadow Copy", selecione-o e acesse Propriedades clicando com o botão direito.
3. Escolha Desativado no menu suspenso "Tipo de inicialização" e confirme a alteração clicando em Aplicar e OK.

Também é possível modificar no Registro a configuração dos arquivos que serão copiados na cópia de sombra: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Sobrescrever arquivos excluídos

- Você pode usar uma **ferramenta do Windows**: `cipher /w:C`. Isso instruirá o cipher a remover quaisquer dados do espaço em disco disponível e não utilizado na unidade C.
- Você também pode usar ferramentas como [**Eraser**](https://eraser.heidi.ie)

### Excluir logs de eventos do Windows

- Windows + R --> eventvwr.msc --> Expanda "Logs do Windows" --> Clique com o botão direito em cada categoria e selecione "Limpar Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Desativar logs de eventos do Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Na seção Serviços, desative o serviço "Windows Event Log"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

### Desativar $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Adulteração avançada de logs e rastreamento (2023-2025)

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

Defensores devem monitorar alterações nessas chaves do registro e a remoção em grande volume de eventos do PowerShell.

### Patch do ETW (Event Tracing for Windows)

Produtos de segurança de endpoint dependem fortemente do ETW. Um método popular de evasão em 2024 consiste em aplicar um patch em `ntdll!EtwEventWrite`/`EtwEventWriteFull` na memória para que todas as chamadas ETW retornem `STATUS_SUCCESS` sem emitir o evento:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

PoCs públicos (por exemplo, `EtwTiSwallow`) implementam a mesma primitiva em PowerShell ou C++.  
Como o patch é **local ao processo**, EDRs em execução dentro de outros processos podem não detectá-lo.<sup>[[5]](#references)</sup>
Detecção: compare o `ntdll` na memória com o arquivo em disco ou instale um hook antes do modo de usuário.

### Ressurgimento dos Fluxos de Dados Alternativos (ADS)

Campanhas de malware em 2023 (por exemplo, loaders do **FIN12**) foram observadas armazenando binários de segundo estágio em ADS para passarem despercebidos pelos scanners tradicionais:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumere os streams com `dir /R`, `Get-Item -Stream *` ou Sysinternals `streams64.exe`.
Copiar o arquivo hospedeiro para FAT/exFAT ou via SMB remove o stream oculto e pode ser usado
pelos investigadores para recuperar o payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver é usado rotineiramente para **anti-forensics** em invasões de ransomware.
A ferramenta open-source **AuKill** carrega um driver assinado, mas vulnerável (`procexp152.sys`), para
suspender ou encerrar sensores de EDR e forenses **antes da criptografia e da destruição dos logs**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

O driver é removido posteriormente, deixando o mínimo de artefatos.<sup>[[1]](#references)</sup>  
Mitigações: habilite a lista de bloqueio de drivers vulneráveis da Microsoft (HVCI/SAC) e gere alertas para a criação de serviços de kernel a partir de caminhos graváveis pelo usuário.

---

## Linux Anti-Forensics: Self-Patching e C2 na nuvem (2023–2025)

### Self-patching de serviços comprometidos para reduzir a detecção (Linux)
Os adversários cada vez mais fazem “self-patching” de um serviço logo após explorá-lo, tanto para impedir uma nova exploração quanto para suprimir detecções baseadas em vulnerabilidades. A ideia é substituir componentes vulneráveis pelos binários/JARs legítimos mais recentes do upstream, para que os scanners indiquem que o host está atualizado enquanto a persistência e o C2 permanecem ativos.<sup>[[3]](#references)</sup>

Exemplo: RCE do Apache ActiveMQ OpenWire (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Após a exploração, os atacantes baixaram JARs legítimos do Maven Central (repo1.maven.org), excluíram os JARs vulneráveis da instalação do ActiveMQ e reiniciaram o broker.
- Isso encerrou a RCE inicial, mantendo outros pontos de acesso (cron, alterações na configuração do SSH e implantes de C2 separados).

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

Dicas de perícia/hunting
- Revise os diretórios de serviços em busca de substituições não programadas de binários/JARs:
  - Debian/Ubuntu: `dpkg -V activemq` e compare os hashes/caminhos dos arquivos com os mirrors dos repositórios.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Procure versões de JARs presentes no disco que não pertençam ao gerenciador de pacotes, ou links simbólicos atualizados fora do processo normal.
- Linha do tempo: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` para correlacionar ctime/mtime com o período do comprometimento.
- Histórico do shell/telemetria de processos: evidências de `curl`/`wget` para `repo1.maven.org` ou outros CDNs de artefatos imediatamente após a exploração inicial.
- Gestão de mudanças: valide quem aplicou o “patch” e por quê, não apenas se há uma versão corrigida.

### C2 por serviços de nuvem com bearer tokens e stagers anti-análise
O tradecraft observado combinava vários caminhos de C2 de longa duração e empacotamento anti-análise:<sup>[[3]](#references)</sup>
- Loaders ELF do PyInstaller protegidos por senha para dificultar o sandboxing e a análise estática (por exemplo, PYZ criptografado, extração temporária em `/_MEI*`).
  - Indicadores: resultados de `strings` como `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefatos em tempo de execução: extração para `/tmp/_MEI*` ou caminhos personalizados de `--runtime-tmpdir`.
- C2 baseado no Dropbox usando OAuth Bearer tokens embutidos no código
  - Marcadores de rede: `api.dropboxapi.com` / `content.dropboxapi.com` com `Authorization: Bearer <token>`.
  - Procure nos dados de proxy/NetFlow/Zeek/Suricata por conexões HTTPS de saída para domínios do Dropbox originadas de workloads de servidor que normalmente não sincronizam arquivos.
- C2 paralelo/de backup por tunelamento (por exemplo, Cloudflare Tunnel `cloudflared`), mantendo o controle caso um canal seja bloqueado.
  - IOCs de host: processos/unidades `cloudflared`, configuração em `~/.cloudflared/*.json`, conexões de saída na porta 443 para os nós de borda da Cloudflare.

### Persistência e “reversão do hardening” para manter o acesso (exemplos de Linux)
Atacantes frequentemente combinam autopatching com caminhos de acesso persistente:<sup>[[3]](#references)</sup>
- Cron/Anacron: alterações no stub `0anacron` em cada diretório `/etc/cron.*/` para execução periódica.
  - Procure:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Rollback do hardening da configuração SSH: habilitando logins de root e alterando shells padrão de contas com poucos privilégios.
  - Procure por habilitação de login de root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Procure shells interativos suspeitos em contas do sistema (por exemplo, `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Artefatos beacon aleatórios, com nomes curtos (8 caracteres alfabéticos), gravados em disco e que também contatam um C2 na nuvem:
  - Investigue:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Os defensores devem correlacionar esses artefatos com a exposição externa e os eventos de aplicação de patches nos serviços para descobrir a autorremediação antiforense usada para ocultar a exploração inicial.

## References

- [1] [Sophos X-Ops – AuKill: Um driver vulnerável transformado em arma para desativar EDR (março de 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching em EtwEventWrite para furtividade: detecção e hunting (junho de 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching para persistência: como o malware Linux DripDropper se move pela nuvem](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE no Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ocultando seu .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Descobrindo uma variante do SectopRAT incorporada a software legítimo](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – comando choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – comando del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
