{{#include ../../banners/hacktricks-training.md}}

# Timestamps

Um atacante pode estar interessado em **alterar os timestamps dos arquivos** para evitar ser detectado.\
É possível encontrar os timestamps dentro do MFT nos atributos `$STANDARD_INFORMATION` ** e ** `$FILE_NAME`.

Ambos os atributos têm 4 timestamps: **Modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

**Windows explorer** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

## TimeStomp - Ferramenta Anti-forense

Esta ferramenta **modifica** as informações de timestamp dentro de **`$STANDARD_INFORMATION`** **mas** **não** as informações dentro de **`$FILE_NAME`**. Portanto, é possível **identificar** **atividade** **suspeita**.

## Usnjrnl

O **USN Journal** (Update Sequence Number Journal) é um recurso do NTFS (sistema de arquivos Windows NT) que rastreia as alterações do volume. A ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permite a análise dessas alterações.

![](<../../images/image (449).png>)

A imagem anterior é a **saída** mostrada pela **ferramenta**, onde pode-se observar que algumas **alterações foram realizadas** no arquivo.

## $LogFile

**Todas as alterações de metadados em um sistema de arquivos são registradas** em um processo conhecido como [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Os metadados registrados são mantidos em um arquivo chamado `**$LogFile**`, localizado no diretório raiz de um sistema de arquivos NTFS. Ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) podem ser usadas para analisar este arquivo e identificar alterações.

![](<../../images/image (450).png>)

Novamente, na saída da ferramenta é possível ver que **algumas alterações foram realizadas**.

Usando a mesma ferramenta, é possível identificar **a que hora os timestamps foram modificados**:

![](<../../images/image (451).png>)

- CTIME: Hora de criação do arquivo
- ATIME: Hora de modificação do arquivo
- MTIME: Modificação do registro MFT do arquivo
- RTIME: Hora de acesso do arquivo

## Comparação entre `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra maneira de identificar arquivos modificados suspeitos seria comparar o tempo em ambos os atributos em busca de **incompatibilidades**.

## Nanosegundos

Os timestamps do **NTFS** têm uma **precisão** de **100 nanosegundos**. Portanto, encontrar arquivos com timestamps como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

## SetMace - Ferramenta Anti-forense

Esta ferramenta pode modificar ambos os atributos `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário que um sistema operacional ao vivo modifique essas informações.

# Data Hiding

O NFTS usa um cluster e o tamanho mínimo da informação. Isso significa que se um arquivo ocupa um e meio cluster, a **metade restante nunca será usada** até que o arquivo seja excluído. Portanto, é possível **ocultar dados neste espaço livre**.

Existem ferramentas como slacker que permitem ocultar dados neste espaço "oculto". No entanto, uma análise do `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![](<../../images/image (452).png>)

Então, é possível recuperar o espaço livre usando ferramentas como FTK Imager. Note que esse tipo de ferramenta pode salvar o conteúdo ofuscado ou até mesmo criptografado.

# UsbKill

Esta é uma ferramenta que **desligará o computador se qualquer alteração nas portas USB** for detectada.\
Uma maneira de descobrir isso seria inspecionar os processos em execução e **revisar cada script python em execução**.

# Live Linux Distributions

Essas distros são **executadas dentro da memória RAM**. A única maneira de detectá-las é **caso o sistema de arquivos NTFS esteja montado com permissões de gravação**. Se estiver montado apenas com permissões de leitura, não será possível detectar a intrusão.

# Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows Configuration

É possível desativar vários métodos de registro do Windows para dificultar muito a investigação forense.

## Desativar Timestamps - UserAssist

Esta é uma chave de registro que mantém datas e horas quando cada executável foi executado pelo usuário.

Desativar o UserAssist requer duas etapas:

1. Defina duas chaves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas para zero a fim de sinalizar que queremos desativar o UserAssist.
2. Limpe suas subárvores de registro que se parecem com `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Desativar Timestamps - Prefetch

Isso salvará informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, isso também pode ser útil para práticas forenses.

- Execute `regedit`
- Selecione o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Clique com o botão direito em `EnablePrefetcher` e `EnableSuperfetch`
- Selecione Modificar em cada um deles para alterar o valor de 1 (ou 3) para 0
- Reinicie

## Desativar Timestamps - Last Access Time

Sempre que uma pasta é aberta a partir de um volume NTFS em um servidor Windows NT, o sistema leva o tempo para **atualizar um campo de timestamp em cada pasta listada**, chamado de hora de último acesso. Em um volume NTFS muito utilizado, isso pode afetar o desempenho.

1. Abra o Editor do Registro (Regedit.exe).
2. Navegue até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procure por `NtfsDisableLastAccessUpdate`. Se não existir, adicione este DWORD e defina seu valor como 1, o que desativará o processo.
4. Feche o Editor do Registro e reinicie o servidor.

## Deletar Histórico USB

Todas as **Entradas de Dispositivos USB** são armazenadas no Registro do Windows sob a chave de registro **USBSTOR** que contém subchaves que são criadas sempre que você conecta um dispositivo USB ao seu PC ou Laptop. Você pode encontrar esta chave aqui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Deletando isso**, você excluirá o histórico USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para ter certeza de que as deletou (e para deletá-las).

Outro arquivo que salva informações sobre os USBs é o arquivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Este também deve ser deletado.

## Desativar Cópias de Sombra

**Liste** as cópias de sombra com `vssadmin list shadowstorage`\
**Deletar** executando `vssadmin delete shadow`

Você também pode deletá-las via GUI seguindo os passos propostos em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar cópias de sombra [passos daqui](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Abra o programa Serviços digitando "services" na caixa de pesquisa de texto após clicar no botão iniciar do Windows.
2. Na lista, encontre "Volume Shadow Copy", selecione-o e acesse Propriedades clicando com o botão direito.
3. Escolha Desativado no menu suspenso "Tipo de Inicialização" e confirme a alteração clicando em Aplicar e OK.

Também é possível modificar a configuração de quais arquivos serão copiados na cópia de sombra no registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Sobrescrever arquivos deletados

- Você pode usar uma **ferramenta do Windows**: `cipher /w:C` Isso indicará ao cipher para remover qualquer dado do espaço de disco não utilizado disponível dentro da unidade C.
- Você também pode usar ferramentas como [**Eraser**](https://eraser.heidi.ie)

## Deletar logs de eventos do Windows

- Windows + R --> eventvwr.msc --> Expanda "Logs do Windows" --> Clique com o botão direito em cada categoria e selecione "Limpar Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Desativar logs de eventos do Windows

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dentro da seção de serviços, desative o serviço "Windows Event Log"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

## Desativar $UsnJrnl

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
