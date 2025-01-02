# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Se você descobriu que pode **escrever em uma pasta do System Path** (note que isso não funcionará se você puder escrever em uma pasta do User Path), é possível que você possa **escalar privilégios** no sistema.

Para fazer isso, você pode abusar de um **Dll Hijacking**, onde você vai **sequestrar uma biblioteca sendo carregada** por um serviço ou processo com **mais privilégios** do que o seu, e como esse serviço está carregando uma Dll que provavelmente nem existe em todo o sistema, ele tentará carregá-la do System Path onde você pode escrever.

Para mais informações sobre **o que é Dll Hijacking**, consulte:

{{#ref}}
./
{{#endref}}

## Privesc com Dll Hijacking

### Encontrando uma Dll ausente

A primeira coisa que você precisa é **identificar um processo** em execução com **mais privilégios** do que você que está tentando **carregar uma Dll do System Path** em que você pode escrever.

O problema nesses casos é que provavelmente esses processos já estão em execução. Para descobrir quais Dlls estão faltando, você precisa iniciar o procmon o mais rápido possível (antes que os processos sejam carregados). Então, para encontrar Dlls ausentes, faça:

- **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **variável de ambiente System Path**. Você pode fazer isso **manualmente** ou com **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Inicie **`procmon`** e vá para **`Options`** --> **`Enable boot logging`** e pressione **`OK`** na mensagem.
- Em seguida, **reinicie**. Quando o computador for reiniciado, **`procmon`** começará a **gravar** eventos imediatamente.
- Assim que o **Windows** estiver **iniciado, execute `procmon`** novamente, ele informará que está em execução e **perguntará se você deseja armazenar** os eventos em um arquivo. Diga **sim** e **armazene os eventos em um arquivo**.
- **Após** o **arquivo** ser **gerado**, **feche** a janela **`procmon`** aberta e **abra o arquivo de eventos**.
- Adicione esses **filtros** e você encontrará todos os Dlls que algum **processo tentou carregar** da pasta do System Path gravável:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Dlls Perdidas

Executando isso em uma **máquina virtual (vmware) Windows 11** gratuita, obtive os seguintes resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Neste caso, os .exe são inúteis, então ignore-os, as DLLs perdidas eram de:

| Serviço                         | Dll                | Linha de CMD                                                         |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Agendador de Tarefas (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Serviço de Política de Diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Depois de encontrar isso, encontrei este post de blog interessante que também explica como [**abusar de WptsExtensions.dll para privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Que é o que **vamos fazer agora**.

### Exploração

Então, para **escalar privilégios**, vamos sequestrar a biblioteca **WptsExtensions.dll**. Tendo o **caminho** e o **nome**, só precisamos **gerar a dll maliciosa**.

Você pode [**tentar usar qualquer um desses exemplos**](./#creating-and-compiling-dlls). Você poderia executar payloads como: obter um rev shell, adicionar um usuário, executar um beacon...

> [!WARNING]
> Note que **nem todos os serviços são executados** com **`NT AUTHORITY\SYSTEM`**, alguns também são executados com **`NT AUTHORITY\LOCAL SERVICE`**, que tem **menos privilégios** e você **não poderá criar um novo usuário** abusando de suas permissões.\
> No entanto, esse usuário tem o privilégio **`seImpersonate`**, então você pode usar o [**potato suite para escalar privilégios**](../roguepotato-and-printspoofer.md). Portanto, neste caso, um rev shell é uma opção melhor do que tentar criar um usuário.

No momento em que escrevo, o serviço **Agendador de Tarefas** está sendo executado com **Nt AUTHORITY\SYSTEM**.

Tendo **gerado a Dll maliciosa** (_no meu caso, usei um rev shell x64 e recebi um shell de volta, mas o defender o matou porque era do msfvenom_), salve-a no System Path gravável com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço ou faça o que for necessário para reiniciar o serviço/programa afetado).

Quando o serviço for reiniciado, a **dll deve ser carregada e executada** (você pode **reutilizar** o truque do **procmon** para verificar se a **biblioteca foi carregada conforme esperado**).

{{#include ../../../banners/hacktricks-training.md}}
