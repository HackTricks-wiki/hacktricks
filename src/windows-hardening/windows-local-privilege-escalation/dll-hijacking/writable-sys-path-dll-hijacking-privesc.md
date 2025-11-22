# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Se você descobrir que pode **escrever em uma pasta do System Path** (observe que isso não funcionará se você puder escrever em uma pasta do User Path), é possível que você consiga **escalar privilégios** no sistema.

Para fazer isso você pode abusar de um **Dll Hijacking** onde você vai **sequestrar uma biblioteca que está sendo carregada** por um serviço ou processo com **mais privilégios** que os seus, e como esse serviço está carregando uma Dll que provavelmente nem existe em todo o sistema, ele tentará carregá‑la a partir do System Path onde você pode escrever.

Para mais informações sobre **o que é Dll Hijackig** confira:


{{#ref}}
./
{{#endref}}

## Privesc com Dll Hijacking

### Encontrando um Dll ausente

A primeira coisa que você precisa é **identificar um processo** rodando com **mais privilégios** que os seus que esteja tentando **carregar uma Dll do System Path** em que você pode escrever.

O problema nesses casos é que provavelmente esses processos já estão em execução. Para descobrir quais Dlls estão faltando nos serviços, você precisa iniciar o procmon o mais cedo possível (antes que os processos sejam carregados). Então, para encontrar .dlls ausentes faça:

- **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **System Path env variable**. Você pode fazer isso **manualmente** ou com **PS**:
```bash
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
- Inicie **`procmon`** e vá em **`Options`** --> **`Enable boot logging`** e pressione **`OK`** no prompt.
- Em seguida, **reboot**. Quando o computador for reiniciado o **`procmon`** irá começar a **registrar** eventos o mais rápido possível.
- Assim que o **Windows** for iniciado execute **`procmon`** novamente; ele informará que estava em execução e **perguntará se você quer salvar** os eventos em um arquivo. Diga **sim** e **salve os eventos em um arquivo**.
- **Depois** que o **arquivo** for **gerado**, **feche** a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
- Adicione estes **filtros** e você encontrará todas as DLLs que algum **processo tentou carregar** a partir da pasta do System Path que é gravável:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### DLLs faltantes

Ao executar isso em uma máquina virtual gratuita (vmware) com Windows 11 obtive estes resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Neste caso os .exe são inúteis então ignore-os; as DLLs faltantes eram de:

| Serviço                         | Dll                | Linha de comando                                                     |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

After finding this, I found this interesting blog post that also explains how to [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Which is what we **are going to do now**.

### Exploitation

Então, para **escalar privilégios** vamos hijackar a biblioteca **WptsExtensions.dll**. Tendo o **caminho** e o **nome** só precisamos **gerar a dll maliciosa**.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). You could run payloads such as: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Note that **not all the service are run** with **`NT AUTHORITY\SYSTEM`** some are also run with **`NT AUTHORITY\LOCAL SERVICE`** which has **less privileges** and you **won't be able to create a new user** abuse its permissions.\
> However, that user has the **`seImpersonate`** privilege, so you can use the[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). So, in this case a rev shell is a better option that trying to create a user.

No momento em que este texto foi escrito o serviço Task Scheduler é executado com **Nt AUTHORITY\SYSTEM**.

Tendo **gerado a DLL maliciosa** (_no meu caso usei um rev shell x64 e obtive uma shell de volta, mas o Defender a matou porque veio do msfvenom_), salve-a no System Path gravável com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço ou faça o que for necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, a **dll deve ser carregada e executada** (você pode **reutilizar** o truque do **procmon** para checar se a **biblioteca foi carregada como esperado**).

{{#include ../../../banners/hacktricks-training.md}}
