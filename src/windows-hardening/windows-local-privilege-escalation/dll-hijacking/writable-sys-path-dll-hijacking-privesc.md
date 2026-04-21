# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Se você descobriu que pode **escrever em uma pasta do System Path** (note que isso não vai funcionar se você puder escrever em uma pasta do User Path), é possível que você possa **elevar privilégios** no sistema.

Para fazer isso, você pode abusar de um **Dll Hijacking**, em que você vai **hijack** uma library sendo carregada por um service ou process com **mais privilégios** do que você, e como esse service está carregando uma Dll que provavelmente nem existe em todo o sistema, ele vai tentar carregá-la a partir do System Path onde você pode escrever.

Para mais info sobre **what is Dll Hijackig** confira:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Encontrando uma Dll ausente

A primeira coisa que você precisa é **identificar um processo** rodando com **mais privilégios** do que você e que esteja tentando **carregar uma Dll do System Path** onde você pode escrever.

Lembre-se de que essa technique depende de uma entrada no **Machine/System PATH**, não apenas no seu **User PATH**. Portanto, antes de gastar tempo no Procmon, vale a pena enumerar as entradas do **Machine PATH** e verificar quais delas são graváveis:
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
O problema nestes casos é que provavelmente esses processos já estão em execução. Para encontrar quais Dlls estão faltando, você precisa iniciar o procmon o mais rápido possível (antes de os processos serem carregados). Então, para encontrar .dlls ausentes, faça:

- **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **variável de ambiente System Path**. Você pode fazer isso **manualmente** ou com **PS**:
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
- Inicie o **`procmon`** e vá em **`Options`** --> **`Enable boot logging`** e pressione **`OK`** no prompt.
- Depois, **reinicie**. Quando o computador for reiniciado, o **`procmon`** começará a **registrar** eventos o mais rápido possível.
- Assim que o **Windows** estiver iniciado, execute **`procmon`** novamente; ele informará que já estava em execução e vai **perguntar se você deseja armazenar** os eventos em um arquivo. Responda **yes** e **salve os eventos em um arquivo**.
- **Depois** que o **arquivo** for **gerado**, **feche** a janela aberta do **`procmon`** e **abra o arquivo de eventos**.
- Adicione estes **filters** e você encontrará todos os Dlls que algum **processo tentou carregar** a partir da pasta writable do System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging is only required for services that start too early** to observe otherwise. If you can **trigger the target service/program on demand** (for example, by interacting with its COM interface, restarting the service, or relaunching a scheduled task), it is usually faster to keep a normal Procmon capture with filters such as **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, and **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Executando isso em uma máquina **virtual (vmware) Windows 11** gratuita, obtive estes resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Nesse caso, os .exe são inúteis, então ignore-os; os DLLs ausentes eram destes:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Depois de encontrar isso, achei este post de blog interessante que também explica como [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). É o que **vamos fazer agora**.

### Other candidates worth triaging

`WptsExtensions.dll` é um bom exemplo, mas não é o único **phantom DLL** recorrente que aparece em serviços privilegiados. As regras modernas de hunting e catálogos públicos de hijack ainda acompanham nomes como:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Clássico candidato **SYSTEM** em sistemas cliente. Bom quando o diretório gravável está no **Machine PATH** e o serviço procura a DLL durante a inicialização. |
| NetMan no Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante em **server editions** porque o serviço roda como **SYSTEM** e pode ser **triggered on demand by a normal user** em algumas builds, tornando-o melhor do que casos que exigem reboot. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Normalmente resulta primeiro em **`NT AUTHORITY\LOCAL SERVICE`**. Isso geralmente ainda é suficiente porque o token tem **`SeImpersonatePrivilege`**, então você pode encadeá-lo com [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Trate esses nomes como **triage hints**, não como vitórias garantidas: eles são **dependentes de SKU/build**, e a Microsoft pode alterar o comportamento entre versões. A lição principal é procurar por **missing DLLs em serviços privilegiados que percorrem o Machine PATH**, especialmente se o serviço puder ser **retriggered sem reiniciar**.

### Exploitation

Então, para **escalate privileges** vamos hijackear a biblioteca **WptsExtensions.dll**. Tendo o **path** e o **nome**, só precisamos **gerar o dll malicioso**.

Você pode [**try to use any of these examples**](#creating-and-compiling-dlls). Você poderia executar payloads como: obter uma rev shell, adicionar um usuário, executar um beacon...

> [!WARNING]
> Observe que **nem todos os serviços são executados** com **`NT AUTHORITY\SYSTEM`**; alguns também são executados com **`NT AUTHORITY\LOCAL SERVICE`**, que tem **menos privilégios** e você **não conseguirá criar um novo usuário** para abusar dessas permissões.\
> Porém, esse usuário tem o privilégio **`seImpersonate`**, então você pode usar a[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Portanto, neste caso, uma rev shell é uma opção melhor do que tentar criar um usuário.

No momento da escrita, o serviço **Task Scheduler** é executado com **Nt AUTHORITY\SYSTEM**.

Tendo **gerado o Dll malicioso** (_no meu caso usei uma rev shell x64 e recebi uma shell de volta, mas o defender a matou porque veio do msfvenom_), salve-o no System Path gravável com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço ou faça o que for necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, o **dll deve ser carregado e executado** (você pode **reutilizar** o truque do **procmon** para verificar se a **library foi carregada como esperado**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
