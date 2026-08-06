# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Se você descobriu que pode **escrever em uma pasta do System Path** (observe que isso não funcionará se você puder escrever em uma pasta do User Path), é possível que consiga **escalar privilégios** no sistema.

Para fazer isso, você pode explorar um **Dll Hijacking**, no qual irá **sequestrar uma library sendo carregada** por um service ou process com **mais privilégios** que os seus. Como esse service está carregando uma Dll que provavelmente nem existe em todo o sistema, ele tentará carregá-la a partir do System Path, onde você pode escrever.

Para obter mais informações sobre **o que é Dll Hijackig**, consulte:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

A primeira coisa necessária é **identificar um process** em execução com **mais privilégios** que os seus e que esteja tentando **carregar uma Dll a partir do System Path** no qual você pode escrever.

Lembre-se de que essa técnica depende de uma entrada no **Machine/System PATH**, e não apenas do seu **User PATH**. Portanto, antes de gastar tempo no Procmon, vale a pena enumerar as entradas do **Machine PATH** e verificar quais podem ser gravadas:<sup>[[1]](#references)</sup>
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
O problema nestes casos é que provavelmente esses processos já estão em execução. Para descobrir quais DLLs estão faltando, você precisa iniciar o procmon o mais rápido possível (antes que os processos sejam carregados). Portanto, para encontrar as `.dlls` ausentes:

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
- Inicie o **`procmon`** e acesse **`Options`** --> **`Enable boot logging`**, depois pressione **`OK`** no prompt.
- Em seguida, **reinicie** o computador. Quando ele for reiniciado, o **`procmon`** começará a **registrar** eventos o mais rápido possível.
- Quando o **Windows** for **iniciado, execute o `procmon`** novamente. Ele informará que estava em execução e **perguntará se você deseja armazenar** os eventos em um arquivo. Responda **sim** e **armazene os eventos em um arquivo**.
- **Depois** que o **arquivo** for **gerado**, **feche** a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
- Adicione estes **filtros** e você encontrará todas as DLLs que algum **processo tentou carregar** da pasta System Path com permissão de escrita:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging só é necessário para serviços que iniciam cedo demais** para serem observados de outra forma. Se você puder **acionar o serviço/programa alvo sob demanda** (por exemplo, interagindo com sua interface COM, reiniciando o serviço ou iniciando novamente uma tarefa agendada), geralmente é mais rápido manter uma captura normal do Procmon com filtros como **`Path contains .dll`**, **`Result is NAME NOT FOUND`** e **`Path begins with <writable_machine_path>`**.

### DLLs não encontradas

Ao executar isso em uma **máquina virtual (vmware) gratuita com Windows 11**, obtive estes resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Nesse caso, os arquivos .exe são inúteis, então ignore-os. As DLLs não encontradas eram provenientes de:

| Serviço                         | DLL                | Linha de comando                                                     |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Agendador de Tarefas (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Serviço de Política de Diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Depois de encontrar isso, encontrei esta publicação interessante que também explica como [**abusar de WptsExtensions.dll para privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). É exatamente o que **vamos fazer agora**.<sup>[[3]](#references)</sup>

### Outros candidatos que vale a pena analisar

`WptsExtensions.dll` é um bom exemplo, mas não é a única **phantom DLL** recorrente que aparece em serviços privilegiados. As regras modernas de hunting e os catálogos públicos de hijacking ainda monitoram nomes como:<sup>[[2]](#references)</sup>

| Serviço / Cenário | DLL ausente | Observações |
| --- | --- | --- |
| Agendador de Tarefas (`Schedule`) | `WptsExtensions.dll` | Candidato clássico a **SYSTEM** em sistemas cliente. É uma boa opção quando o diretório com permissão de escrita está no **Machine PATH** e o serviço procura a DLL durante a inicialização. |
| NetMan no Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante em **edições de servidor** porque o serviço é executado como **SYSTEM** e pode ser **acionado sob demanda por um usuário normal** em algumas builds, tornando-o melhor do que casos que exigem apenas uma reinicialização. |
| Serviço Connected Devices Platform (`CDPSvc`) | `cdpsgshims.dll` | Normalmente resulta primeiro em **`NT AUTHORITY\LOCAL SERVICE`**. Isso ainda costuma ser suficiente porque o token possui **`SeImpersonatePrivilege`**, permitindo encadeá-lo com [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Trate esses nomes como **dicas para triagem**, não como garantias de sucesso: eles dependem da **SKU/build**, e a Microsoft pode alterar o comportamento entre versões. O ponto principal é procurar **DLLs ausentes em serviços privilegiados que percorrem o Machine PATH**, especialmente se o serviço puder ser **acionado novamente sem reinicialização**.

### Exploitation

Portanto, para **escalar privilégios**, vamos fazer hijacking da biblioteca **WptsExtensions.dll**. Como temos o **caminho** e o **nome**, basta **gerar a DLL maliciosa**.

Você pode [**tentar usar qualquer um destes exemplos**](#creating-and-compiling-dlls). Você poderia executar payloads como: obter uma rev shell, adicionar um usuário, executar um beacon...

> [!WARNING]
> Observe que **nem todos os serviços são executados** com **`NT AUTHORITY\SYSTEM`**. Alguns também são executados com **`NT AUTHORITY\LOCAL SERVICE`**, que possui **menos privilégios**, e você **não poderá criar um novo usuário** abusando de suas permissões.\
> No entanto, esse usuário possui o privilégio **`seImpersonate`**, então você pode usar o[ **potato suite para escalar privilégios**](../roguepotato-and-printspoofer.md). Nesse caso, uma rev shell é uma opção melhor do que tentar criar um usuário.

No momento da redação, o serviço **Agendador de Tarefas** é executado com **Nt AUTHORITY\SYSTEM**.

Depois de **gerar a DLL maliciosa** (_no meu caso, usei uma rev shell x64 e obtive uma shell de volta, mas o defender a encerrou porque ela foi criada pelo msfvenom_), salve-a no System Path com permissão de escrita usando o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço, ou faça o que for necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, a **DLL deverá ser carregada e executada** (você pode **reutilizar** o truque do **procmon** para verificar se a **biblioteca foi carregada conforme esperado**).

## Referências

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
