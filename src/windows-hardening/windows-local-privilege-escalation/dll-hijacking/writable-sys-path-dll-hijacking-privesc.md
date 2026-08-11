# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Se você puder **escrever em um diretório no `PATH` de todo o sistema** (não apenas no `PATH` do seu usuário), poderá conseguir **escalar privilégios** no sistema.

Isso pode ser explorado por meio de **DLL hijacking** quando um serviço ou processo com mais privilégios tenta carregar uma DLL que não existe nos locais de pesquisa anteriores e, por fim, pesquisa no diretório gravável do sistema presente no `PATH`.

Para obter mais informações sobre **DLL hijacking**, consulte:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

Primeiro, **identifique um processo** em execução com **mais privilégios** que tente **carregar uma DLL de um diretório gravável do sistema presente no `PATH`**.

Lembre-se de que essa técnica depende de uma entrada no **Machine/System PATH**, não apenas no seu **User PATH**. Portanto, antes de passar tempo no Procmon, vale a pena enumerar as entradas do **Machine PATH** e verificar quais delas permitem escrita:<sup>[[1]](#references)</sup>
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
O problema nesses casos é que esses processos provavelmente já estão em execução. Para identificar DLLs que os serviços tentam carregar, mas não conseguem, inicie o Procmon o mais cedo possível (antes de os processos serem iniciados) e, em seguida:

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
- Inicie o **`procmon`** e vá para **`Options`** --> **`Enable boot logging`**, depois pressione **`OK`** no prompt.
- Em seguida, **reinicie**. Quando o computador for reiniciado, o **`procmon`** começará a **registrar** eventos imediatamente.
- Quando o **Windows** for **iniciado, execute o `procmon`** novamente. Ele informará que estava em execução e **perguntará se você deseja armazenar** os eventos em um arquivo. Responda **sim** e **armazene os eventos em um arquivo**.
- **Depois que** o **arquivo** for **gerado**, feche a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
- Adicione estes **filtros** para encontrar todas as DLLs que um **processo tentou carregar** da pasta writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> O **Boot logging** só é necessário para serviços que iniciam **cedo demais** para serem observados de outra forma. Se você puder **acionar o serviço/programa alvo sob demanda** (por exemplo, interagindo com sua interface COM, reiniciando o serviço ou relançando uma tarefa agendada), geralmente é mais rápido manter uma captura normal do Procmon com filtros como **`Path contains .dll`**, **`Result is NAME NOT FOUND`** e **`Path begins with <writable_machine_path>`**.

### DLLs não encontradas

Executando isso em uma **máquina virtual (vmware) gratuita com Windows 11**, obtive estes resultados:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Neste caso, ignore os resultados `.exe`. As sondagens por DLLs ausentes vieram de:

| Serviço                         | DLL                | Linha de CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

O exemplo a seguir usa a técnica descrita neste artigo sobre [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Outros candidatos que vale a pena analisar

`WptsExtensions.dll` é um bom exemplo, mas não é a única **phantom DLL** recorrente que aparece em serviços privilegiados. As regras modernas de hunting e os catálogos públicos de hijacking ainda monitoram nomes como:<sup>[[2]](#references)</sup>

| Serviço / Cenário | DLL ausente | Observações |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidato clássico a **SYSTEM** em sistemas cliente. É uma boa opção quando o diretório gravável está no **Machine PATH** e o serviço faz uma sondagem pela DLL durante a inicialização. |
| NetMan no Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessante em **server editions**, pois o serviço é executado como **SYSTEM** e pode ser **acionado sob demanda por um usuário comum** em algumas builds, tornando-o melhor do que casos que exigem apenas uma reinicialização. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Normalmente resulta primeiro em **`NT AUTHORITY\LOCAL SERVICE`**. Isso ainda costuma ser suficiente, pois o token possui **`SeImpersonatePrivilege`**, permitindo encadeá-lo com [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Trate esses nomes como **dicas para triagem**, não como garantias de sucesso: eles dependem da **SKU/build**, e a Microsoft pode alterar o comportamento entre versões. O ponto principal é procurar **DLLs ausentes em serviços privilegiados que percorrem o Machine PATH**, especialmente se o serviço puder ser **acionado novamente sem reinicialização**.

### Exploitation

Para **escalar privilégios**, faça hijack de **`WptsExtensions.dll`**. Depois que o **caminho** e o **nome** forem conhecidos, gere a DLL maliciosa.

Você pode [**tentar usar qualquer um destes exemplos**](#creating-and-compiling-dlls). Você poderia executar payloads como: obter uma rev shell, adicionar um usuário, executar um beacon...

> [!WARNING]
> Observe que **nem todos os serviços são executados** como **`NT AUTHORITY\SYSTEM`**. Alguns são executados como **`NT AUTHORITY\LOCAL SERVICE`**, que possui **menos privilégios**, portanto abusar de um desses serviços pode não permitir criar um novo usuário.\
> No entanto, essa conta possui o direito de usuário **`SeImpersonatePrivilege`**, então você pode usar a [**Potato suite para escalar privilégios**](../roguepotato-and-printspoofer.md). Nesse caso, uma reverse shell é uma opção melhor do que tentar criar um usuário.

No momento da redação, o serviço **Task Scheduler** é executado com **Nt AUTHORITY\SYSTEM**.

Depois de **gerar a DLL maliciosa** (_no meu caso, usei uma rev shell x64 e obtive uma shell de volta, mas o defender a encerrou porque ela veio do msfvenom_), salve-a no writable System Path com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço, ou faça o que for necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, a **DLL deverá ser carregada e executada** (você pode **reutilizar** o truque do **procmon** para verificar se a **biblioteca foi carregada conforme esperado**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL Suspeita Carregada para Persistência ou Escalação de Privilégios](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Escalação de Privilégios no Windows](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
