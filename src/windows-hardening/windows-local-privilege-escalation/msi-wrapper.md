# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

O MSI Wrapper pode empacotar um executável ou script como um arquivo do Windows Installer (`.msi`). Baixe e inicie a edição gratuita e, em seguida, selecione o executável a ser empacotado.<sup>[[3]](#references)</sup> Para executar uma sequência de comandos, selecione um arquivo `.bat` como entrada em vez de empacotar o `cmd.exe`.<sup>[[1]](#references)</sup>

![Selecionando o executável de origem ou o script em lote no MSI Wrapper](<../../images/image (417).png>)

Configure cuidadosamente o contexto de execução e outras propriedades do instalador:

![Configurando o ID do aplicativo e o contexto de segurança no MSI Wrapper](<../../images/image (312).png>)

![Configurando as propriedades do instalador no MSI Wrapper](<../../images/image (346).png>)

![Revisando as configurações de compilação do MSI Wrapper](<../../images/image (1072).png>)

Esses valores podem ser alterados ao empacotar um binário personalizado.

Continue pelas páginas restantes do assistente e selecione **Build** para gerar o instalador.<sup>[[1]](#references)</sup>

## Verifique o contexto de execução do comando encapsulado

Para um pacote de teste, encapsule um arquivo `.bat` que registre seu token, em vez de presumir que a configuração de elevação do MSI se aplica ao processo filho.<sup>[[4]](#references)</sup> No assistente, escolha o contexto de segurança **System** em vez de **User** e escolha uma instalação por máquina com elevação, se esse for o caminho pretendido.<sup>[[5]](#references)</sup> A opção **System** não contorna a autorização: um usuário não administrador ainda precisa de um meio para realizar uma instalação elevada, como a [configuração incorreta de duas políticas `AlwaysInstallElevated`](index.html#alwaysinstallelevated) ou um fluxo de instalação privilegiado.<sup>[[2]](#references)</sup> Escolher **User** executa o comando encapsulado no contexto do usuário que está instalando, o que pode ser necessário para acessar recursos específicos do usuário ou recursos de rede.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Gere o MSI usando este arquivo batch como entrada, depois execute-o no host de teste e inspecione a identidade e os privilégios registrados.<sup>[[4]](#references)</sup> O MSI Wrapper mapeia um código de saída batch diferente de zero para o erro de instalação 1603, então a saída zero explícita evita uma falha falsa após um teste bem-sucedido.<sup>[[4]](#references)</sup> O arquivo de saída é um artefato de teste; não presuma execução como SYSTEM apenas com base em uma saída bem-sucedida do `msiexec` ou em uma instalação silenciosa.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` silencia a interface do MSI, mas não necessariamente a interface do próprio executável encapsulado.<sup>[[6]](#references)[[7]](#references)</sup> Para um instalador encapsulado, defina os argumentos silenciosos compatíveis no assistente; a propriedade dinâmica `WRAPPED_ARGUMENTS` do MSI Wrapper é um recurso PRO.<sup>[[1]](#references)[[7]](#references)</sup> Consulte [a abordagem de custom action do WiX](create-msi-with-wix.md) se precisar de controle direto sobre o sequenciamento e a impersonation de custom actions.

> [!WARNING]
> Criar um MSI não concede, por si só, privilégios elevados. A elevação da instalação depende da política do Windows Installer, do contexto do pacote e da autorização do usuário. A Microsoft alerta que habilitar `AlwaysInstallElevated` tanto para o usuário quanto para o computador permite que usuários não administradores instalem pacotes com privilégios de sistema.<sup>[[2]](#references)</sup>



## References

- [1] [Documentação do MSI Wrapper - Primeiros passos](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instalar um pacote com privilégios elevados para um usuário não administrador](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Criar MSI a partir de um arquivo batch](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Páginas do assistente](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Opções de linha de comando](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Argumentos de linha de comando](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
