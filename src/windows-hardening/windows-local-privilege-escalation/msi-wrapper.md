# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

O MSI Wrapper pode empacotar um executável ou script como um arquivo do Windows Installer (`.msi`). Baixe e inicie a edição gratuita e, em seguida, selecione o executável a ser empacotado.<sup>[[3]](#references)</sup> Para executar uma sequência de comandos, selecione um arquivo `.bat` como entrada em vez de empacotar o `cmd.exe`.<sup>[[1]](#references)</sup>

![Selecionando o executável de origem ou script em lote no MSI Wrapper](<../../images/image (417).png>)

Configure cuidadosamente o contexto de execução e outras propriedades do instalador:

![Configurando o ID do aplicativo e o contexto de segurança no MSI Wrapper](<../../images/image (312).png>)

![Configurando as propriedades do instalador no MSI Wrapper](<../../images/image (346).png>)

![Revisando as configurações de compilação do MSI Wrapper](<../../images/image (1072).png>)

Esses valores podem ser alterados ao empacotar um binário personalizado.

Continue pelas páginas restantes do assistente e selecione **Build** para gerar o instalador.<sup>[[1]](#references)</sup>

> [!WARNING]
> Criar um MSI, por si só, não concede privilégios elevados. A elevação da instalação depende da política do Windows Installer, do contexto do pacote e da autorização do usuário. A Microsoft alerta que habilitar `AlwaysInstallElevated` para o usuário e o computador permite que não administradores instalem pacotes com privilégios de sistema.<sup>[[2]](#references)</sup>

## References

- [1] [Documentação do MSI Wrapper - Primeiros passos](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instalando um pacote com privilégios elevados para um usuário não administrador](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
