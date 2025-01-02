# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas mais avançadas** da comunidade.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Como funcionam

O processo é descrito nos passos abaixo, ilustrando como os binários de serviço são manipulados para alcançar a execução remota em uma máquina alvo via SMB:

1. **Cópia de um binário de serviço para o compartilhamento ADMIN$ via SMB** é realizada.
2. **Criação de um serviço na máquina remota** é feita apontando para o binário.
3. O serviço é **iniciado remotamente**.
4. Ao sair, o serviço é **parado, e o binário é deletado**.

### **Processo de Execução Manual do PsExec**

Assumindo que há um payload executável (criado com msfvenom e ofuscado usando Veil para evadir a detecção de antivírus), nomeado 'met8888.exe', representando um payload reverse_http do meterpreter, os seguintes passos são realizados:

- **Cópia do binário**: O executável é copiado para o compartilhamento ADMIN$ a partir de um prompt de comando, embora possa ser colocado em qualquer lugar no sistema de arquivos para permanecer oculto.

- **Criação de um serviço**: Utilizando o comando `sc` do Windows, que permite consultar, criar e deletar serviços do Windows remotamente, um serviço chamado "meterpreter" é criado para apontar para o binário carregado.

- **Iniciando o serviço**: O passo final envolve iniciar o serviço, o que provavelmente resultará em um erro de "timeout" devido ao binário não ser um verdadeiro binário de serviço e falhar em retornar o código de resposta esperado. Este erro é irrelevante, pois o objetivo principal é a execução do binário.

A observação do listener do Metasploit revelará que a sessão foi iniciada com sucesso.

[Saiba mais sobre o comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Encontre passos mais detalhados em: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Você também pode usar o binário PsExec.exe do Windows Sysinternals:**

![](<../../images/image (165).png>)

Você também pode usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{{#include ../../banners/hacktricks-training.md}}
