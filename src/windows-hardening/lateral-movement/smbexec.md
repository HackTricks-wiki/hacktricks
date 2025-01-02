# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem**

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas mais de 20 ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem escalar privilégios e usar exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Como Funciona

**Smbexec** é uma ferramenta usada para execução remota de comandos em sistemas Windows, semelhante ao **Psexec**, mas evita colocar arquivos maliciosos no sistema alvo.

### Pontos Chave sobre **SMBExec**

- Ele opera criando um serviço temporário (por exemplo, "BTOBTO") na máquina alvo para executar comandos via cmd.exe (%COMSPEC%), sem deixar binários.
- Apesar de sua abordagem furtiva, ele gera logs de eventos para cada comando executado, oferecendo uma forma de "shell" não interativa.
- O comando para se conectar usando **Smbexec** se parece com isto:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Executando Comandos Sem Binários

- **Smbexec** permite a execução direta de comandos através de binPaths de serviço, eliminando a necessidade de binários físicos no alvo.
- Este método é útil para executar comandos únicos em um alvo Windows. Por exemplo, emparelhá-lo com o módulo `web_delivery` do Metasploit permite a execução de um payload reverso Meterpreter direcionado ao PowerShell.
- Ao criar um serviço remoto na máquina do atacante com binPath configurado para executar o comando fornecido através do cmd.exe, é possível executar o payload com sucesso, alcançando callback e execução do payload com o listener do Metasploit, mesmo que ocorram erros de resposta do serviço.

### Exemplo de Comandos

Criar e iniciar o serviço pode ser realizado com os seguintes comandos:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Para mais detalhes, consulte [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Referências

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenha a perspectiva de um hacker sobre seus aplicativos web, rede e nuvem**

**Encontre e relate vulnerabilidades críticas e exploráveis com impacto real nos negócios.** Use nossas mais de 20 ferramentas personalizadas para mapear a superfície de ataque, encontrar problemas de segurança que permitem escalar privilégios e usar exploits automatizados para coletar evidências essenciais, transformando seu trabalho árduo em relatórios persuasivos.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
