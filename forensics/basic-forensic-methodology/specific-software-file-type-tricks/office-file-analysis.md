# Análise de arquivos do Office

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com facilidade, usando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introdução

A Microsoft criou **dezenas de formatos de arquivos de documentos do Office**, muitos dos quais são populares para a distribuição de ataques de phishing e malware por causa de sua capacidade de **incluir macros** (scripts VBA).

De maneira geral, existem duas gerações de formatos de arquivos do Office: os **formatos OLE** (extensões de arquivo como RTF, DOC, XLS, PPT) e os "**formatos Office Open XML**" (extensões de arquivo que incluem DOCX, XLSX, PPTX). **Ambos** os formatos são formatos binários de arquivo compostos e estruturados que **permitem conteúdo vinculado ou incorporado** (objetos). Os arquivos OOXML são contêineres de arquivos zip, o que significa que uma das maneiras mais fáceis de verificar dados ocultos é simplesmente `descompactar` o documento:
```
$ unzip example.docx 
Archive:  example.docx
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: word/_rels/document.xml.rels  
  inflating: word/document.xml       
  inflating: word/theme/theme1.xml   
 extracting: docProps/thumbnail.jpeg  
  inflating: word/comments.xml       
  inflating: word/settings.xml       
  inflating: word/fontTable.xml      
  inflating: word/styles.xml         
  inflating: word/stylesWithEffects.xml  
  inflating: docProps/app.xml        
  inflating: docProps/core.xml       
  inflating: word/webSettings.xml    
  inflating: word/numbering.xml
$ tree
.
├── [Content_Types].xml
├── _rels
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── thumbnail.jpeg
└── word
    ├── _rels
    │   └── document.xml.rels
    ├── comments.xml
    ├── document.xml
    ├── fontTable.xml
    ├── numbering.xml
    ├── settings.xml
    ├── styles.xml
    ├── stylesWithEffects.xml
    ├── theme
    │   └── theme1.xml
    └── webSettings.xml
```
Como pode ser visto, parte da estrutura é criada pelo arquivo e hierarquia de pastas. O restante é especificado dentro dos arquivos XML. [_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) detalha algumas ideias para técnicas de ocultação de dados, mas os autores de desafios CTF sempre estarão criando novas.

Mais uma vez, existe um conjunto de ferramentas Python para exame e **análise de documentos OLE e OOXML**: [oletools](http://www.decalage.info/python/oletools). Para documentos OOXML em particular, [OfficeDissector](https://www.officedissector.com) é um framework de análise muito poderoso (e biblioteca Python). Este último inclui um [guia rápido para seu uso](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Às vezes, o desafio não é encontrar dados estáticos ocultos, mas **analisar uma macro VBA** para determinar seu comportamento. Este é um cenário mais realista e um que os analistas de campo realizam todos os dias. As ferramentas de dissector mencionadas acima podem indicar se uma macro está presente e provavelmente extraí-la para você. Uma macro VBA típica em um documento do Office, no Windows, fará o download de um script PowerShell para %TEMP% e tentará executá-lo, caso em que você agora tem uma tarefa de análise de script PowerShell. Mas macros VBA maliciosas raramente são complicadas, já que o VBA é [geralmente usado apenas como uma plataforma de lançamento para inicializar a execução de código](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). No caso em que você precisa entender uma macro VBA complicada, ou se a macro está ofuscada e tem uma rotina de descompactação, você não precisa ter uma licença do Microsoft Office para depurá-la. Você pode usar o [Libre Office](http://libreoffice.org): [sua interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) será familiar para quem já depurou um programa; você pode definir pontos de interrupção e criar variáveis de observação e capturar valores depois que eles foram descompactados, mas antes que o comportamento da carga útil tenha sido executado. Você pode até iniciar uma macro de um documento específico a partir de uma linha de comando:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

O **oletools** é um conjunto de ferramentas para analisar arquivos OLE (Object Linking and Embedding), como arquivos do Microsoft Office. Ele inclui várias ferramentas para extrair informações de arquivos OLE e detectar possíveis ameaças de segurança, como macros maliciosas. Algumas das ferramentas incluídas são:

- **olevba**: extrai e analisa macros VBA (Visual Basic for Applications) de arquivos do Office.
- **oleid**: verifica se um arquivo OLE contém características suspeitas que possam indicar uma ameaça de segurança.
- **oledump**: analisa a estrutura de um arquivo OLE e extrai seus componentes, como macros, objetos e fluxos.

Essas ferramentas podem ser úteis para analisar arquivos do Office em busca de possíveis ameaças de segurança ou para extrair informações de arquivos OLE para fins forenses.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Execução Automática

Funções de macro como `AutoOpen`, `AutoExec` ou `Document_Open` serão **executadas automaticamente**.

## Referências

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
