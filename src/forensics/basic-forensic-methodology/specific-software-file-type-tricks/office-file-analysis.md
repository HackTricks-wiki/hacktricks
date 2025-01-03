# Análise de arquivos do Office

{{#include ../../../banners/hacktricks-training.md}}

Para mais informações, consulte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este é apenas um resumo:

A Microsoft criou muitos formatos de documentos do Office, sendo os dois principais tipos os **formatos OLE** (como RTF, DOC, XLS, PPT) e os **formatos Office Open XML (OOXML)** (como DOCX, XLSX, PPTX). Esses formatos podem incluir macros, tornando-se alvos para phishing e malware. Os arquivos OOXML são estruturados como contêineres zip, permitindo a inspeção através da descompactação, revelando a hierarquia de arquivos e pastas e o conteúdo dos arquivos XML.

Para explorar as estruturas de arquivos OOXML, o comando para descompactar um documento e a estrutura de saída são fornecidos. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando inovação contínua na ocultação de dados dentro dos desafios CTF.

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos de ferramentas abrangentes para examinar documentos OLE e OOXML. Essas ferramentas ajudam a identificar e analisar macros incorporadas, que muitas vezes servem como vetores para a entrega de malware, normalmente baixando e executando cargas maliciosas adicionais. A análise de macros VBA pode ser realizada sem o Microsoft Office utilizando o Libre Office, que permite a depuração com pontos de interrupção e variáveis de observação.

A instalação e o uso do **oletools** são diretos, com comandos fornecidos para instalação via pip e extração de macros de documentos. A execução automática de macros é acionada por funções como `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
