# Stego

{{#include ../banners/hacktricks-training.md}}

Esta seção se concentra em **encontrar e extrair dados ocultos** de arquivos (imagens/áudio/vídeo/documentos/arquivos compactados) e em esteganografia baseada em texto.

Se você está aqui em busca de ataques criptográficos, vá para a seção **Crypto**.

## Entry Point

Aborde a esteganografia como um problema forense: identifique o container real, enumere locais de alto sinal (metadados, dados anexados, arquivos incorporados) e só então aplique técnicas de extração no nível do conteúdo.

### Workflow & triage

Um workflow estruturado que prioriza a identificação do container, a inspeção de metadados/strings, o carving e a análise específica do formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Onde a maior parte do CTF stego aparece: LSB/bit-planes (PNG/BMP), peculiaridades de chunks/formatos de arquivo, ferramentas para JPEG e técnicas com GIFs multi-frame.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Mensagens em spectrogramas, embedding de LSB em samples e tons de teclas telefônicas (DTMF) são padrões recorrentes.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Se o texto é renderizado normalmente, mas se comporta de forma inesperada, considere homoglyphs Unicode, caracteres de largura zero ou encoding baseado em whitespace.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs e arquivos do Office são, antes de tudo, containers; os ataques geralmente envolvem arquivos/streams incorporados, grafos de objetos/relacionamentos e extração de ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

A entrega de payloads frequentemente usa arquivos aparentemente válidos (por exemplo, GIF/PNG) que carregam payloads de texto delimitados por marcadores, em vez de ocultação no nível dos pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
