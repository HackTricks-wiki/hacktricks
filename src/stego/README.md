# Stego

{{#include ../banners/hacktricks-training.md}}

Esta seção se concentra em **encontrar e extrair dados ocultos** de imagens, áudio, vídeo, documentos, arquivos compactados e texto. A esteganografia oculta a existência de uma comunicação incorporando dados dentro de outros dados.<sup>[[1]](#references)</sup>

Se você está aqui em busca de ataques criptográficos, vá para a seção **Crypto**.

## Entry Point

Aborde a esteganografia como um problema forense: identifique o container real, enumere locais de alto sinal (metadados, dados anexados, arquivos incorporados) e só então aplique técnicas de extração no nível do conteúdo.

### Workflow e triagem

Um workflow estruturado que prioriza a identificação do container, a inspeção de metadados/strings, o carving e a ramificação específica do formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Onde a maior parte do CTF stego acontece: LSB/planos de bits (PNG/BMP), peculiaridades de chunks/formato de arquivo, ferramentas para JPEG e truques com GIFs de vários frames.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Mensagens em espectrogramas, incorporação de LSB em samples e tons de teclas telefônicas (DTMF) são padrões recorrentes.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Se o texto é renderizado normalmente, mas se comporta de forma inesperada, considere homoglyphs Unicode, caracteres de largura zero ou encoding baseado em espaços em branco.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs e arquivos do Office são, antes de tudo, containers; os ataques geralmente envolvem arquivos/streams incorporados, grafos de objetos/relacionamentos e extração de ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

A entrega de payloads pode usar arquivos com aparência válida, como imagens GIF ou PNG, que carregam payloads de texto delimitados por marcadores em vez de ocultar dados nos pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glossário do CSRC do NIST - Esteganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
