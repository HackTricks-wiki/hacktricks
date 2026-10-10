# Stego

{{#include ../banners/hacktricks-training.md}}

Esta seção se concentra em **encontrar e extrair dados ocultos** de imagens, áudio, vídeo, documentos, arquivos compactados e texto. A esteganografia oculta a existência de uma comunicação incorporando dados em outros dados.<sup>[[1]](#references)</sup>

Se você está aqui para ataques criptográficos, acesse a seção **Crypto**.

## Ponto de entrada

Aborde a esteganografia como um problema forense: identifique o contêiner real, enumere locais com alta probabilidade de conter dados (metadados, dados anexados, arquivos incorporados) e só então aplique técnicas de extração no conteúdo.

### Fluxo de trabalho e triagem

Um fluxo de trabalho estruturado que prioriza a identificação do contêiner, a inspeção de metadados e strings, o carving e a ramificação por formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Imagens

Onde ocorre a maior parte da esteganografia em CTFs: LSB/planos de bits (PNG/BMP), peculiaridades de chunks e formatos de arquivo, ferramentas para JPEG e truques com GIFs de múltiplos frames.

{{#ref}}
images/README.md
{{#endref}}

### Áudio

Mensagens em espectrogramas, incorporação de LSB em amostras e tons de teclado telefônico (DTMF) são padrões recorrentes.

{{#ref}}
audio/README.md
{{#endref}}

### Texto

Se o texto é exibido normalmente, mas se comporta de forma inesperada, considere homoglifos Unicode, caracteres de largura zero ou codificação baseada em espaços em branco.

{{#ref}}
text/README.md
{{#endref}}

### Documentos

PDFs e arquivos do Office são, antes de tudo, contêineres; os ataques geralmente envolvem arquivos/streams incorporados, grafos de objetos e relacionamentos e extração de ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware e esteganografia para entrega de payloads

A entrega de payloads pode usar arquivos com aparência legítima, como imagens GIF ou PNG, que contêm payloads de texto delimitados por marcadores, em vez de ocultar dados nos pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glossário NIST CSRC - Esteganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
