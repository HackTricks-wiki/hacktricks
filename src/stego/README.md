# Stego

{{#include ../banners/hacktricks-training.md}}

Esta seção foca em **encontrar e extrair dados ocultos** de arquivos (imagens/áudio/vídeo/documentos/arquivos) e de esteganografia baseada em texto.

Se você está aqui por ataques criptográficos, vá para a seção **Crypto**.

## Ponto de entrada

Aborde steganography como um problema forense: identifique o container real, enumere locais de alta informação (metadados, dados anexados, arquivos embutidos) e só então aplique técnicas de extração a nível de conteúdo.

### Fluxo de trabalho & triagem

Um fluxo de trabalho estruturado que prioriza identificação do container, inspeção de metadata/strings, carving, e ramificações específicas por formato.
{{#ref}}
workflow/README.md
{{#endref}}

### Imagens

Onde a maior parte do stego de CTF aparece: LSB/bit-planes (PNG/BMP), estranhezas de chunk/file-format, tooling para JPEG, e truques com GIF multi-frame.
{{#ref}}
images/README.md
{{#endref}}

### Áudio

Mensagens em spectrogram, sample LSB embedding, e tons de teclado telefônico (DTMF) são padrões recorrentes.
{{#ref}}
audio/README.md
{{#endref}}

### Texto

Se o texto é renderizado normalmente mas se comporta de forma inesperada, considere Unicode homoglyphs, caracteres zero-width, ou codificação baseada em espaços em branco.
{{#ref}}
text/README.md
{{#endref}}

### Documentos

PDFs e Office files são containers antes de mais nada; ataques geralmente giram em torno de arquivos/streams embutidos, grafos de objetos/relacionamentos, e extração de ZIP.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery frequentemente usa arquivos com aparência válida (ex.: GIF/PNG) que carregam payloads de texto delimitados por marcadores, em vez de esconder em nível de pixel.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
