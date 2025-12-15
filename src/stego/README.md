# Stego

{{#include ../banners/hacktricks-training.md}}

Цей розділ зосереджений на **пошуку та вилученні прихованих даних** з файлів (зображення/аудіо/відео/документи/архіви) та з текстової steganography.

If you're here for cryptographic attacks, go to the **Crypto** section.

## Вхідна точка

Розглядайте steganography як задачу форензики: визначте реальний контейнер, перераховуйте місця з високим сигналом (метадані, appended data, embedded files), і лише потім застосовуйте техніки вилучення на рівні вмісту.

### Workflow & triage

Структурований робочий процес, який віддає пріоритет ідентифікації контейнера, перевірці метаданих/рядків, carving, та розгалуженню залежно від формату.
{{#ref}}
workflow/README.md
{{#endref}}

### Зображення

Тут знаходиться більшість CTF stego: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, and multi-frame GIF tricks.
{{#ref}}
images/README.md
{{#endref}}

### Аудіо

Повідомлення в спектрограмі, sample LSB embedding, та тони телефонної клавіатури (DTMF) — повторювані патерни.
{{#ref}}
audio/README.md
{{#endref}}

### Текст

Якщо текст відображається нормально, але поводиться несподівано, розгляньте Unicode homoglyphs, zero-width characters, або whitespace-based encoding.
{{#ref}}
text/README.md
{{#endref}}

### Документи

PDFs та Office файли перш за все є контейнерами; атаки зазвичай зосереджуються навколо embedded files/streams, object/relationship graphs, та ZIP extraction.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery frequently uses valid-looking files (e.g., GIF/PNG) that carry marker-delimited text payloads, rather than pixel-level hiding.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
