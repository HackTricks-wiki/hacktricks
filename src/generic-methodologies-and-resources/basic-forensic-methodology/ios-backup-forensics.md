# Forense de Backup iOS (Triagem centrada em mensagens)

{{#include ../../banners/hacktricks-training.md}}

Esta página descreve passos práticos para reconstruir e analisar backups iOS em busca de sinais de entrega de exploits 0‑click via anexos de apps de mensagens. Ela foca em transformar o layout de backup com nomes hash da Apple em caminhos legíveis por humanos, e então enumerar e escanear anexos em apps comuns.

Objetivos:
- Reconstruir caminhos legíveis a partir do Manifest.db
- Enumerar bancos de dados de mensagens (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver caminhos de anexos, extrair objetos embutidos (PDF/Imagens/Fontes) e enviá‑los para detectores estruturais


## Reconstruindo um backup iOS

Backups armazenados em MobileSync usam nomes de arquivo hashados que não são legíveis por humanos. O banco de dados SQLite Manifest.db mapeia cada objeto armazenado para seu caminho lógico.

Procedimento de alto nível:
1) Abra o Manifest.db e leia os registros de arquivo (domain, relativePath, flags, fileID/hash)
2) Recrie a hierarquia original de pastas com base em domain + relativePath
3) Copie ou crie um hardlink de cada objeto armazenado para seu caminho reconstruído

Exemplo de fluxo de trabalho com uma ferramenta que implementa isso de ponta a ponta (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Lide com backups criptografados fornecendo a senha do backup ao seu extrator
- Preserve timestamps/ACLs originais quando possível para valor probatório


## Enumeração de anexos de apps de mensagens

Após a reconstrução, enumere os anexos dos apps mais populares. O esquema exato varia por app/versão, mas a abordagem é similar: consulte o banco de dados de mensagens, faça join entre message e attachment, e resolva os caminhos no disco.

### iMessage (sms.db)
Tabelas-chave: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Consultas de exemplo:
```sql
-- List attachments with basic message linkage
SELECT
m.ROWID            AS message_rowid,
a.ROWID            AS attachment_rowid,
a.filename         AS attachment_path,
m.handle_id,
m.date,
m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
c.display_name,
a.filename AS attachment_path,
m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```
Os caminhos dos anexos podem ser absolutos ou relativos à árvore reconstruída em Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Ligação comum: message table ↔ media/attachment table (os nomes variam conforme a versão). Consulte as linhas da tabela media para obter os caminhos no disco.

Exemplo (genérico):
```sql
SELECT
m.Z_PK          AS message_pk,
mi.ZMEDIALOCALPATH AS media_path,
m.ZMESSAGEDATE  AS message_date
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Adjust table/column names to your app version (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal: o DB de mensagens está criptografado; no entanto, anexos em cache no disco (e miniaturas) geralmente podem ser escaneados
- Telegram: inspecione os diretórios de cache (caches de foto/vídeo/documento) e mapeie para chats quando possível
- Viber: Viber.sqlite contém tabelas de mensagem/anexo com referências em disco

Dica: mesmo quando os metadados estão criptografados, escanear os diretórios media/cache ainda revela objetos maliciosos.


## Scanning attachments for structural exploits

Uma vez que você tenha caminhos de anexos, alimente-os em detectores estruturais que validam invariantes do formato de arquivo em vez de assinaturas. Exemplo com ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detecções cobertas por regras estruturais incluem:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados de dicionário JBIG2 impossíveis
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construções de tabelas Huffman superdimensionadas
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode não documentados
- DNG/TIFF CVE‑2025‑43300: incompatibilidades entre metadados e componentes de stream


## Validação, ressalvas e falsos positivos

- Conversões de tempo: iMessage armazena datas em Apple epochs/units em algumas versões; converta adequadamente ao relatar
- Deriva de esquema: schemas SQLite de apps mudam ao longo do tempo; confirme nomes de tabelas/colunas por build do dispositivo
- Extração recursiva: PDFs podem embutir streams JBIG2 e fontes; extraia e escaneie objetos internos
- Falsos positivos: heurísticas estruturais são conservadoras, mas podem sinalizar mídias raras malformadas porém benignas


## Referências

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
