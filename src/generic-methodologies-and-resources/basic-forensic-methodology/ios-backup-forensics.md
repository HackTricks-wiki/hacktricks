# iOS Backup Forensics (Triagem centrada em mensagens)

{{#include ../../banners/hacktricks-training.md}}

Esta página descreve passos práticos para reconstruir e analisar backups iOS em busca de sinais de entrega de exploit 0‑click via anexos de apps de mensagens. Foca em transformar o layout de backup com nomes hash da Apple em caminhos legíveis, e em seguida enumerar e escanear anexos em apps comuns.

Objetivos:
- Reconstruir caminhos legíveis a partir de Manifest.db
- Enumerar bancos de dados de mensagens (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver caminhos de anexos, extrair objetos incorporados (PDF/Imagens/Fontes) e submetê‑los a detectores estruturais


## Reconstruindo um backup iOS

Backups armazenados sob MobileSync usam nomes de arquivo com hash que não são legíveis. O banco de dados SQLite Manifest.db mapeia cada objeto armazenado para seu caminho lógico.

Procedimento geral:
1) Abra o Manifest.db e leia os registros de arquivos (domain, relativePath, flags, fileID/hash)
2) Recrie a hierarquia de pastas original com base em domain + relativePath
3) Copie ou crie hardlink de cada objeto armazenado para seu caminho reconstruído

Exemplo de fluxo de trabalho com uma ferramenta que implementa isso de ponta a ponta (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Trate backups criptografados fornecendo a senha do backup para sua ferramenta de extração
- Preserve os timestamps/ACLs originais quando possível para fins probatórios

### Adquirindo & descriptografando o backup (USB / Finder / libimobiledevice)

- No macOS/Finder, ative "Encrypt local backup" e crie um backup criptografado *novo* para que os itens do keychain estejam presentes.
- Multiplataforma: `idevicebackup2` (libimobiledevice ≥1.4.0) entende as mudanças no protocolo de backup do iOS 17/18 e corrige erros de handshake em restore/backup anteriores.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triagem orientada por IOC com MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) agora funciona diretamente em backups criptografados do iTunes/Finder, automatizando a descriptografia e a correspondência de IOC para casos de spyware mercenário.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Os resultados são colocados em `mvt-results/` (por exemplo, analytics_detected.json, safari_history_detected.json) e podem ser correlacionados com os caminhos dos anexos recuperados abaixo.

### Análise geral de artefatos (iLEAPP)

Para linha do tempo/metadados além de mensagens, execute o iLEAPP diretamente na pasta de backup (suporta esquemas iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeração de anexos de apps de mensagens

Após a reconstrução, enumere os anexos para aplicativos populares. O esquema exato varia por aplicativo/versão, mas a abordagem é similar: consultar o banco de dados de mensagens, relacionar mensagens com anexos e resolver caminhos no disco.

### iMessage (sms.db)
Tabelas principais: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Vinculação comum: tabela de mensagens ↔ tabela de mídia/anexos (a nomenclatura varia conforme a versão). Consulte as linhas de mídia para obter os caminhos no disco. Builds recentes do iOS ainda expõem `ZMEDIALOCALPATH` em `ZWAMEDIAITEM`.
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Os caminhos normalmente resolvem em `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` dentro do backup reconstruído.

### Signal / Telegram / Viber
- Signal: o DB de mensagens está criptografado; no entanto, anexos armazenados em cache no disco (e miniaturas) geralmente podem ser escaneados
- Telegram: o cache permanece em `Library/Caches/` dentro do sandbox; builds do iOS 18 exibem bugs de limpeza de cache, então grandes caches residuais de mídia são fontes comuns de evidência
- Viber: Viber.sqlite contém tabelas de mensagens/anexos com referências em disco

Dica: mesmo quando os metadados estão criptografados, escanear os diretórios de mídia/cache ainda revela objetos maliciosos.


## Escaneando anexos para exploits estruturais

Depois de obter os caminhos dos anexos, passe-os por detectores estruturais que validam invariantes de formato de arquivo em vez de assinaturas. Exemplo com ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detecções cobertas por regras estruturais incluem:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados de dicionário JBIG2 impossíveis
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construções de tabelas de Huffman sobredimensionadas
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode não documentados
- DNG/TIFF CVE‑2025‑43300: incompatibilidades entre metadados e componentes de fluxo


## Validação, ressalvas e falsos positivos

- Conversões de tempo: o iMessage armazena datas em epochs/unidades da Apple em algumas versões; converta adequadamente ao relatar
- Deriva de schema: schemas SQLite de apps mudam ao longo do tempo; confirme nomes de tabelas/colunas por build do dispositivo
- Extração recursiva: PDFs podem incorporar streams JBIG2 e fontes; extraia e escaneie objetos internos
- Falsos positivos: heurísticas estruturais são conservadoras, mas podem sinalizar mídias raras malformadas porém benignas


## Referências

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
