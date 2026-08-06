# Forensics de Backup do iOS (triagem focada em mensagens)

{{#include ../../banners/hacktricks-training.md}}

Esta página descreve etapas práticas para reconstruir e analisar backups do iOS em busca de sinais de entrega de exploits 0-click por meio de anexos de aplicativos de mensagens. O foco é transformar o layout hashado dos backups da Apple em caminhos legíveis e, em seguida, enumerar e verificar anexos em aplicativos comuns.

Objetivos:
- Reconstruir caminhos legíveis a partir do Manifest.db
- Enumerar bancos de dados de mensagens (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver caminhos de anexos, extrair objetos incorporados (PDF/Imagens/Fontes) e enviá-los para structural detectors


## Reconstruindo um backup do iOS

Os backups armazenados em MobileSync usam nomes de arquivo hashados que não são legíveis. O banco de dados SQLite Manifest.db mapeia cada objeto armazenado para seu caminho lógico.

Procedimento de alto nível:
1) Abrir o Manifest.db e ler os registros de arquivos (domain, relativePath, flags, fileID/hash)
2) Recriar a hierarquia de pastas original com base em domain + relativePath
3) Copiar ou criar um hardlink para cada objeto armazenado em seu caminho reconstruído

Exemplo de workflow com uma ferramenta que implementa esse processo de ponta a ponta (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Observações:
- Lide com backups criptografados fornecendo a senha do backup ao seu extrator
- Preserve os timestamps/ACLs originais sempre que possível para manter o valor probatório

### Aquisição e descriptografia do backup (USB / Finder / libimobiledevice)

- No macOS/Finder, marque "Encrypt local backup" e crie um backup criptografado *novo* para que os itens do keychain estejam presentes.
- Multiplataforma: `idevicebackup2` (libimobiledevice ≥1.4.0) entende as alterações no protocolo de backup do iOS 17/18 e corrige erros anteriores de handshake de restauração/backup.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triagem orientada por IOC com MVT

O Mobile Verification Toolkit (mvt-ios) da Amnesty agora funciona diretamente com backups criptografados do iTunes/Finder, automatizando a descriptografia e a correspondência de IOC em casos de spyware mercenário.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Os resultados são salvos em `mvt-results/` (por exemplo, `analytics_detected.json`, `safari_history_detected.json`) e podem ser correlacionados com os caminhos dos anexos recuperados abaixo.

### Análise geral de artefatos (iLEAPP)

Para obter uma timeline/metadados além das mensagens, execute o iLEAPP diretamente na pasta do backup (compatível com schemas do iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeração de anexos de aplicativos de mensagens

Após a reconstrução, enumere os anexos de aplicativos populares. O schema exato varia de acordo com o aplicativo/versão, mas a abordagem é semelhante: consultar o banco de dados de mensagens, associar mensagens a anexos e resolver os caminhos no disco.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tabelas principais: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Exemplos de consultas:
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
Vinculação comum: tabela de mensagens ↔ tabela de mídia/anexos (a nomenclatura varia conforme a versão). Consulte as linhas de mídia para obter os caminhos no disco. Versões recentes do iOS ainda expõem `ZMEDIALOCALPATH` em `ZWAMEDIAITEM`.
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
Os caminhos geralmente são resolvidos em `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` dentro do backup reconstruído.

### Signal / Telegram / Viber
- Signal: o message DB é criptografado; no entanto, os anexos armazenados em cache no disco (e as miniaturas) geralmente podem ser analisados
- Telegram: o cache permanece em `Library/Caches/` dentro do sandbox; builds do iOS 18 apresentam bugs na limpeza do cache, portanto grandes caches residuais de mídia são fontes comuns de evidências<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite contém tabelas de mensagens/anexos com referências no disco

Dica: mesmo quando os metadados estão criptografados, a análise dos diretórios de mídia/cache ainda revela objetos maliciosos.


## Analisando anexos em busca de exploits estruturais

Depois de obter os caminhos dos anexos, envie-os para structural detectors que validam invariantes do formato de arquivo em vez de assinaturas. Exemplo com ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detecções abrangidas pelas regras estruturais incluem:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados impossíveis de dicionários JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construções de tabelas Huffman grandes demais
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode não documentados
- DNG/TIFF CVE‑2025‑43300: incompatibilidades entre metadados e componentes do stream


## Validação, ressalvas e falsos positivos

- Conversões de tempo: o iMessage armazena datas usando epochs/unidades da Apple em algumas versões; converta adequadamente durante os relatórios
- Alterações de schema: os schemas SQLite dos aplicativos mudam com o tempo; confirme os nomes das tabelas/colunas de acordo com o build do dispositivo
- Extração recursiva: PDFs podem incorporar streams JBIG2 e fontes; extraia e analise os objetos internos
- Falsos positivos: heurísticas estruturais são conservadoras, mas podem sinalizar mídias raras, malformadas e benignas<sup>[[1]](#references)[[2]](#references)</sup>


## Referências

- [1] [ELEGANTBOUNCER: Quando você não pode obter as amostras, mas ainda precisa detectar a ameaça](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Projeto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Fluxo de trabalho de backup do MVT iOS](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Notas de versão do libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [A atualização 11.2 interrompeu a limpeza do cache no iOS 18.0.1 (Rastreador de bugs do Telegram)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
