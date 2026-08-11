# Forense de Backup do iOS (triagem focada em mensagens)

{{#include ../../banners/hacktricks-training.md}}

Esta página descreve etapas práticas para reconstruir e analisar backups do iOS em busca de sinais de entrega de exploit 0-click por meio de anexos de aplicativos de mensagens. O foco é transformar o layout com hashes dos backups da Apple em caminhos legíveis e, em seguida, enumerar e verificar anexos em aplicativos comuns.

Objetivos:
- Reconstruir caminhos legíveis a partir do Manifest.db
- Enumerar bancos de dados de mensagens (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolver caminhos de anexos, extrair objetos incorporados quando houver suporte (PDF/Images/Fonts) e encaminhá-los para detectores estruturais


## Reconstruindo um backup do iOS

Os backups armazenados no MobileSync usam nomes de arquivo com hashes que não são legíveis por humanos. O banco de dados SQLite Manifest.db mapeia cada objeto armazenado para seu caminho lógico.<sup>[[1]](#references)[[2]](#references)</sup>

Procedimento de alto nível:
1) Abrir o Manifest.db e ler os registros de arquivos (domain, relativePath, flags, fileID/hash)
2) Recriar a hierarquia original de pastas com base em domain + relativePath
3) Copiar ou criar um hardlink de cada objeto armazenado para seu caminho reconstruído

Exemplo de workflow com uma ferramenta que implementa esse processo de ponta a ponta (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- Descriptografe os backups criptografados antes de passá-los a uma ferramenta de reconstrução; ElegantBouncer espera um backup descriptografado.<sup>[[2]](#references)[[3]](#references)</sup>
- Preserve os timestamps/ACLs originais sempre que possível para valor probatório

### Aquisição e descriptografia do backup (USB / Finder / libimobiledevice)

- No Finder/Apple Devices/iTunes, ative "Criptografar backup local" e crie um novo backup; os backups criptografados podem incluir senhas salvas e dados do app Saúde que os backups não criptografados omitem.<sup>[[8]](#references)</sup>
- Multiplataforma: libimobiledevice 1.4.0 inclui correções para `idevicebackup2`.<sup>[[4]](#references)</sup> Ative a criptografia interativamente e, em seguida, force um backup completo usando a ordem de comandos documentada, com o diretório de destino por último.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triagem orientada por IOC com MVT

O Mobile Verification Toolkit da Amnesty pode extrair uma chave e descriptografar backups criptografados do iTunes/Finder e, em seguida, verificar o backup descriptografado com um arquivo IOC STIX2.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Com `-o`, os resultados em JSON são gravados em `/tmp/mvt-results/`; as correspondências de IOC usam o sufixo `_detected` e podem ser correlacionadas com os caminhos dos anexos recuperados abaixo.<sup>[[3]](#references)</sup>

### Análise geral de artefatos (iLEAPP)

Para obter informações de linha do tempo/metadados além das mensagens, execute o iLEAPP na pasta de backup bruta; seu tipo de entrada `itunes` aceita backups do iTunes/Finder, e as versões atuais oferecem suporte ao iOS/iPadOS 11 até as versões atuais.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeração de anexos de aplicativos de mensagens

Após a reconstrução, enumere os anexos de aplicativos populares. O esquema exato varia conforme o aplicativo/versão, mas a abordagem é semelhante: consulte o banco de dados de mensagens, faça a junção entre mensagens e anexos e resolva os caminhos no disco.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tabelas principais: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Os caminhos dos anexos podem ser absolutos ou relativos à árvore reconstruída em Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Vinculação comum: tabela de mensagens ↔ tabela de mídia/anexos (a nomenclatura varia conforme a versão). Consulte as linhas de mídia para obter os caminhos no disco. O Belkasoft identifica `ZMEDIALOCALPATH` em `ZWAMEDIAITEM` como a localização do arquivo de mídia; a implementação atual do ElegantBouncer faz a junção de `ZWAMEDIAITEM.ZMESSAGE` com `ZWAMESSAGE.Z_PK` e adiciona `Message/` ao resolver um caminho que começa com `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Para esse caminho de reconstrução do ElegantBouncer, um caminho de mídia que começa com `Media/` é resolvido em `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; o guia da Belkasoft, por outro lado, documenta um caminho `Messages/Media/`, portanto, inspecione o backup antes de presumir qualquer uma das grafias.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: o DB de mensagens é criptografado; no entanto, os anexos armazenados em cache no disco (e as miniaturas) geralmente podem ser escaneados.<sup>[[2]](#references)</sup>
- Telegram: inspecione os diretórios de mídia/cache do app; o Telegram documentou um bug de limpeza de cache no app iOS 11.2 no iOS 18.0.1, marcado como corrigido na versão 11.3, portanto, verifique se há arquivos residuais.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite contém tabelas de mensagens/anexos com referências no disco.<sup>[[2]](#references)</sup>

Dica: mesmo quando os metadados estão criptografados, a varredura dos diretórios de mídia/cache ainda revela objetos maliciosos.<sup>[[2]](#references)</sup>


## Verificando anexos em busca de explorações estruturais

Depois de obter os caminhos dos anexos, forneça-os a detectores estruturais que validam invariantes do formato de arquivo em vez de assinaturas. Exemplo com ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detecções abrangidas pelas regras estruturais incluem:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): estados impossíveis do dicionário JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): construções de tabelas Huffman superdimensionadas
- TrueType TRIANGULATION (CVE‑2023‑41990): opcodes de bytecode não documentados
- DNG/TIFF CVE‑2025‑43300: incompatibilidades entre metadados e componentes do stream


## Validação, ressalvas e falsos positivos

- Conversões de tempo: o iMessage armazena datas em épocas/unidades da Apple em algumas versões; converta-as adequadamente durante a geração do relatório.<sup>[[2]](#references)</sup>
- Alteração de schema: os schemas SQLite dos aplicativos mudam ao longo do tempo; confirme os nomes das tabelas/colunas de acordo com o build do dispositivo
- Extração recursiva: PDFs podem incorporar streams JBIG2 e fontes; use um parser que consiga extrair e verificar objetos internos
- Falsos positivos: heurísticas estruturais são conservadoras, mas podem sinalizar mídias raras, malformadas porém benignas.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Quando você não consegue obter as amostras, mas ainda precisa detectar a ameaça](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [Projeto ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [Fluxo de trabalho de backup do MVT iOS](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Notas de versão do libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [A atualização 11.2 interrompeu a limpeza do cache no iOS 18.0.1 (Rastreador de bugs do Telegram)](https://bugs.telegram.org/c/44361)
- [6] [Manual do idevicebackup2](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [Projeto iLEAPP (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Sobre backups criptografados no iPhone, iPad ou iPod touch (Suporte da Apple)](https://support.apple.com/en-ie/108353)
- [9] [Forense do WhatsApp no iOS com o Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [Scanner do WhatsApp e resolvedor de caminhos do ElegantBouncer](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
