# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 messaging app attachments를 통한 0-click exploit delivery의 흔적을 재구성하고 분석하기 위한 실용적인 iOS backup 분석 절차를 설명합니다. Apple의 hash 기반 backup layout을 사람이 읽을 수 있는 path로 변환한 다음, 일반적인 app 전체에서 attachments를 열거하고 스캔하는 데 중점을 둡니다.

목표:
- Manifest.db에서 읽을 수 있는 path 재구성
- messaging databases(iMessage, WhatsApp, Signal, Telegram, Viber) 열거
- attachment path 확인, 지원되는 경우 내장 objects(PDF/Images/Fonts) 추출 후 structural detectors에 전달


## iOS backup 재구성

MobileSync에 저장된 backup은 사람이 읽을 수 없는 hash filename을 사용합니다. SQLite database인 Manifest.db는 저장된 각 object를 logical path에 매핑합니다.<sup>[[1]](#references)[[2]](#references)</sup>

상위 수준의 절차:
1) Manifest.db를 열고 file records(domain, relativePath, flags, fileID/hash)를 읽습니다.
2) domain + relativePath를 기반으로 원래 folder hierarchy를 재생성합니다.
3) 각 저장된 object를 재구성된 path로 복사하거나 hardlink합니다.

이 전체 과정을 구현한 tool인 ElegantBouncer를 사용한 workflow 예시:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
참고:
- 암호화된 백업은 reconstruction tool에 전달하기 전에 복호화하세요. ElegantBouncer는 복호화된 백업을 필요로 합니다.<sup>[[2]](#references)[[3]](#references)</sup>
- 증거 가치를 위해 가능한 경우 원본 타임스탬프/ACL을 보존하세요.

### 백업 수집 및 복호화 (USB / Finder / libimobiledevice)

- Finder/Apple Devices/iTunes에서 "Encrypt local backup"을 활성화하고 새 백업을 생성하세요. 암호화된 백업에는 암호화되지 않은 백업에서 제외되는 저장된 암호와 Health 데이터가 포함될 수 있습니다.<sup>[[8]](#references)</sup>
- 크로스 플랫폼: libimobiledevice 1.4.0에는 `idevicebackup2` 수정 사항이 포함되어 있습니다.<sup>[[4]](#references)</sup> 대화형으로 암호화를 활성화한 다음, 문서에 명시된 명령 순서를 사용하여 전체 백업을 강제로 수행하세요. 대상 디렉터리는 마지막에 지정해야 합니다.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### MVT를 활용한 IOC 기반 triage

Amnesty의 Mobile Verification Toolkit은 암호화된 iTunes/Finder backup에서 key를 추출하고 이를 decrypt한 다음, STIX2 IOC 파일을 사용해 decrypt된 backup을 scan할 수 있습니다.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
`-o`를 사용하면 JSON 결과가 `/tmp/mvt-results/` 아래에 기록되며, IOC 일치 항목에는 `_detected` 접미사가 사용되어 아래에서 복구된 첨부 파일 경로와 상호 연관시킬 수 있습니다.<sup>[[3]](#references)</sup>

### 일반 아티팩트 파싱 (iLEAPP)

메시징 이외의 타임라인/메타데이터를 확인하려면 raw backup 폴더에 대해 iLEAPP를 실행합니다. iLEAPP의 `itunes` 입력 유형은 iTunes/Finder 백업을 허용하며, 최신 릴리스는 iOS/iPadOS 11부터 현재 버전까지 지원합니다.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

복원 후, 인기 있는 앱의 첨부 파일을 열거합니다. 정확한 스키마는 앱/버전에 따라 다르지만, 접근 방식은 유사합니다. 메시징 database를 쿼리하고, 메시지를 첨부 파일과 조인한 다음, 디스크에서 경로를 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
주요 테이블: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

예시 쿼리:
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
첨부 파일 경로는 절대 경로이거나 Library/SMS/Attachments 아래의 재구성된 트리 기준 상대 경로일 수 있습니다.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
일반적인 연결: message 테이블 ↔ media/attachment 테이블(버전에 따라 명칭이 다름). 디스크상의 경로를 얻으려면 media 행을 조회합니다. Belkasoft는 `ZWAMEDIAITEM`의 `ZMEDIALOCALPATH`를 미디어 파일 위치로 식별하며, ElegantBouncer의 현재 구현은 `ZWAMEDIAITEM.ZMESSAGE`를 `ZWAMESSAGE.Z_PK`에 조인하고 `Media/`로 시작하는 경로를 확인할 때 `Message/`를 앞에 추가합니다.<sup>[[9]](#references)[[10]](#references)</sup>
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
해당 ElegantBouncer reconstruction 경로에서 `Media/`로 시작하는 media path는 `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 아래로 resolve됩니다. Belkasoft의 guide에서는 대신 `Messages/Media/` path를 문서화하고 있으므로, 어느 spelling이 맞다고 가정하기 전에 backup을 검사하세요.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB는 암호화되어 있지만, disk에 cached된 attachments(및 thumbnails)는 일반적으로 스캔할 수 있습니다.<sup>[[2]](#references)</sup>
- Telegram: app의 media/cache directories를 검사하세요. Telegram은 iOS 18.0.1에서 iOS app 11.2의 cache-cleanup bug를 문서화했으며, 11.3에서 fixed된 것으로 표시했으므로 residual files를 확인하세요.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite에는 on-disk references가 포함된 message/attachment tables가 있습니다.<sup>[[2]](#references)</sup>

Tip: metadata가 암호화되어 있더라도 media/cache directories를 스캔하면 malicious objects가 여전히 발견됩니다.<sup>[[2]](#references)</sup>


## Scanning attachments for structural exploits

attachment paths를 확보한 후에는 signatures가 아니라 file-format invariants를 검증하는 structural detectors에 입력하세요. ElegantBouncer를 사용한 예시:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
구조적 규칙으로 탐지되는 항목은 다음과 같습니다:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 불가능한 JBIG2 dictionary 상태
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 지나치게 큰 Huffman table 생성
- TrueType TRIANGULATION (CVE‑2023‑41990): 문서화되지 않은 bytecode opcode
- DNG/TIFF CVE‑2025‑43300: metadata와 stream component 간 불일치


## 검증, 주의사항 및 false positives

- 시간 변환: 일부 버전에서 iMessage는 Apple epoch/unit으로 날짜를 저장하므로, 보고 시 적절히 변환해야 합니다.<sup>[[2]](#references)</sup>
- Schema drift: 앱 SQLite schema는 시간이 지나면서 변경되므로, device build별 table/column 이름을 확인해야 합니다.
- Recursive extraction: PDF에는 JBIG2 stream과 font가 포함될 수 있으므로, 내부 object를 추출하고 scan할 수 있는 parser를 사용해야 합니다.
- False positives: 구조적 heuristic은 보수적으로 설계되었지만, 드물게 손상된 정상 media를 탐지할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [샘플을 확보할 수 없지만 여전히 위협을 탐지해야 할 때: ELEGANTBOUNCER](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 manual](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP project (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [iPhone, iPad 또는 iPod touch의 암호화된 backup 정보 (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Belkasoft X를 사용한 iOS WhatsApp Forensics](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner 및 path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
