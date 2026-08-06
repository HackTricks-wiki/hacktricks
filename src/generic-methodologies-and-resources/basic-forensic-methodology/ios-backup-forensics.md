# iOS Backup Forensics (Messaging 중심 triage)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 messaging app attachments를 통한 0-click exploit 전달 흔적을 확인하기 위해 iOS backups를 재구성하고 분석하는 실용적인 단계를 설명합니다. Apple의 hashed backup layout을 사람이 읽을 수 있는 경로로 변환한 다음, 일반적인 앱 전반에서 attachments를 열거하고 scanning하는 데 중점을 둡니다.

목표:
- Manifest.db에서 읽을 수 있는 경로 재구성
- messaging databases(iMessage, WhatsApp, Signal, Telegram, Viber) 열거
- attachment paths 확인, 내장 객체(PDF/이미지/폰트) 추출 및 structural detectors에 전달


## iOS backup 재구성

MobileSync에 저장된 backups는 사람이 읽을 수 없는 hashed filenames를 사용합니다. Manifest.db SQLite database는 저장된 각 object를 logical path에 매핑합니다.

상위 수준의 절차:
1) Manifest.db를 열고 file records(domain, relativePath, flags, fileID/hash)를 읽습니다.
2) domain + relativePath를 기반으로 원래 folder hierarchy를 재구성합니다.
3) 저장된 각 object를 재구성된 경로에 복사하거나 hardlink합니다.

이 과정을 end-to-end로 구현한 tool(ElegantBouncer)을 사용하는 workflow 예시:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
참고:
- extractor에 백업 비밀번호를 제공하여 암호화된 백업을 처리
- 증거로서의 가치를 위해 가능한 경우 원본 타임스탬프/ACL을 보존

### 백업 획득 및 복호화 (USB / Finder / libimobiledevice)

- macOS/Finder에서 "Encrypt local backup"을 설정하고 새로운 암호화된 백업을 생성하여 keychain 항목이 포함되도록 합니다.
- 크로스 플랫폼: `idevicebackup2` (libimobiledevice ≥1.4.0)는 iOS 17/18 백업 프로토콜 변경을 이해하며, 이전 버전의 복원/백업 핸드셰이크 오류를 수정합니다.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### MVT를 활용한 IOC 기반 선별 분석

Amnesty의 Mobile Verification Toolkit (mvt-ios)은 이제 암호화된 iTunes/Finder 백업에서 직접 작동하여, 용병형 스파이웨어 사건에 대한 복호화와 IOC 매칭을 자동화합니다.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
출력은 `mvt-results/`에 저장되며(예: analytics_detected.json, safari_history_detected.json), 아래에서 복구한 attachment paths와 상호 연관 분석할 수 있습니다.

### 일반 artifact parsing (iLEAPP)

messaging 외의 timeline/metadata를 분석하려면 백업 폴더에서 iLEAPP를 직접 실행합니다(iOS 11‑17 schemas 지원):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

복원 후 인기 앱의 attachment를 열거합니다. 정확한 schema는 앱/버전에 따라 다르지만, 접근 방식은 유사합니다. messaging database를 조회하고, messages와 attachments를 join한 뒤, 디스크의 경로를 확인합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
주요 테이블: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
첨부 파일 경로는 절대 경로이거나 Library/SMS/Attachments/ 아래에 재구성된 트리에 대한 상대 경로일 수 있습니다.

### WhatsApp (ChatStorage.sqlite)
일반적인 연결 관계: message 테이블 ↔ media/attachment 테이블(버전에 따라 명칭이 다름). 디스크상의 경로를 확인하려면 media 행을 조회합니다. 최신 iOS 빌드에서도 여전히 `ZWAMEDIAITEM`의 `ZMEDIALOCALPATH`가 노출됩니다.
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
경로는 일반적으로 재구성된 backup 내부의 `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 아래에서 확인됩니다.

### Signal / Telegram / Viber
- Signal: message DB는 암호화되어 있지만, 디스크에 캐시된 attachments(및 thumbnails)는 일반적으로 scan할 수 있습니다.
- Telegram: cache는 sandbox 내부의 `Library/Caches/` 아래에 남아 있습니다. iOS 18 builds에서는 cache-clearing bugs가 나타나므로, 대규모 잔여 media caches가 흔한 evidence source입니다<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite에는 message/attachment tables와 디스크상의 references가 포함되어 있습니다.

Tip: metadata가 암호화되어 있더라도 media/cache directories를 scan하면 malicious objects가 여전히 발견됩니다.


## structural exploits에 대한 attachments scanning

attachment paths를 확보한 후에는 signatures가 아니라 file-format invariants를 검증하는 structural detectors에 입력합니다. ElegantBouncer 사용 예:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Structural rules가 다루는 탐지 항목은 다음과 같습니다:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 불가능한 JBIG2 dictionary 상태
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 과도하게 큰 Huffman table 구성
- TrueType TRIANGULATION (CVE‑2023‑41990): 문서화되지 않은 bytecode opcode
- DNG/TIFF CVE‑2025‑43300: metadata와 stream component 간 불일치


## 검증, 주의 사항 및 false positive

- Time conversions: 일부 버전에서 iMessage는 Apple epoch/unit으로 날짜를 저장하므로, 보고 시 적절히 변환해야 합니다
- Schema drift: 앱 SQLite schema는 시간이 지나면서 변경되므로, 각 device build에 맞는 table/column 이름을 확인해야 합니다
- Recursive extraction: PDF에는 JBIG2 stream과 font가 포함될 수 있으므로, 내부 object를 추출하고 scan해야 합니다
- False positives: structural heuristic는 보수적으로 설계되었지만, 드물게 손상된 정상 media를 탐지할 수 있습니다<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: 샘플을 확보할 수 없지만 여전히 위협을 탐지해야 할 때](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
