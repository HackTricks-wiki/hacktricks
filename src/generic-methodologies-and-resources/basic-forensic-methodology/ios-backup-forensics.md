# iOS 백업 포렌식 (메시징 중심 트리아지)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 메시징 앱 첨부파일을 통한 0‑click 익스플로잇 전달 징후를 재구성하고 분석하기 위한 iOS 백업 실무 단계를 설명합니다. Apple의 해시된 백업 레이아웃을 사람이 읽을 수 있는 경로로 변환한 후, 일반적인 앱 전반의 첨부파일을 열거하고 스캔하는 데 중점을 둡니다.

Goals:
- Manifest.db에서 읽을 수 있는 경로 복원
- 메시징 데이터베이스 나열 (iMessage, WhatsApp, Signal, Telegram, Viber)
- 첨부 파일 경로 해석, 임베디드 객체(PDF/Images/Fonts) 추출, 구조적 탐지기로 전송


## iOS 백업 재구성

MobileSync 아래에 저장된 백업은 사람이 읽을 수 없는 해시된 파일명을 사용합니다. Manifest.db SQLite 데이터베이스는 각 저장된 객체를 논리적 경로와 매핑합니다.

고수준 절차:
1) Manifest.db를 열어 파일 레코드 (domain, relativePath, flags, fileID/hash)를 읽습니다
2) domain + relativePath를 기반으로 원래의 폴더 계층 재구성
3) 각 저장된 객체를 재구성된 경로로 복사하거나 hardlink 생성

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
참고:
- 암호화된 백업은 백업 암호를 추출 도구에 제공하여 처리하세요
- 증거 가치를 위해 가능하면 원본 타임스탬프/ACL을 보존하세요

### 백업 획득 및 복호화 (USB / Finder / libimobiledevice)

- On macOS/Finder에서 "Encrypt local backup"을 설정하고 키체인 항목이 포함되도록 *새로운* 암호화된 백업을 생성하세요.
- 크로스 플랫폼: `idevicebackup2` (libimobiledevice ≥1.4.0)은 iOS 17/18 백업 프로토콜 변경을 이해하고 이전의 복원/백업 핸드셰이크 오류를 수정합니다.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### MVT로 수행하는 IOC‑기반 분류

Amnesty’s Mobile Verification Toolkit (mvt-ios)는 이제 암호화된 iTunes/Finder 백업에서 직접 작동하여, 상업용 스파이웨어 사례에 대한 복호화 및 IOC 매칭을 자동화합니다.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
출력은 `mvt-results/`에 저장되며(예: analytics_detected.json, safari_history_detected.json), 아래에서 복구된 첨부 파일 경로와 연관시킬 수 있습니다.

### 일반 아티팩트 파싱 (iLEAPP)

메시징을 넘어선 타임라인/메타데이터는 백업 폴더에서 직접 iLEAPP를 실행하여 수집하세요 (iOS 11‑17 스키마 지원):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## 메시징 앱 첨부파일 열거

재구성 후, 인기 앱들의 첨부파일을 열거한다. 스키마는 앱/버전마다 다르지만 접근 방식은 유사하다: 메시징 데이터베이스를 query하고, 메시지와 첨부파일을 join하며, 디스크상의 경로를 resolve한다.

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

예제 쿼리:
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
첨부 파일 경로는 Library/SMS/Attachments/ 아래의 복원된 트리를 기준으로 절대 경로이거나 상대 경로일 수 있습니다.

### WhatsApp (ChatStorage.sqlite)
일반적인 연결: message 테이블 ↔ media/attachment 테이블(명칭은 버전별로 다름). 미디어 행을 쿼리하여 디스크상의 경로를 얻습니다. 최근 iOS 빌드에서는 여전히 `ZMEDIALOCALPATH`가 `ZWAMEDIAITEM`에 노출됩니다.
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
Paths usually resolve under `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` inside the reconstructed backup.

### Signal / Telegram / Viber
- Signal: 메시지 DB는 암호화되어 있습니다; 그러나 디스크에 캐시된 첨부파일(및 썸네일)은 대개 스캔 가능합니다
- Telegram: 캐시는 sandbox 내부의 `Library/Caches/`에 남아 있습니다; iOS 18 빌드에서 캐시 정리 버그가 있어 대규모 잔류 미디어 캐시가 흔한 증거원이 됩니다
- Viber: Viber.sqlite에는 디스크상의 참조를 가진 메시지/첨부 테이블이 포함되어 있습니다

Tip: 메타데이터가 암호화되어 있어도 미디어/캐시 디렉터리를 스캔하면 악성 객체가 여전히 드러납니다.


## Scanning attachments for structural exploits

한 번 첨부파일 경로를 확보하면, 시그니처 대신 파일 포맷의 불변성을 검증하는 구조적 탐지기에 입력하세요. ElegantBouncer 예:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 불가능한 JBIG2 딕셔너리 상태
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 과도하게 큰 Huffman 테이블 구성
- TrueType TRIANGULATION (CVE‑2023‑41990): 문서화되지 않은 bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: 메타데이터와 스트림 구성요소 간 불일치


## 검증, 주의사항 및 오탐

- 시간 변환: iMessage는 일부 버전에서 날짜를 Apple epochs/units로 저장합니다; 보고 시 적절히 변환하세요
- 스키마 변경: 앱의 SQLite 스키마는 시간이 지나며 변경됩니다; 디바이스 빌드별로 테이블/컬럼 이름을 확인하세요
- 재귀적 추출: PDFs는 JBIG2 스트림과 폰트를 포함할 수 있습니다; 내부 객체를 추출해 스캔하세요
- 오탐: 구조적 휴리스틱은 보수적이지만 드물게 손상되었지만 무해한 미디어를 표시할 수 있습니다


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
