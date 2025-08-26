# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 메시징 앱 첨부 파일을 통한 0‑click exploit 전달 흔적을 찾기 위해 iOS 백업을 복원하고 분석하는 실무적 절차를 설명합니다. Apple의 해시된 백업 레이아웃을 사람이 읽을 수 있는 경로로 변환한 다음, 일반 앱 전반의 첨부 파일을 열거하고 스캔하는 데 중점을 둡니다.

Goals:
- Manifest.db로부터 읽을 수 있는 경로 재구성
- 메시징 데이터베이스 열거 (iMessage, WhatsApp, Signal, Telegram, Viber)
- 첨부 파일 경로 해석, 포함된 객체 추출 (PDF/이미지/폰트), 및 구조 기반 탐지기에 전달


## Reconstructing an iOS backup

MobileSync 아래에 저장된 백업은 사람이 읽을 수 없는 해시된 파일명을 사용합니다. Manifest.db SQLite 데이터베이스는 각 저장된 객체를 논리적 경로에 매핑합니다.

High‑level procedure:
1) Manifest.db를 열어 파일 레코드 (domain, relativePath, flags, fileID/hash)를 읽습니다  
2) domain + relativePath를 기반으로 원래의 폴더 계층을 재구성합니다  
3) 각 저장된 객체를 복사하거나 하드링크하여 재구성된 경로에 배치합니다

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
참고:
- 암호화된 백업은 백업 비밀번호를 추출 도구에 제공하여 처리하세요
- 증거 가치를 위해 가능하면 원본 타임스탬프/ACL을 보존하세요


## 메시징 앱 첨부파일 열거

재구성 후, 인기 있는 앱들의 첨부파일을 열거하세요. 정확한 스키마는 앱/버전마다 다르지만 접근 방식은 유사합니다: 메시징 데이터베이스를 쿼리하고, 메시지를 첨부파일에 조인한 다음 디스크상의 경로를 확인합니다.

### iMessage (sms.db)
핵심 테이블: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
첨부 파일 경로는 절대 경로일 수도 있고, 재구성된 트리인 Library/SMS/Attachments/ 아래의 상대 경로일 수도 있습니다.

### WhatsApp (ChatStorage.sqlite)
일반적 연결: message table ↔ media/attachment table (이름은 버전마다 다름). on‑disk 경로를 얻기 위해 media 행을 쿼리하세요.

예시 (일반):
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
- Signal: 메시지 DB는 암호화되어 있지만, 디스크에 캐시된 첨부파일(및 썸네일)은 일반적으로 스캔 가능합니다
- Telegram: 캐시 디렉터리(사진/비디오/문서 캐시)를 검사하고 가능하면 채팅과 매핑하세요
- Viber: Viber.sqlite에는 message/attachment 테이블이 있으며 디스크상의 참조를 포함합니다

팁: 메타데이터가 암호화되어 있어도 media/cache 디렉터리를 스캔하면 악성 객체가 여전히 드러납니다.


## Scanning attachments for structural exploits

첨부파일 경로를 확보한 후에는, 서명(signatures) 대신 파일 포맷의 불변성(invariants)을 검증하는 구조적 탐지기(structural detectors)에 입력하세요. Example with ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
탐지 규칙(구조적 규칙)이 다루는 항목에는 다음이 포함됩니다:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 존재할 수 없는 JBIG2 사전 상태
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 과도하게 큰 허프만 테이블 구성
- TrueType TRIANGULATION (CVE‑2023‑41990): 문서화되지 않은 바이트코드 옵코드
- DNG/TIFF CVE‑2025‑43300: 메타데이터와 스트림 구성 요소 간 불일치


## 검증, 주의사항 및 오탐

- 시간 변환: 일부 버전에서 iMessage는 날짜를 Apple epoch/단위로 저장합니다; 보고 시 적절히 변환하세요
- Schema drift: 앱의 SQLite 스키마는 시간이 지나며 변경됩니다; 기기 빌드별 테이블/열 이름을 확인하세요
- Recursive extraction: PDFs는 JBIG2 스트림과 폰트를 포함할 수 있습니다; 내부 객체를 추출하여 스캔하세요
- False positives: 구조적 휴리스틱은 보수적이지만 드물게 손상되었지만 무해한 미디어를 표시할 수 있습니다


## 참고자료

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
