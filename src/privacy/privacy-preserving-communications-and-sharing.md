# Privacy-Preserving Communications and Sharing

{{#include ../banners/hacktricks-training.md}}

End-to-end encryption은 콘텐츠를 보호합니다. 하지만 계정, 전화번호, 연락처 그래프, IP 주소, push token, notification preview, 타이밍, 파일 metadata 또는 수신자의 동작을 자동으로 숨기지는 않습니다. 도구는 제거하는 metadata와 새로 노출시키는 관찰자를 기준으로 선택하세요.

## Compare communication models

| Tool/model | 유용한 특성 | 남아 있는 관찰자와 한계 |
|---|---|---|
| Signal | 성숙한 E2EE; username으로 번호를 공유하지 않고 연락 시작 가능; sealed sender가 service metadata를 줄임 | 등록에 전화번호 필요; service, push provider, 연락처 및 endpoint에 일부 관찰 정보가 남음 |
| SimpleX | 전역 user identifier 없음; contact별 queue; 선택적 Tor transport | relay 타이밍/transport, push service, invitation 및 endpoint; 더 새롭고 작은 생태계 |
| Briar | 직접 synchronization; 온라인에서는 Tor; 오프라인에서는 Bluetooth/Wi-Fi; 중앙 message store 없음 | 연락처 및 endpoint; local radio 관찰자; Android 중심; 양쪽 모두 사용 가능해야 하며, 그렇지 않으면 Mailbox 사용 |
| OnionShare | 임시 onion service를 통한 직접 file/receive/chat/site; storage provider 없음 | sender computer가 service 역할을 함; link를 가진 사람이 access를 알 수 있음; 타이밍과 endpoint는 남음 |
| `age` encrypted file | transport와 독립적인 간단한 recipient-key encryption | transport에서 sender/recipient/timing/size를 볼 수 있음; filename/archive metadata 및 endpoint는 남음 |
| 일반 email + TLS | server-to-server channel encryption | 일반적으로 두 mail provider 모두 콘텐츠를 읽고 routing/account metadata를 보존할 수 있음 |

## Signal: 번호를 공개하지 않는 비공개 연락

Signal username은 새 연락처에 사용자의 전화번호를 공개하지 않고 chat을 시작할 수 있게 하지만, 등록에는 여전히 전화번호가 필요합니다.<sup>[[1]](#references)</sup> Sealed sender는 점진적인 metadata 보호 기능이며, 모든 IP/timing correlation에 대한 저항 기능은 아닙니다.<sup>[[2]](#references)</sup>

### Workflow

1. 공식 app store/project에서 Signal을 설치하고 먼저 OS를 업데이트합니다.
2. 합법적으로 사용할 권리가 있는 번호로 등록합니다. 임대한 SMS activation, 다른 사람의 번호 또는 허위 신원으로 획득한 provider account를 사용하지 마세요.
3. **Settings → Privacy → Phone Number**에서 threat model에 따라 누가 번호를 볼 수 있는지, 누가 번호로 account를 찾을 수 있는지를 설정합니다.
4. 새 연락처 검색을 위해 username을 생성합니다. 이미 authentication된 channel을 통해 정확한 link/QR을 공유합니다. username은 변경될 수 있으며 profile name이 아닙니다.
5. 편의성보다 linkage 방지가 중요하다면 contact upload/permission을 비활성화하고, platform이 지원하는 경우 연락처를 수동으로 추가합니다.
6. 민감한 콘텐츠를 보내기 전에 연락처 세부 정보를 열고 두 번째 channel 또는 대면 방식으로 safety number/QR을 비교합니다.
7. linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults 및 backup 동작을 검토합니다.
8. 민감하지 않은 test message를 보내고 통화합니다. 양쪽의 lock-screen, desktop, wearable 및 cloud-notification trace를 확인합니다.
9. 변경된 safety number 또는 예상하지 못한 linked device는 자동으로 무시할 alert가 아니라 조사해야 하는 사건으로 취급합니다.

가명 profile photo, bio, group membership 또는 schedule을 식별 가능한 Signal context와 함께 사용하지 마세요.

## SimpleX: 전역 identifier 없는 contact별 connection

SimpleX는 단방향 queue를 통해 message를 routing하며 network-wide user identifier를 할당하지 않습니다. 자체 policy에도 transport session, 임시 server data, push-notification tradeoff 및 endpoint 책임이 명시되어 있습니다.<sup>[[3]](#references)</sup>

### Workflow

1. 공식 project/store에서 유지 관리되는 client를 다운로드하고 publisher를 확인합니다. identity를 분리해야 한다면 전용 OS/app profile을 사용합니다.
2. context에 맞는 display name과 image를 사용하는 **local** profile을 생성합니다. backup 없이 app을 삭제하면 profile과 connection을 잃을 수 있습니다.
3. 최초 실행 시 notification mode를 신중하게 선택합니다. 즉시 mobile push를 사용하면 Apple/Google infrastructure에 추가 metadata가 노출될 수 있습니다.
4. 한 연락처를 위한 일회성 invitation link를 생성합니다. authentication된 channel을 통해 전달하며, 유효한 invitation을 획득한 누구나 사용을 시도할 수 있습니다.
5. 연결한 후 contact details를 열고 대면 또는 독립적으로 검증된 channel을 통해 security code를 비교합니다.<sup>[[4]](#references)</sup>
6. 지원되는 경우 서로 관련 없는 group에서 같은 profile을 재사용하는 대신 incognito per-group profile을 사용합니다.
7. local network/server가 direct IP를 보지 않아야 한다면 client가 지원하는 Tor transport를 설정합니다. 변경 후 connection을 확인하며, 지원되지 않는 system proxy를 강제로 사용하지 마세요.
8. delivery receipt, link preview, call, automatic download 및 database export/backup을 검토합니다. 각각 metadata 또는 endpoint 노출을 변경합니다.
9. 중복된 live profile state를 실행하지 않는 예비 격리 device에서 recovery를 테스트합니다. project는 동시에 실행되는 복사본이 conversation을 방해할 수 있다고 경고합니다.

전역 identifier가 없더라도 콘텐츠, profile 재사용, invitation 전달, 타이밍 또는 social graph를 통해 연락처가 사용자를 식별하는 것은 막을 수 없습니다.

## Briar: 직접적이고 disruption-resistant한 messaging

Briar는 device 간에 직접 synchronization하며, 온라인에서는 Tor를 통해, local outage 중에는 Bluetooth/Wi-Fi를 통해 동작합니다. 공식 threat model은 short-range radio에 대한 제한적인 adversarial monitoring만을 가정하므로 local wireless는 보이지 않는 것이 아닙니다.<sup>[[5]](#references)</sup>

### Workflow

1. 공식 Briar distribution에서 설치하고 package source를 확인합니다. 최신 security update가 적용된 지원 Android device를 사용합니다.
2. 고유한 context nickname과 강력한 password로 local account를 생성합니다. password-reset 경로가 없으므로 unlock secret을 복구할 수 있는지 테스트합니다.
3. 가능하면 서로의 QR code를 scan하여 대면으로 연락처를 추가합니다. 이는 연락처를 authentication하고 correlation 가능한 channel을 통한 link 전송을 피합니다.
4. connectivity settings에서 필요한 transport만 활성화합니다: Tor/Internet, Wi-Fi 및/또는 Bluetooth. 필요하지 않을 때는 local radio를 비활성화합니다.
5. 비동기 delivery를 위해 전원이 연결된 전용 device에서 Briar Mailbox를 평가합니다. message server처럼 inventory를 관리하고 물리적으로 보호합니다.
6. Internet을 사용할 수 있을 때 무해한 test를 전송한 뒤, 소유자가 승인한 장소에서 Internet을 비활성화하고 계획된 outage 경로를 테스트합니다.
7. Android backup, notification preview, screenshot 및 exported content를 확인합니다. endpoint가 unlock/compromise되면 local encrypted storage가 노출됩니다.
8. 분실한 contact/device를 제거하고 물리적 관리 권한 또는 account password가 compromise되었다면 전체 context를 폐기합니다.

## OnionShare: 직접적인 임시 전송

OnionShare는 sender/receiver computer에서 onion service를 실행합니다. 파일은 storage provider에 upload되지 않으며 traffic은 Tor 내부에서 end-to-end encrypted됩니다.<sup>[[6]](#references)</sup> 전체 onion URL은 bearer capability이므로 보호해야 합니다.

### GUI file-sharing workflow

1. 공식 서명 distribution에서 OnionShare를 설치하고 recipient 측에 Tor Browser를 설치합니다.
2. 파일의 **sanitized copies**를 전용 staging directory에 넣습니다. OnionShare가 개인 home directory를 가리키도록 하지 마세요.
3. **Share Files**를 열고 staging된 파일만 추가합니다. private key/access protection은 활성화된 상태로 두고, 한 명의 recipient를 위해 **Stop sharing after files have been sent**를 활성화합니다.
4. sharing을 시작하고 이미 authentication된 E2EE channel을 통해 전체 onion URL을 전송합니다. email, issue tracker 또는 public chat에 붙여 넣지 마세요.
5. recipient는 Tor Browser에서 URL을 열고 sender와 예상한 filename/size를 확인한 뒤 download합니다.
6. 파일 자체가 security boundary인 경우 양쪽에서 사전에 합의했거나 별도로 전달한 SHA-256 digest를 비교하여 integrity를 확인합니다.
7. download 후 OnionShare가 중지되었는지 확인합니다. 그렇지 않으면 수동으로 중지하고 application을 종료합니다.
8. retention policy에 따라 staging copy를 삭제하고 OnionShare history/log settings에서 의도하지 않은 filename disclosure가 있는지 확인합니다.

### CLI workflow

공식 CLI는 positional argument로 파일을 받고, 기본적으로 한 번의 완료된 share 후 중지합니다. 공식 CLI/Tor가 설치된 host에서:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
결과로 생성된 전체 URL을 안전하게 전달하세요. 위협 모델이 결과로 노출되는 정보를 명시적으로 요구하지 않는 한 `--public`, `--no-autostop-sharing`, 상세 파일 이름 logging 또는 persistence를 추가하지 마세요.<sup>[[7]](#references)</sup>

수신한 문서는 악성으로 간주하세요. 신원을 식별할 수 있는 host에서 여는 대신, 폐기 가능한 VM 또는 Dangerzone-style renderer에서 여세요.

## `age`로 파일을 독립적으로 암호화

storage/email provider가 객체를 볼 수 있는 경우, 전송 방식과 무관한 암호화가 유용합니다. 하지만 발신자, 수신자, 크기, 타이밍 또는 파일 이름을 별도로 처리하지 않는 한 이를 숨기지는 못합니다.

### 수신자 설정
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
두 번째 채널을 통해 공개 수신자 문자열을 인증합니다. 그런 다음 sender가 다음을 실행합니다:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
수신자는 새 경로로 복호화합니다:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
공식 CLI는 `-o`가 기존 출력을 덮어쓴다고 경고하므로, 새 디렉터리를 사용하고 이동하기 전에 digest/content를 확인하세요.<sup>[[8]](#references)</sup> 암호문과 함께 identity file을 절대 보내지 마세요.

## 재현 가능한 파일 sanitization pipeline

메타데이터 제거는 형식에 따라 다릅니다. 진위성, 포렌식 또는 chain of custody가 중요한 경우 암호화된 원본을 보존하고 사본에서 작업하세요.

### JPEG 예시
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
이는 ExifTool의 더 안전한 JPEG 지침을 따릅니다. 모든 태그를 무작정 제거하면 색상 정보도 함께 삭제될 수 있습니다.<sup>[[9]](#references)</sup> 그런 다음 얼굴, 반사, 화면, 랜드마크, 고유한 손상/노이즈 패턴이 있는지 픽셀을 시각적으로 검사합니다.

### Office/PDF 작업 흐름

1. 편집 가능한 원본은 암호화하고 게시 환경과 분리된 오프라인 상태로 보관합니다.
2. 작성 애플리케이션에서 댓글, 변경 내용 추적, 숨겨진 슬라이드/시트, 포함된 파일, 개인 템플릿 및 문서 속성을 제거합니다.
3. 전용 클린 프로필에서 새 PDF를 내보냅니다. cloud printer로 “인쇄”하지 마십시오.
4. 형식 인식 도구와 일회용 시각적 렌더러를 모두 사용하여 검사합니다:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. 렌더링된 출력에서 이름, 경로, 이메일 주소 및 revision 텍스트를 검색합니다. Rasterization은 활성 구조를 제거할 수 있지만 접근성/검색 기능을 저하시킬 뿐이며, 표시되는 콘텐츠나 작성 스타일을 제거하지는 않습니다.
6. 최종 artifact를 hash하고 publication compartment를 통해 해당 사본만 전송합니다.

## Privacy Pass: service designer를 위한 익명 authorization

Privacy Pass는 token **issuance**와 **redemption**을 분리합니다. origin은 client가 issuer가 승인한 token을 보유하고 있다는 사실은 알 수 있지만, client의 구체적인 issuance 상호작용은 알 수 없습니다. token 재사용, 고유 metadata, timing 또는 collusion으로 인해 linkability가 다시 발생할 수 있습니다.<sup>[[10]](#references)</sup>

안전한 deployment pattern:

1. token이 증명하는 내용을 정의합니다(예: rate-limit eligibility). 숨겨진 전역 identity를 정의하지 않습니다.
2. 표준화된 architecture와 issuance protocol을 사용합니다. blind-signature cryptography를 처음부터 구현하지 않습니다.
3. 원하는 속성에 이를 필요로 하는 경우 issuer/attester와 origin administration을 분리합니다.
4. public/private token metadata를 최소화하고 anonymity set이 충분히 큰지 확인합니다.
5. 지원되는 경우 사용 전에 batch로 발급하여 issuance time이 redemption time과 쉽게 일치하지 않도록 합니다.
6. 각 token을 한 번만 redeem하고, origin-bound challenge를 검증하며, 만료된 token state를 삭제합니다.
7. cookies, IP logging 및 application accounts가 token privacy property를 무의식적으로 무효화하지 않도록 합니다.
8. timing, metadata 또는 고유한 오류를 사용하여 issuer와 origin의 log가 통제된 issuance 및 redemption event를 결합할 수 있는지 테스트합니다.

Privacy Pass는 application feature이며, 사용자가 임의의 account에 추가할 수 있는 기능이 아닙니다.

## Communications verification checklist

- [ ] Contact/invitation/key가 독립적으로 authenticated되었는지 확인했습니다.
- [ ] Phone number, username, profile, group 및 contact-upload 노출을 파악했습니다.
- [ ] Direct IP, relay, Tor, push-provider 및 local-radio observer를 나열했습니다.
- [ ] Notification preview, wearables, linked desktop 및 backup을 테스트했습니다.
- [ ] Files를 sanitized하고, 필요한 경우 encrypted했으며, disposable context에서 열었습니다.
- [ ] 관련 없는 identity를 연결하지 않고 recovery가 작동합니다.
- [ ] Logs, history 및 temporary share service에 shutdown/retention rule이 있습니다.

## References

- [1] [Signal — Phone Number Privacy and Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy and Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy and security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — How it works](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage and CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — official CLI and usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Safely removing metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
