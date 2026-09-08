# Privacy-Preserving Communications and Sharing

End-to-end encryption은 콘텐츠를 보호합니다. 하지만 계정, 전화번호, 연락처 그래프, IP 주소, push token, notification preview, 타이밍, 파일 metadata 또는 수신자 행동을 자동으로 숨기지는 않습니다. 제거하는 metadata와 새로 관찰할 수 있게 되는 주체를 기준으로 도구를 선택하세요.

## Compare communication models

| Tool/model | Useful property | Remaining observers and limits |
|---|---|---|
| Signal | 성숙한 E2EE; username으로 번호를 공유하지 않고 연락 시작 가능; sealed sender가 service metadata를 줄임 | 등록에 전화번호 필요; service, push provider, contacts 및 endpoints에 일부 관찰 정보가 남음 |
| SimpleX | 전역 사용자 식별자 없음; contact별 queue; 선택적 Tor transport | Relay timing/transport, push service, invitations 및 endpoints; 더 새롭고 작은 ecosystem |
| Briar | 직접 synchronization; 온라인에서는 Tor; offline에서는 Bluetooth/Wi-Fi; 중앙 message store 없음 | Contacts 및 endpoints; local radio observers; Android 중심; 양쪽 모두 연결되어 있거나 Mailbox를 사용해야 함 |
| OnionShare | 임시 onion service를 통한 직접 file/receive/chat/site; storage provider 없음 | Sender computer가 service임; link bearer가 access를 알게 됨; timing 및 endpoints는 남음 |
| `age` encrypted file | transport와 독립적인 간단한 recipient-key encryption | Transport가 sender/recipient/timing/size를 확인 가능; filenames/archive metadata 및 endpoints는 남음 |
| Ordinary email + TLS | Server-to-server channel encryption | 일반적으로 두 mail provider 모두 content를 읽고 routing/account metadata를 보관 가능 |

## Signal: private contact without number disclosure

Signal username은 새 contact에게 사용자의 전화번호를 공개하지 않고 chat을 시작할 수 있게 하지만, 등록에는 여전히 전화번호가 필요합니다.<sup>[[1]](#references)</sup> Sealed sender는 점진적인 metadata 보호 기능이며, 모든 IP/timing correlation에 대한 저항 기능은 아닙니다.<sup>[[2]](#references)</sup>

### Workflow

1. 공식 app store/project에서 Signal을 설치하고 먼저 OS를 update하세요.
2. 법적으로 사용할 권리가 있는 번호로 등록하세요. 대여한 SMS activation, 다른 사람의 번호 또는 허위 신원으로 취득한 provider account를 사용하지 마세요.
3. **Settings → Privacy → Phone Number**에서 threat model에 따라 누가 번호를 볼 수 있는지, 누가 번호로 account를 찾을 수 있는지 설정하세요.
4. 새 contact 검색을 위해 username을 생성하세요. 이미 인증된 channel을 통해 정확한 link/QR을 공유하세요. username은 변경될 수 있으며 profile name이 아닙니다.
5. 편의성보다 linkage 방지가 중요하다면 contact upload/permissions를 비활성화하고, platform이 지원하는 경우 contact를 수동으로 추가하세요.
6. 민감한 content를 보내기 전에 contact details를 열고 두 번째 channel 또는 대면으로 safety number/QR을 비교하세요.
7. linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults 및 backup 동작을 검토하세요.
8. 민감하지 않은 test message를 보내고 call하세요. 양쪽에서 lock-screen, desktop, wearable 및 cloud-notification trace를 확인하세요.
9. 변경된 safety number나 예상하지 못한 linked device를 자동으로 무시할 alert가 아니라 investigation event로 취급하세요.

Pseudonymous profile photo, bio, group membership 또는 schedule을 식별 가능한 Signal context와 혼합하지 마세요.

## SimpleX: per-contact connections without a global identifier

SimpleX는 단방향 queue를 통해 message를 routing하며 network-wide user identifier를 할당하지 않습니다. 자체 policy에는 transport session, 임시 server data, push-notification tradeoff 및 endpoint 책임에 대한 내용이 여전히 문서화되어 있습니다.<sup>[[3]](#references)</sup>

### Workflow

1. 공식 project/store에서 유지 관리되는 client를 다운로드하고 publisher를 검증하세요. Identity를 섞지 않아야 한다면 전용 OS/app profile을 사용하세요.
2. context에 맞는 display name과 image를 사용하는 **local** profile을 생성하세요. backup 없이 app을 삭제하면 profile과 connection을 잃을 수 있습니다.
3. 첫 실행 시 notification mode를 신중하게 선택하세요. 즉시 mobile push를 사용하면 Apple/Google infrastructure에 추가 metadata가 노출될 수 있습니다.
4. 한 명의 contact를 위한 일회성 invitation link를 생성하세요. 인증된 channel을 통해 전달하세요. 유효한 invitation을 획득한 사람은 누구든 사용을 시도할 수 있습니다.
5. 연결한 후 contact details를 열고 대면 또는 독립적으로 검증된 channel을 통해 security code를 비교하세요.<sup>[[4]](#references)</sup>
6. 지원되는 경우 관련 없는 여러 group에서 동일한 profile을 재사용하는 대신 incognito per-group profile을 사용하세요.
7. local network/server가 direct IP를 확인하지 않아야 한다면 client가 지원하는 Tor transport를 설정하세요. 변경 후 connection을 확인하고, 지원되지 않는 system proxy를 강제로 사용하지 마세요.
8. delivery receipts, link previews, calls, automatic downloads 및 database export/backup을 검토하세요. 각각 metadata 또는 endpoint exposure를 변경합니다.
9. 중복된 live profile state를 실행하지 않고 별도의 격리된 spare device에서 recovery를 테스트하세요. project는 동시에 실행되는 복사본이 conversation을 방해할 수 있다고 경고합니다.

전역 identifier가 없더라도 contact가 content, profile reuse, invitation delivery, timing 또는 social graph를 통해 사용자를 식별하는 것을 막지는 못합니다.

## Briar: direct and disruption-resistant messaging

Briar는 device 간에 직접 synchronization하며, 온라인일 때는 Tor를 통해, local outage 중에는 Bluetooth/Wi-Fi를 통해 동기화합니다. 공식 threat model은 short-range radio에 대한 adversarial monitoring이 제한적이라고 가정하므로 local wireless는 보이지 않는 것이 아닙니다.<sup>[[5]](#references)</sup>

### Workflow

1. 공식 Briar distribution에서 설치하고 package source를 검증하세요. 최신 security update가 적용된 지원 Android device를 사용하세요.
2. 고유한 context nickname과 강력한 password로 local account를 생성하세요. Password-reset 경로가 없으므로 unlock secret을 복구할 수 있는지 테스트하세요.
3. 가능하면 서로의 QR code를 scan하여 대면으로 contact를 추가하세요. 이렇게 하면 contact를 인증하고 correlation 가능한 channel을 통해 link를 보내지 않아도 됩니다.
4. connectivity settings에서 필요한 transport만 활성화하세요: Tor/Internet, Wi-Fi 및/또는 Bluetooth. 필요하지 않을 때는 local radio를 비활성화하세요.
5. 비동기 delivery를 위해 전용 전원 연결 device에서 Briar Mailbox를 사용하는 방안을 평가하세요. 이를 message server처럼 inventory하고 물리적으로 보호하세요.
6. Internet을 사용할 수 있을 때 benign test를 전송한 다음, 소유자가 승인한 장소에서 Internet을 비활성화하고 계획한 outage 경로를 테스트하세요.
7. Android backup, notification previews, screenshots 및 exported content를 확인하세요. endpoint가 unlock되거나 compromised되면 local encrypted storage가 노출됩니다.
8. 분실한 contact/device를 제거하고 physical custody 또는 account password가 compromised되었다면 전체 context를 폐기하세요.

## OnionShare: direct temporary transfer

OnionShare는 sender/receiver computer에서 onion service를 실행합니다. 따라서 파일이 storage provider에 upload되지 않으며 traffic은 Tor 내부에서 end-to-end encrypted됩니다.<sup>[[6]](#references)</sup> 전체 onion URL은 bearer capability이므로 보호해야 합니다.

### GUI file-sharing workflow

1. 공식 서명 distribution에서 OnionShare를 설치하고 recipient 측에 Tor Browser를 설치하세요.
2. **sanitized copies**의 파일을 전용 staging directory에 넣으세요. OnionShare가 개인 home directory를 가리키도록 하지 마세요.
3. **Share Files**를 열고 staging된 파일만 추가하세요. private key/access protection은 활성화된 상태로 두고, 한 명의 recipient를 위해 **Stop sharing after files have been sent**를 활성화된 상태로 유지하세요.
4. sharing을 시작하고 이미 인증된 E2EE channel을 통해 전체 onion URL을 보내세요. email, issue tracker 또는 public chat에 붙여넣지 마세요.
5. Recipient는 Tor Browser에서 URL을 열고 sender와 예상한 filename/size를 확인한 다음 download합니다.
6. 파일 자체가 security boundary인 경우 양쪽에서 사전에 합의했거나 별도로 전달된 SHA-256 digest를 비교하여 integrity를 확인하세요.
7. download 후 OnionShare가 중지되었는지 확인하세요. 그렇지 않으면 수동으로 중지하고 application을 닫으세요.
8. retention policy에 따라 staging copy를 삭제하고, 의도하지 않은 filename disclosure가 발생하지 않도록 OnionShare history/log settings를 확인하세요.

### CLI workflow

공식 CLI는 positional argument로 파일을 받으며, 기본적으로 한 번의 share가 완료되면 중지합니다. 공식 CLI/Tor가 설치된 host에서:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
결과 URL 전체를 안전하게 전달하세요. 위협 모델에서 결과로 인해 발생하는 노출이 명시적으로 요구되는 경우가 아니라면 `--public`, `--no-autostop-sharing`, 자세한 filename 로깅 또는 persistence를 추가하지 마세요.<sup>[[7]](#references)</sup>

받은 문서는 적대적인 것으로 취급하세요. 신원 정보가 포함된 host에서 문서를 열지 말고, 폐기 가능한 VM/Dangerzone-style renderer에서 여세요.

## `age`로 파일을 독립적으로 Encrypt

storage/email provider가 object를 볼 수 있는 경우, transport와 무관한 encryption이 유용합니다. 다만 sender, recipient, size, timing 또는 filename을 별도로 처리하지 않는 한 이를 숨기지는 못합니다.

### Recipient 설정
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
공개 수신자 문자열을 두 번째 채널을 통해 인증합니다. 그런 다음 발신자는 다음을 실행합니다:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
수신자는 새로운 경로로 복호화합니다:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
공식 CLI는 `-o`가 기존 output을 덮어쓴다고 경고하므로, 새 디렉터리를 사용하고 이동하기 전에 digest/content를 검증하세요.<sup>[[8]](#references)</sup> 암호문과 함께 identity file을 절대 전송하지 마세요.

## 재현 가능한 파일 정제 파이프라인

Metadata 제거는 형식에 따라 다릅니다. authenticity, forensics 또는 chain of custody가 중요한 경우 암호화된 원본을 보존하고, 복사본에서 작업하세요.

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
This follows ExifTool의 safer JPEG guidance: blindly removing every tag may also remove color information.<sup>[[9]](#references)</sup> Then visually inspect pixels for faces, reflections, screens, landmarks and unique damage/noise patterns.

### Office/PDF workflow

1. Keep the editable original encrypted and offline from the publication context.
2. Remove comments, tracked changes, hidden slides/sheets, embedded files, personal templates and document properties in the authoring application.
3. Export a new PDF from a dedicated clean profile; do not “print” to a cloud printer.
4. Inspect with both format-aware tools and a disposable visual renderer:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. 렌더링된 출력에서 이름, 경로, 이메일 주소 및 revision 텍스트를 검색합니다. Rasterization은 활성 구조를 제거할 수 있지만 접근성/검색 기능을 저해하며, 표시되는 콘텐츠나 작성 스타일을 제거하지는 않습니다.
6. 최종 artifact를 hash하고 publication compartment를 통해 해당 사본만 전송합니다.

## Privacy Pass: service designer를 위한 anonymous authorization

Privacy Pass는 token **issuance**와 **redemption**을 분리합니다. origin은 client가 issuer가 승인한 token을 보유하고 있다는 사실은 알 수 있지만, client의 구체적인 issuance 상호작용은 알 수 없습니다. token 재사용, 고유 metadata, timing 또는 collusion으로 인해 linkability가 다시 발생할 수 있습니다.<sup>[[10]](#references)</sup>

안전한 deployment pattern:

1. token이 증명하는 내용을 정의합니다(예: rate-limit eligibility). 숨겨진 global identity를 정의하지 않습니다.
2. 표준화된 architecture와 issuance protocol을 사용합니다. blind-signature cryptography를 처음부터 구현하지 않습니다.
3. 원하는 property에 이를 필요로 하는 경우 issuer/attester와 origin administration을 분리합니다.
4. public/private token metadata를 최소화하고 anonymity set이 충분히 큰지 확인합니다.
5. 지원되는 경우 사용 전에 batch로 발급하여 issuance time이 redemption time과 쉽게 일치하지 않도록 합니다.
6. 각 token을 한 번만 redeem하고, origin-bound challenge를 검증하며, 만료된 token state를 삭제합니다.
7. cookies, IP logging 및 application accounts가 token privacy property를 조용히 무력화하지 않도록 합니다.
8. timing, metadata 또는 고유한 errors를 사용하여 issuer와 origin의 logs가 통제된 issuance 및 redemption event를 결합할 수 있는지 테스트합니다.

Privacy Pass는 application feature이며, 사용자가 임의의 account에 추가할 수 있는 것이 아닙니다.

## Communications verification checklist

- [ ] Contact/invitation/key가 독립적으로 인증되었습니다.
- [ ] Phone number, username, profile, group 및 contact-upload exposure를 파악했습니다.
- [ ] Direct IP, relay, Tor, push-provider 및 local-radio observers를 열거했습니다.
- [ ] Notification previews, wearables, linked desktops 및 backups를 테스트했습니다.
- [ ] Files를 sanitize하고, 필요한 경우 encrypt했으며, disposable context에서 열었습니다.
- [ ] 관련 없는 identities를 연결하지 않고 recovery가 작동합니다.
- [ ] Logs, history 및 temporary share services에 shutdown/retention rule이 있습니다.

## References

- [1] [Signal — Phone Number Privacy and Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy and Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy and security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — 작동 방식](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage and CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — 공식 CLI 및 사용법](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — metadata를 안전하게 제거하기](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
