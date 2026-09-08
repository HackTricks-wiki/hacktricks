# Threat Modeling & Identity Separation

{{#include ../banners/hacktricks-training.md}}

가장 흔한 anonymity 실패는 깨진 암호화가 원인이 아닙니다. 문제는 **linkage**입니다. 하나의 식별자, 시간 패턴, 장치, 계정, 결제 수단, 파일 또는 인간의 습관이 서로 분리되어 있어야 하는 두 context를 연결하는 것입니다.

## privacy threat model 구축

EFF의 six-question security plan은 강력한 기반입니다. 무엇을 보호해야 하는지, 누구로부터 보호해야 하는지, 실패의 영향과 가능성, 투입할 수 있는 노력, 그리고 도움을 줄 수 있는 협력자를 파악합니다.<sup>[[1]](#references)</sup> 다음과 같은 작은 표를 사용해 이를 운영 가능한 형태로 만드세요.

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| client 조사 | ISP | Destination/timing metadata | Home subscriber record | Tor Browser | Tor 사용이 드러남; end-to-end correlation |
| Pseudonymous account | Platform | IP, browser, recovery data | Reused phone/email/photo | Dedicated context and alias | Writing/social graph correlation |
| Online purchase | Merchant | Account, delivery, tokenized card | Address and account history | Guest checkout, minimal fields, virtual card | Issuer와 carrier가 기록을 보관 |
| Red-team traffic | Target/client | Source IP and behavior | Provider/engagement records | Dedicated authorized egress | escalation 상황에서 의도적으로 귀속 가능 |

위치, provider, device, counterpart 또는 consequences가 변경될 때마다 표를 검토하세요.

## linkability graph 그리기

각 identity를 별도의 node로 취급하세요. 공유되는 각 attribute에 대해 edge를 추가합니다.

- email 또는 recovery address;
- phone number 또는 contact-book upload;
- username, avatar, photo, bio 또는 writing/code style;
- password, passkey-sync account 또는 recovery question;
- device, advertising ID, browser profile, cookies, fonts 또는 extensions;
- IP address, time zone, language, schedule 또는 simultaneous online status;
- bank card, exchange account, wallet cluster, shipping address 또는 loyalty program;
- document author fields, EXIF location, printer marks 또는 cloud-share owner;
- colleague, group membership 및 social graph.

edge가 자동으로 치명적인 것은 아니지만, 어떤 observer가 연결을 만들 수 있는지 알려줍니다. EFF는 특히 phone numbers, email addresses 및 재사용된 photographs가 profile을 연결할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>

## compartment를 단계별로 생성

1. **context와 금지된 link를 이름으로 지정합니다.** 예: `client-red-2026`은 personal email, home browser profiles, personal payment methods 및 unrelated clients와 연결하지 않습니다.
2. **isolation boundary를 선택합니다.** 강도가 높아지는 순서로는 separate browser profile → separate OS account → separate VM/qube → dedicated device입니다. 별도의 tab이나 private window는 security boundary가 아닙니다.
3. **해당 boundary 안에서 새로운 identifier를 생성합니다.** context-specific email/alias, username, password-manager vault 또는 collection, authentication keys를 사용합니다. provider와의 unlinkability가 중요하다면 personal recovery channel을 추가하지 마세요.
4. **하나의 network policy를 선택합니다.** context에서 항상 client VPN, engagement VPS, trusted VPN 또는 Tor 중 무엇을 사용할지 결정하세요. 가능한 경우 fail-closed routing을 강제합니다.
5. **payment policy를 선택합니다.** payment method는 observer model과 일치해야 합니다. virtual card는 merchant에게 PAN을 숨길 수 있지만 issuer에게는 여전히 customer를 식별할 수 있습니다.
6. **data-transfer rules를 설정합니다.** 범위를 좁히고 의도적으로 수행하는 transfer를 우선하세요. clipboard, shared folders, USB devices, cloud sync, printers 및 screenshots를 잠재적인 bridge로 취급합니다.
7. **생성일과 폐기일을 기록합니다.** contracts/tax/compliance를 위해 어떤 evidence를 보존해야 하는지, 어떤 transient data를 만료시킬지 정의하세요.
8. **사용 전에 link를 테스트합니다.** account settings, recovery fields, public profile, IP/DNS, browser state, file metadata 및 provider dashboards를 검사하세요.

{% hint style="warning" %}
service 또는 law에서 정확한 identification을 요구하는 경우 identity 정보를 지어내지 마세요. privacy compartment는 data minimization과 separation을 위한 것이며, identity fraud나 customer due diligence 우회를 위한 것이 아닙니다.
{% endhint %}

## Endpoint 및 account baseline

- 지원되는 hardware를 사용하고 OS, browser, wallet 및 firmware updates를 즉시 설치하세요.
- device encryption을 활성화하고 강력한 device passcode를 사용하세요. Encryption at rest는 전원이 꺼진 device를 분실하거나 압수당했을 때 도움이 되지만, malware 또는 잠금 해제된 session이 data를 읽을 수 있는 동안에는 도움이 되지 않습니다.<sup>[[3]](#references)</sup>
- password manager에서 고유하고 무작위로 생성된 passwords를 사용하세요.
- threat model에서 recovery/sync model을 허용하는 경우 WebAuthn/passkeys 또는 hardware security keys와 같은 phishing-resistant authentication을 우선하세요. NIST는 수동으로 입력하는 OTP가 phishing-resistant하지 않다고 설명합니다. impostor가 이를 relay할 수 있기 때문입니다.<sup>[[4]](#references)</sup>
- recovery codes를 offline 상태로 endpoint와 분리해 보관하세요. synced passkey account가 분리되어 있어야 하는 identities를 연결하는지 검토하세요.
- 불필요한 location, contacts, microphone, camera, Bluetooth, advertising-ID 및 background permissions를 비활성화하세요.
- personal cloud sync, browser sync, password-manager accounts 또는 app stores를 high-separation context에 섞지 마세요.

## Browser privacy

Browser fingerprinting은 관찰 가능한 configuration, device, environment 및 behavior를 사용해 user를 식별하거나 correlate합니다. cookies를 삭제하거나 IP addresses를 변경해도 이를 안정적으로 무력화할 수 없으며, W3C는 널리 배포된 수단으로 완전한 technical elimination을 달성하는 것이 현실적으로 어렵다고 봅니다.<sup>[[5]](#references)</sup>

일반적인 privacy를 위해 다음을 수행하세요.

1. HTTPS-only mode와 강력한 tracking protection이 적용된 유지 관리되는 browser를 사용하세요.
2. 지원되는 경우 third-party tracking을 차단하고 state를 partition하세요.
3. 실제로 분리된 context에는 별도의 browser profiles를 사용하세요.
4. 필요하지 않은 permissions를 비활성화하고 정해진 일정에 따라 site data를 삭제하세요.
5. 관련 없는 민감한 research를 수행하는 동안 identity-rich accounts에 login하지 마세요.

Web anonymity를 위해 **Tor Browser in its standard configuration**을 사용하세요. 일반적인 browser를 Tor를 통해 proxy하지 마세요. Tor Project는 일반적인 browsers가 DNS/WebRTC, persistent state, fonts, plugins 및 fingerprint 차이를 통해 leak할 수 있다고 경고합니다.<sup>[[6]](#references)</sup> 추가 extensions, 특이한 window sizes, custom fonts 및 browser를 두드러지게 만드는 preferences를 피하세요.<sup>[[7]](#references)</sup>

## Communications 및 metadata

Metadata에는 message content가 encrypted되어 있더라도 sender, recipient, time, location 및 기타 context가 포함됩니다.<sup>[[8]](#references)</sup>

- 가능하다면 server-side metadata를 최소화하고 open protocols/clients를 사용하는 end-to-end-encrypted tools를 우선하세요.
- independent channel 또는 직접 만나서 민감한 contacts를 확인하세요. Signal safety numbers는 이러한 확인을 위해 설계되었습니다.<sup>[[9]](#references)</sup>
- Signal usernames를 사용하면 phone number를 공유하지 않고 contact를 시작할 수 있지만, 등록하려면 여전히 phone number가 필요합니다. phone-number visibility/discoverability를 신중하게 설정하세요.<sup>[[9]](#references)</sup>
- Disappearing messages는 보존되는 copies를 줄이지만, recipients는 여전히 content를 촬영하거나, 복사하거나, forward하거나, archive할 수 있습니다.
- Email은 일반적으로 routing metadata를 노출합니다. privacy-focused providers도 상대방이 ordinary email을 사용하는 경우, 양쪽 모두 compatible E2EE method를 사용하지 않는 한 message를 end-to-end encrypted 상태로 만들 수 없습니다. 예를 들어 Proton은 다른 providers로 보내는 ordinary mail이 TLS를 사용하며 receiving provider가 읽을 수 있는 상태로 남는다고 설명합니다.<sup>[[10]](#references)</sup>
- address books를 분리하고 pseudonymous account에 personal contacts를 upload하지 마세요.

## Files, photos 및 authorship

Tails는 photographs에 camera 및 location data가 포함될 수 있고, office documents에 author 및 creation-time fields가 포함될 수 있다고 경고합니다.<sup>[[11]](#references)</sup>

공유하기 전에:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
그런 다음 정리된 사본을 격리된 viewer에서 다시 열고 다음을 확인합니다.

- 문서 속성, comments, tracked changes, 숨겨진 sheets/slides, thumbnails 및 attachments;
- EXIF/XMP/IPTC, GPS, timestamps, device/software 이름 및 고유 ID;
- 눈에 보이는 반사, 랜드마크, 화면 내용, 목소리, 얼굴 및 배경음;
- filename, archive paths, cloud-share 소유자, signing certificate 및 revision history.

Sanitization은 evidence 또는 authenticity를 손상시킬 수 있습니다. chain of custody 또는 이후 verification이 중요한 경우 암호화된 원본을 보존합니다. Stylometry와 coding style도 authorship를 연결할 수 있으며, metadata removal은 인간의 스타일을 바꾸지 않습니다.

## 일반적인 실패 패턴

- “anonymous” connection을 통해 personal account에 로그인하기.
- recovery phone, avatar, username, public key, wallet 또는 donation address 재사용하기.
- 상관관계가 있는 context에서 두 identity를 동시에 운영하기.
- personal cloud clipboard 또는 shared folder를 통해 text/files 복사하기.
- 특징적인 Tor Browser extensions를 설치하거나 많은 기본값 변경하기.
- 무엇이 기록되는지, 얼마나 오래 보존되는지, 어떤 subcontractors가 처리하는지 이해하지 않고 “no logs” 주장을 신뢰하기.
- secondary phone이 personal phone과 함께 이동하는 동안 anonymous하다고 가정하기. EFF는 cellular location과 co-travel이 기기들을 상관시킬 수 있다고 설명합니다.<sup>[[3]](#references)</sup>
- encryption을 deletion으로 취급하기. endpoints와 recipients가 plaintext를 보존할 수 있습니다.

## Verification checklist

- [ ] context에 의도적으로 허용한 경우를 제외하고 personal recovery address, phone, sync account 또는 재사용된 media가 없습니다.
- [ ] 의도한 network path가 활성화되어 있으며 fail closed 방식으로 작동합니다.
- [ ] browser/device time zone, locale, extensions 및 permissions가 계획과 일치합니다.
- [ ] compartment에서 personal accounts가 열려 있지 않습니다.
- [ ] files를 검사하고 sanitized했으며, originals는 별도로 처리합니다.
- [ ] contacts가 second channel을 통해 authenticated되었습니다.
- [ ] provider에게 표시되는 metadata와 retention period를 이해하고 있습니다.
- [ ] teardown, evidence retention 및 account-recovery procedures가 문서화되어 있습니다.

## References

- [1] [EFF Surveillance Self-Defense — 보안 계획](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks에서 자신을 보호하기](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — 시위 참석하기](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication 및 Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications에서 Browser Fingerprinting 완화하기](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — 다른 browsers와 함께 Tor 사용하기](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser의 Plugins 및 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata가 중요한 이유](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy 및 Usernames: 심층 분석](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail 내에서 암호화되는 것은 무엇인가?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings: Tails는 안전하지만 마법은 아닙니다](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
