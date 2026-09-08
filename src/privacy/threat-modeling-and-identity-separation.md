# Threat Modeling & Identity Separation

가장 흔한 anonymity failure은 깨진 cryptography가 아니다. **linkage**다. 하나의 identifier, timing pattern, device, account, payment, file 또는 human habit이 서로 분리되어 있어야 하는 두 context를 연결하는 것이다.

## Build a privacy threat model

EFF의 six-question security plan은 강력한 기반이다. 무엇을 보호해야 하는지, 누구로부터 보호해야 하는지, failure의 impact와 likelihood, 투입할 수 있는 effort, 그리고 도움을 줄 수 있는 allies를 묻는다.<sup>[[1]](#references)</sup> 다음과 같은 작은 표를 사용해 이를 operational하게 만들 수 있다.

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Client 조사 | ISP | Destination/timing metadata | Home subscriber record | Tor Browser | Tor 사용이 노출됨; end-to-end correlation |
| Pseudonymous account | Platform | IP, browser, recovery data | Reused phone/email/photo | Dedicated context and alias | Writing/social graph correlation |
| Online purchase | Merchant | Account, delivery, tokenized card | Address and account history | Guest checkout, minimal fields, virtual card | Issuer와 carrier가 records를 보관 |
| Red-team traffic | Target/client | Source IP and behavior | Provider/engagement records | Dedicated authorized egress | Escalation 시 의도적으로 귀속 가능 |

Location, provider, device, counterpart 또는 consequences가 변경될 때마다 표를 검토한다.

## Draw the linkability graph

각 identity를 별도의 node로 취급한다. 공유되는 각 attribute마다 edge를 추가한다.

- email 또는 recovery address;
- phone number 또는 contact-book upload;
- username, avatar, photo, bio 또는 writing/code style;
- password, passkey-sync account 또는 recovery question;
- device, advertising ID, browser profile, cookies, fonts 또는 extensions;
- IP address, time zone, language, schedule 또는 simultaneous online status;
- bank card, exchange account, wallet cluster, shipping address 또는 loyalty program;
- document author fields, EXIF location, printer marks 또는 cloud-share owner;
- colleague, group membership 및 social graph.

Edge가 자동으로 치명적인 것은 아니지만, 어떤 observer가 connection을 만들어낼 수 있는지 알려준다. EFF는 phone numbers, email addresses 및 reused photographs가 profiles를 연결할 수 있다고 구체적으로 경고한다.<sup>[[2]](#references)</sup>

## Create a compartment step by step

1. **Context와 금지된 links를 명시한다.** 예: `client-red-2026`; personal email, home browser profiles, personal payment methods 및 unrelated clients와 연결하지 않는다.
2. **Isolation boundary를 선택한다.** 강도가 높아지는 순서로 separate browser profile → separate OS account → separate VM/qube → dedicated device를 사용한다. Separate tab 또는 private window는 security boundary가 아니다.
3. **그 boundary 내부에서 새로운 identifiers를 만든다.** Context-specific email/alias, username, password-manager vault 또는 collection, authentication keys를 사용한다. Provider로부터의 unlinkability가 중요하다면 personal recovery channel을 추가하지 않는다.
4. **하나의 network policy를 선택한다.** Context가 항상 client VPN, engagement VPS, trusted VPN 또는 Tor 중 무엇을 사용할지 결정한다. 가능한 경우 fail-closed routing을 적용한다.
5. **Payment policy를 선택한다.** Payment method는 observer model과 일치해야 한다. Virtual card는 merchant에게 PAN을 숨길 수 있지만 issuer에게는 여전히 customer를 식별할 수 있다.
6. **Data-transfer rules를 설정한다.** 범위가 좁고 의도적인 transfers를 우선한다. Clipboard, shared folders, USB devices, cloud sync, printers 및 screenshots를 가능한 bridges로 취급한다.
7. **Creation 및 teardown dates를 기록한다.** Contracts/tax/compliance를 위해 어떤 evidence를 보존해야 하는지, 어떤 transient data가 만료되어야 하는지 정의한다.
8. **사용 전에 links를 테스트한다.** Account settings, recovery fields, public profile, IP/DNS, browser state, file metadata 및 provider dashboards를 검사한다.

{% hint style="warning" %}
Service 또는 law가 정확한 identification을 요구하는 경우 identity information을 조작하지 않는다. Privacy compartment는 data minimization과 separation을 위한 것이며, identity fraud 또는 customer due diligence 우회를 위한 것이 아니다.
{% endhint %}

## Endpoint and account baseline

- Supported hardware를 사용하고 OS, browser, wallet 및 firmware updates를 즉시 설치한다.
- Device encryption을 활성화하고 strong device passcode를 사용한다. Encryption at rest는 powered-off device를 분실하거나 압수당했을 때 도움이 되지만, malware 또는 unlocked session이 data를 읽을 수 있는 동안에는 도움이 되지 않는다.<sup>[[3]](#references)</sup>
- Password manager에서 unique하고 randomly generated된 passwords를 사용한다.
- Threat model이 recovery/sync model을 허용하는 경우 WebAuthn/passkeys 또는 hardware security keys와 같은 phishing-resistant authentication을 우선한다. NIST는 manually entered OTPs가 phishing-resistant하지 않다고 설명한다. Impostor가 이를 relay할 수 있기 때문이다.<sup>[[4]](#references)</sup>
- Recovery codes를 offline 상태로 endpoint와 분리해 보관한다. Synced passkey account가 분리되어 있어야 하는 identities를 연결하는지 검토한다.
- 불필요한 location, contacts, microphone, camera, Bluetooth, advertising-ID 및 background permissions를 비활성화한다.
- Personal cloud sync, browser sync, password-manager accounts 또는 app stores를 high-separation context에 혼합하지 않는다.

## Browser privacy

Browser fingerprinting은 관찰 가능한 configuration, device, environment 및 behavior를 사용해 user를 식별하거나 correlate한다. Cookies를 지우거나 IP addresses를 변경하는 것만으로는 이를 안정적으로 방어할 수 없으며, W3C는 널리 배포된 수단으로 이를 기술적으로 완전히 제거하는 것이 불가능할 것으로 본다.<sup>[[5]](#references)</sup>

일반적인 privacy를 위해 다음을 따른다.

1. HTTPS-only mode와 strong tracking protection을 지원하는 maintained browser를 사용한다.
2. Third-party tracking을 차단하고 지원되는 경우 state를 partition한다.
3. 실제로 분리된 contexts에는 별도의 browser profiles를 사용한다.
4. 필요하지 않은 permissions를 비활성화하고 정의된 일정에 따라 site data를 삭제한다.
5. 관련 없는 민감한 research를 수행하는 동안 identity-rich accounts에 로그인하지 않는다.

Web anonymity를 위해 **Tor Browser in its standard configuration**을 사용한다. 일반 browser를 Tor를 통해 proxy하지 않는다. Tor Project는 ordinary browsers가 DNS/WebRTC, persistent state, fonts, plugins 및 fingerprint differences를 통해 leak할 수 있다고 경고한다.<sup>[[6]](#references)</sup> 추가 extensions, unusual window sizes, custom fonts 및 browser를 두드러지게 만드는 preferences를 피한다.<sup>[[7]](#references)</sup>

## Communications and metadata

Metadata에는 message content가 encrypted되어 있더라도 sender, recipient, time, location 및 기타 context가 포함된다.<sup>[[8]](#references)</sup>

- 가능한 경우 server-side metadata가 최소화되고 open protocols/clients를 사용하는 end-to-end-encrypted tools를 우선한다.
- Sensitive contacts는 independent channel 또는 직접 만나서 verify한다. Signal safety numbers는 이러한 확인을 위해 설계되었다.<sup>[[9]](#references)</sup>
- Signal usernames는 phone number를 공유하지 않고도 contact를 시작할 수 있지만, register하려면 여전히 phone number가 필요하다. Phone-number visibility/discoverability는 신중하게 configure한다.<sup>[[9]](#references)</sup>
- Disappearing messages는 보관되는 copies를 줄이지만, recipients는 여전히 content를 촬영, 복사, forward 또는 archive할 수 있다.
- Email은 일반적으로 routing metadata를 노출한다. Privacy-focused providers라 하더라도 상대방이 ordinary email을 사용하는 경우, 양쪽이 compatible E2EE method를 사용하지 않는 한 message를 end-to-end encrypted로 만들 수 없다. 예를 들어 Proton은 다른 providers로 보내는 ordinary mail이 TLS를 사용하며 receiving provider가 읽을 수 있는 상태로 남는다고 설명한다.<sup>[[10]](#references)</sup>
- Address books를 분리하고 pseudonymous account에 personal contacts를 upload하지 않는다.

## Files, photos and authorship

Tails는 photographs에 camera 및 location data가 포함될 수 있고 office documents에 author 및 creation-time fields가 포함될 수 있다고 경고한다.<sup>[[11]](#references)</sup>

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
- 보이는 반사, 랜드마크, 화면 내용, 목소리, 얼굴 및 배경음;
- filename, archive paths, cloud-share owner, signing certificate 및 revision history.

Sanitization은 evidence 또는 authenticity를 손상시킬 수 있습니다. chain of custody 또는 이후 verification이 중요하다면 암호화된 원본을 보존합니다. Stylometry와 coding style도 authorship을 연결하는 단서가 될 수 있습니다. metadata removal은 human style을 바꾸지 않습니다.

## 일반적인 실패 패턴

- “anonymous” connection을 통해 personal account에 로그인하기.
- recovery phone, avatar, username, public key, wallet 또는 donation address 재사용하기.
- 상관관계가 있는 contexts에서 두 identities를 동시에 운영하기.
- personal cloud clipboard 또는 shared folder를 통해 text/files 복사하기.
- 구별되는 Tor Browser extensions를 설치하거나 많은 defaults 변경하기.
- 무엇이 기록되고, 얼마나 오래 보관되며, 어떤 subcontractors가 처리하는지 이해하지 않고 “no logs” 주장을 신뢰하기.
- secondary phone이 personal phone과 함께 이동하는 동안 anonymous하다고 가정하기. EFF는 cellular location과 co-travel이 devices를 상관시킬 수 있다고 설명합니다.<sup>[[3]](#references)</sup>
- encryption을 deletion으로 취급하기. endpoints와 recipients가 plaintext를 보관할 수 있습니다.

## Verification checklist

- [ ] context에 personal recovery address, phone, sync account 또는 재사용된 media가 없거나, 의도적으로 허용되었습니다.
- [ ] 의도한 network path가 활성화되어 있고 fails closed 상태입니다.
- [ ] Browser/device time zone, locale, extensions 및 permissions가 계획과 일치합니다.
- [ ] compartment에서 personal accounts가 열려 있지 않습니다.
- [ ] Files를 검사하고 sanitized했으며, originals는 별도로 처리됩니다.
- [ ] Contacts가 second channel을 통해 authenticated되었습니다.
- [ ] provider-visible metadata 및 retention period를 이해하고 있습니다.
- [ ] Teardown, evidence retention 및 account-recovery procedures가 문서화되어 있습니다.

## References

- [1] [EFF Surveillance Self-Defense — 보안 계획](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks에서 자신을 보호하기](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Protest에 참석하기](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication 및 Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications에서 Browser Fingerprinting 완화하기](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — 다른 browsers와 Tor 사용하기](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser의 Plugins 및 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata가 중요한 이유](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy 및 Usernames: 심층 분석](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail에서 암호화되는 것은 무엇인가?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings: Tails는 안전하지만 마법은 아닙니다](https://tails.net/doc/about/warnings/index.en.html)
