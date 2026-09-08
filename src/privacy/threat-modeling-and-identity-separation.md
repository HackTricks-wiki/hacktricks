# Threat Modeling & Identity Separation

最も一般的な anonymity の失敗は、暗号が破られることではありません。それは **linkage** です。つまり、1つの identifier、時間パターン、device、account、payment、file、または人間の習慣によって、本来分離されているはずの2つの context が結び付けられることです。

## プライバシーの threat model を構築する

EFF の6つの質問による security plan は、強固な基盤になります。何を保護する必要があるのか、誰から保護するのか、失敗の影響と可能性、利用できる労力、そして助けになれる協力者を明確にします。<sup>[[1]](#references)</sup> 小さな表を使って、これを実際の運用に落とし込みます。

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| クライアントの調査 | ISP | 宛先と timing metadata | 自宅の subscriber record | Tor Browser | Tor の利用が見える；end-to-end correlation |
| Pseudonymous account | Platform | IP、browser、recovery data | 再利用した phone/email/photo | 専用の context と alias | 文章や social graph による correlation |
| Online purchase | Merchant | Account、delivery、tokenized card | Address と account history | Guest checkout、最小限の fields、virtual card | Issuer と carrier に records が残る |
| Red-team traffic | Target/client | Source IP と behavior | Provider/engagement records | 専用の authorized egress | escalation 時には意図的に attributable |

location、provider、device、counterpart、または consequences が変わるたびに、この表を見直します。

## linkability graph を描く

各 identity を別々の node として扱います。共有されている attribute ごとに edge を追加します。

- email または recovery address；
- phone number または contact-book upload；
- username、avatar、photo、bio、または writing/code style；
- password、passkey-sync account、または recovery question；
- device、advertising ID、browser profile、cookies、fonts、または extensions；
- IP address、time zone、language、schedule、または同時に online であること；
- bank card、exchange account、wallet cluster、shipping address、または loyalty program；
- document author fields、EXIF location、printer marks、または cloud-share owner；
- colleague、group membership、social graph。

edge は自動的に致命的なものではありません。しかし、どの observer がその connection を作れるのかを示します。EFF は、phone numbers、email addresses、再利用した photographs が profiles を結び付ける可能性について、特に警告しています。<sup>[[2]](#references)</sup>

## compartment を段階的に作成する

1. **context と禁止する links に名前を付ける。** 例：`client-red-2026`。personal email、home browser profiles、personal payment methods、無関係な clients との link を禁止します。
2. **isolation boundary を選択する。** 強度が低い順に、separate browser profile → separate OS account → separate VM/qube → dedicated device です。separate tab や private window は security boundary ではありません。
3. **その boundary 内で新しい identifiers を作成する。** context 専用の email/alias、username、password-manager vault または collection、authentication keys を使用します。provider からの unlinkability が重要な場合は、personal recovery channel を追加しないでください。
4. **1つの network policy を選択する。** context が常に client VPN、engagement VPS、trusted VPN、または Tor のどれを使うのか決定します。可能な場合は fail-closed routing を強制します。
5. **payment policy を選択する。** payment method は observer model に合わせる必要があります。virtual card は merchant から PAN を隠せる場合がありますが、issuer には customer を識別されます。
6. **data-transfer rules を設定する。** 範囲を限定した意図的な transfer を優先します。clipboard、shared folders、USB devices、cloud sync、printers、screenshots は、潜在的な bridges として扱います。
7. **作成日と teardown 日を記録する。** contracts/tax/compliance のために保持すべき evidence と、期限切れにすべき transient data を定義します。
8. **使用前に links をテストする。** account settings、recovery fields、public profile、IP/DNS、browser state、file metadata、provider dashboards を確認します。

{% hint style="warning" %}
service または law によって正確な identification が要求されている場合は、identity information を捏造しないでください。privacy compartment は data minimization と separation のためのものであり、identity fraud や customer due diligence の bypass のためのものではありません。
{% endhint %}

## Endpoint と account の baseline

- supported hardware を使用し、OS、browser、wallet、firmware の updates を速やかに install します。
- device encryption を有効にし、強力な device passcode を使用します。Encryption at rest は、電源オフの device を紛失または押収された場合には有効ですが、malware や unlocked session が data を読み取れる状態では有効ではありません。<sup>[[3]](#references)</sup>
- password manager で、unique かつ randomly generated な passwords を使用します。
- threat model が recovery/sync model を許容する場合は、WebAuthn/passkeys や hardware security keys などの phishing-resistant authentication を優先します。NIST は、manually entered OTPs は phishing-resistant ではないと説明しています。impostor がそれらを relay できるためです。<sup>[[4]](#references)</sup>
- recovery codes は offline に保管し、endpoint から分離します。synced passkey account が、本来分離すべき identities を結び付けていないか確認します。
- 不要な location、contacts、microphone、camera、Bluetooth、advertising-ID、background permissions を無効にします。
- personal cloud sync、browser sync、password-manager accounts、app stores を high-separation context に混在させないでください。

## Browser privacy

Browser fingerprinting は、観測可能な configuration、device、environment、behavior を使って user を識別または correlate します。cookies を消去したり IP addresses を変更したりしても、これを確実に防ぐことはできません。また W3C は、広く配備された手段によってこれを完全に技術的排除することは困難だとしています。<sup>[[5]](#references)</sup>

通常の privacy では、次のようにします。

1. HTTPS-only mode と強力な tracking protection を備えた、maintained browser を使用します。
2. third-party tracking を block し、対応している場合は state を partition します。
3. 本当に分離すべき context には、separate browser profiles を使用します。
4. 不要な permissions を無効にし、定めた schedule で site data を消去します。
5. 無関係な sensitive research を行っている間は、identity-rich accounts に login しないでください。

web anonymity には、**Tor Browser の standard configuration** を使用します。通常の browser を Tor 経由で proxy しないでください。Tor Project は、通常の browsers が DNS/WebRTC、persistent state、fonts、plugins、fingerprint の違いを通じて leak する可能性があると警告しています。<sup>[[6]](#references)</sup> 追加の extensions、珍しい window sizes、custom fonts、browser を目立たせる preferences は避けてください。<sup>[[7]](#references)</sup>

## Communications と metadata

Metadata には、message content が encrypted であっても、sender、recipient、time、location、その他の context が含まれます。<sup>[[8]](#references)</sup>

- 実用上可能な場合は、server-side metadata を最小化し、open protocols/clients を備えた end-to-end-encrypted tools を優先します。
- sensitive contacts は、独立した channel または対面で確認します。Signal safety numbers は、この確認のために設計されています。<sup>[[9]](#references)</sup>
- Signal usernames は phone number を共有せずに contact を開始できますが、register には phone number が依然として必要です。phone-number visibility/discoverability は意図的に設定してください。<sup>[[9]](#references)</sup>
- Disappearing messages は保持される copies を減らしますが、recipients は content を撮影、copy、forward、archive できます。
- Email は通常、routing metadata を露出します。privacy-focused providers であっても、相手側が ordinary email を使っている場合、両者が互換性のある E2EE method を使用しない限り、message を end-to-end encrypted にはできません。例えば Proton は、他の providers への ordinary mail は TLS を使用し、receiving provider から読み取り可能なままであると説明しています。<sup>[[10]](#references)</sup>
- address books を分離し、pseudonymous account に personal contacts を upload しないでください。

## Files、photos、authorship

Tails は、photographs に camera と location data が含まれる可能性があり、office documents に author と creation-time fields が含まれる可能性があると警告しています。<sup>[[11]](#references)</sup>

共有する前に：
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
その後、クリーニング済みのコピーを隔離された viewer で再度開き、次を確認します。

- document properties、comments、tracked changes、hidden sheets/slides、thumbnails、attachments；
- EXIF/XMP/IPTC、GPS、timestamps、device/software names、unique IDs；
- 目に見える反射、landmarks、screen contents、voices、faces、background sounds；
- filename、archive paths、cloud-share owner、signing certificate、revision history。

Sanitization によって evidence や authenticity が損なわれることがあります。chain of custody または後日の verification が重要な場合は、encrypted original を保管してください。Stylometry や coding style によって authorship が特定されることもあります。metadata removal では human style は変わりません。

## Common failure patterns

- “anonymous” connection を通じて personal account にログインする。
- recovery phone、avatar、username、public key、wallet、donation address を再利用する。
- 相関する状況から、2つの identity を同時に運用する。
- personal cloud clipboard や shared folder を介して text/files をコピーする。
- 特徴的な Tor Browser extensions をインストールしたり、多数の default settings を変更したりする。
- 何が、どの期間、どの subcontractors によって logging されるのかを理解せず、“no logs” という主張を信用する。
- secondary phone が personal phone と一緒に移動しているにもかかわらず、anonymous だと考える。EFF は、cellular location と co-travel によってデバイス間の相関が可能になると指摘しています。<sup>[[3]](#references)</sup>
- encryption を deletion とみなす。endpoints や recipients が plaintext を保持している可能性があります。

## Verification checklist

- [ ] context に personal recovery address、phone、sync account、または意図的に受け入れたものを除く reused media が存在しない。
- [ ] 意図した network path が有効で、fail closed する。
- [ ] browser/device time zone、locale、extensions、permissions が plan と一致している。
- [ ] compartment 内で personal accounts が開かれていない。
- [ ] files が inspection と sanitization を受けており、originals は別に扱われている。
- [ ] contacts が second channel を通じて authenticated されている。
- [ ] provider-visible metadata と retention period を理解している。
- [ ] teardown、evidence retention、account-recovery procedures が文書化されている。

## References

- [1] [EFF Surveillance Self-Defense — Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks での自己防衛](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Protest への参加](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication と Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications における Browser Fingerprinting の Mitigation](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — 他の browsers で Tor を使用する](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser の Plugins と add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata が重要な理由](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy と Usernames：Deeper Dive](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail 内で暗号化されるもの](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings：Tails は safe だが magic ではない](https://tails.net/doc/about/warnings/index.en.html)
