# Attribution、Detection、Countermeasures

Attribution-evasion infrastructure は、個々の indicator を使い捨て可能にするよう設計されています。Defender は raw evidence を保持し、関係性をモデル化し、IP、domain、persona の変更後も残る behavior を hunt すべきです。

## Evidence hierarchy

| Evidence | Useful for | Main caveat |
|---|---|---|
| Source IP/ASN/geolocation | 目に見える exit と provider の特定 | exit は relay、NAT、または victim の可能性があり、geolocation はおおよそのもの |
| Passive DNS/registration | infrastructure の履歴と co-hosting | privacy/redaction と shared hosting により gaps が生じる |
| Certificate/TLS/HTTP fingerprint | 繰り返される deployment の cluster 化 | common software と mimicry により false positives が生じる |
| Flow timing and byte shape | relay stages と繰り返される beacon の関連付け | CDN/NAT と limited visibility により確実性が低下する |
| Endpoint process/identity | なぜ connection が発生したかの説明 | edge/IoT には存在せず、attacker は native tools を使用する可能性がある |
| Cloud/CDN/API audit | tenant と infrastructure control の特定 | retention と provider/legal access は異なる |
| Payment/account/device | procurement と person/entity の関連付け | nominee、compromise、shared devices を考慮する必要がある |
| Seized implant/configuration | keys、peers、controllers、build links の露呈 | collection integrity と seizure の時期が重要 |
| Human/physical evidence | digital event と place/operator の関連付け | intrusive で、jurisdiction に依存し、厳格な handling が必要 |

単一の row に high-confidence な state attribution を担わせるべきではありません。競合する hypotheses を使用し、それぞれを falsify する observation を明示してください。

## Minimum telemetry

1. **DNS:** client、question、type、answers、TTL、response code、resolver、timestamp。
2. **Network flow:** source/destination/port、start/end、packets/bytes、TCP flags、sensor location。
3. **TLS/HTTP:** 可視の場合は SNI、certificate、negotiated protocol、client/server fingerprint、method、authority/path category、status、byte count。sensitive な full URLs を保護する。
4. **Identity:** authentication result、factor/certificate/device、source、application、session ID、risk decision。
5. **Endpoint:** initiating process、parent、user、binary signature/hash、destination。
6. **Edge/network device:** configuration diff、admin login、process/file/firmware integrity、interface、flow logs。
7. **Cloud/SaaS/CDN:** actor、tenant/project、API action、source、object/resource、token、result。
8. **Wireless/NAC:** station、randomized-MAC flag、AP、signal、EAP identity/certificate、assigned VLAN/IP、posture。

Clocks を同期し、original time zones を保持し、NAT/proxy boundaries を文書化し、31-day ORB node より長く存続できるだけの history を保持してください。

## Build an attribution graph

Observations を typed nodes と edges として表現します:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
有用なノードには、IP、prefix、ASN、domain、DNS account、certificate/key、JA3/JA4-like fingerprint、HTTP grammar、file/config hash、cloud tenant、API token、email、persona、payment instrument、physical deviceなどがあります。すべてのエッジには、`first_seen`、`last_seen`、sensor/source、confidence、およびそれが観測されたものか推定されたものかを示す情報が必要です。

グラフの密度だけでは誤解を招きます。CDNやcertificate authorityは、無関係な多数のactorを接続するためです。一般的なhostingよりも、同じAPI account、SSH key、origin allowlist、固有のresponse body、control protocolなど、operatorが管理する希少な関係を重く評価します。

## ORBとcompromised-router hunting

### 観測されたexitから

1. そのaddressがhosting、residential、mobile、education、businessのいずれであるかを判定します。residential sourceを除外してはいけません。
2. 限定した期間について、過去のDNS、services/certificates、open ports、観測されたscan/exploitation behaviorを取得します。
3. 希少なservice fingerprint、controller destination、certificate material、rotation timingを共有するpeerを検索します。
4. 想定されるroleを、access、traversal、exit/staging、administrationに分類します。
5. 複数の無関係なintrusion clusterが同じpoolを使用していないか確認します。multi-tenancyは直接的なactor attributionの確度を下げますが、ORB仮説の確度を高めます。
6. 古いIPが消失した後、role profileに一致する新しいnodeを追跡します。

### network owner側

- 新たにInternetに公開されたmanagement機能、およびdefault/legacy authenticationに対してalertを発生させます。
- router/firewall/VPNのconfiguration変更とadmin authenticationをdevice外部へ送信します。
- 通常ほとんどsessionを開始しないinfrastructureからのoutbound connectionをbaseline化します。
- 新しいproxy/listener process、tunnel、scheduled task、firmware変更、予期しないDNSを検出します。
- end-of-life deviceを交換します。rebootによってvolatile malwareが削除されても、exposureは解消されません。
- managementを、authenticated administration planeおよび既知のsourceに限定します。

Mandiantは、短期間のIP blockingではtopologyとlifecycleを把握できないため、ORB infrastructureを変化するentityとして追跡することを推奨しています。<sup>[[1]](#references)</sup>

## Fast-fluxとdynamic-DNS analytics

registered domainとsliding window単位で集約します。実用的なscoreには、次の要素を組み合わせられます。
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
複数の独立した特徴を持つドメインを調査し、単一のしきい値だけに依存しないでください。CDN/anti-DDoS の allow-model と比較し、権威ネームサーバーのローテーションを確認して、single flux と double flux を区別します。DGA では、クライアントごとの NXDOMAIN バースト、長さや文字分布、複数ホスト間で同期したクエリ、およびそれらを生成しているプロセスを追加します。MITRE の現在のガイダンスも、高頻度の変更、低 TTL、プロセスとネットワークの相関を重視しています。<sup>[[2]](#references)</sup>

## Domain-fronting 検出

エンタープライズの endpoint または認可された inspection point が両方の識別情報を取得できる場合は、比較します：
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
SNI と authority が無関係な tenant に属している場合、プロセスが承認済みの client ではない場合、session が周期的または長期間継続している場合、さらに内側の origin がまれな場合は、確信度を高めます。空の SNI は記録すべき特徴であり、自動的に悪意があるとは限りません。ECH によって wire 上の SNI が隠される可能性があるため、endpoint、DNS、provider/CDN のログがより重要になります。MITRE は不一致の SNI と blank-SNI の両方の variant を文書化しています。<sup>[[3]](#references)</sup>

## Dead-drop resolver sequence の検出

高いシグナルとなる挙動は、blocked domain ではなく、次のような sequence です：
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
フリート全体を対象に、同一のオブジェクトパス、レスポンスハッシュ、API識別子、後続の接続先を探索する。取得したコンテンツは、攻撃者が編集または削除できるため保存する。不要なサービスAPIを制限し、承認済みアプリケーションに enterprise proxy の使用を義務付ける。ただし、developer tools と自動化は考慮する。MITREは、実際の手順として GitHub、フォーラム、ドキュメント、ソーシャル／Webサービスを挙げている。<sup>[[4]](#references)</sup>

## Redirector と再利用可能なデプロイメントのクラスタリング

ドメインやアドレスが変わっても、operator は同じ自動化を再デプロイすることが多い。以下の組み合わせでクラスタリングする。

- 証明書フィールド／鍵の再利用と発行タイミング；
- TLSバージョン／cipher／extensionの順序とサーバーの挙動；
- 同一の HTTPステータス、ヘッダー順序、cacheの挙動、icon／body、エラーページ；
- 通常とは異なるポートペアと redirect chain；
- DNS provider／name server のパターンと TTL のスケジュール；
- デプロイ時刻、稼働時間、メンテナンス時間帯；
- back-end origin の露出または同一の allowlist。

単一の汎用 Nginx ページは弱い証拠である。複数の稀な独立マッチに加え、時間的な継続性があれば、インフラストラクチャ・クラスター仮説を立てる根拠となる。

## Residential proxy と不可能なセッションの検知

IPレイヤーより上位でセッションの identity を維持する。次のような組み合わせにフラグを立てる。

- 1つのセッション／デバイス fingerprint が、移動で説明できる速度を超えて国／ASNを変更する；
- consumer IP がリクエストごとに変化する一方、cookie と TLS／browser identity は固定されている；
- 申告されたローカルデバイスの latency／time zone／言語が exit と一致しない；
- 1つのアドレスが無関係なアカウント集団を交互に使用する、または backconnect proxy の挙動を示す；
- 特権セッションが、組織の device certificate なしに residential access から現れる。

Carrier NAT、accessibility tools、corporate VPN、旅行によっても無害な異常が生じる。「residential proxy」というラベルだけを根拠に不可逆的な block を行うのではなく、追加認証または調査を要求する。

## Wireless および covert device の検知

RADIUS／NAC を AP および物理的コンテキストと結合する。

1. 初めて確認されたアカウント–デバイス–APの組み合わせを見つける；
2. managed EAP certificate／posture なしで使用された認証情報を特定する；
3. 同時セッションと badge／建物内の存在を比較する；
4. 異常に弱い、または edge の signal と AP間の移動を調査する；
5. 近隣の managed endpoint で、wireless scanning、新たに有効化された interface bridge／NAT、virtual adapter、tunnel を探索する；
6. 新しい switchport、DHCP、USB network、PoE の活動を inventory 化する；
7. 証拠が裏付ける場合、承認済みの RF／物理 sweep を実施する。

これにより、APT28型の最近傍経路と、演習用の drop の両方を検知できる。MAC randomization を identity または有罪の根拠として扱ってはならない。

## Financial-attribution の検知

- 正確な chain、token、address、transaction、block identifier を保存する。
- change、peel chain、fan-out／in、mixer、bridge、service deposit を通じた value の流れを追跡し、heuristic であることを明示する。
- 時刻、手数料控除後の金額、contract event、liquidity、送金先 chain からの withdrawal を相関させる。
- 適法な exchange、bridge、merchant、account、device、delivery の記録を取得または保存する。
- 適用される program に基づき、現在の sanctioned entity／address とその派生物を screening する。古い静的リストに依存してはならない。
- privacy protocol の使用は、違法行為の証明ではなく、risk context への入力として扱う。

FATF の red flag は明確に context 依存である。異常な pattern、金額／頻度、地域、資金源、anonymity-enhancing service は、組み合わさることで意味を持つ。<sup>[[5]](#references)</sup>

## Deception と canary

Defender は、通常のユーザーを deanonymize しようとせずに、高信頼度のシグナルを作成できる。

- 1つのシステムから外部に出るはずのない固有の認証情報またはドキュメント；
- 偽の管理用 endpoint と decoy share；
- 管理下の artifact にのみ埋め込んだ、instrumented DNS name；
- 正当な用途のない canary cloud key；
- managed device が保有していない decoy Wi-Fi identity。

Deception の scope と管理を慎重に行う。canary は defender 自身の asset の不正使用を特定するものであり、無関係な第三者の traffic を収集してはならない。

## 対策の優先順位

1. サポートされていない Internet-facing router、VPN、appliance を撤去する。
2. 内部／wireless access を含め、phishing-resistant MFA と device-bound certificate を必須にする。
3. 変更不能性が十分に確保された identity、endpoint、DNS、flow、proxy、cloud、network-device log を一元化する。
4. management と egress を制限し、外部から到達可能なすべての service を inventory 化する。
5. DNS、certificate transparency、cloud configuration を監視し、未承認の asset を検知する。
6. process-to-network および object-level SaaS の可視性を保持する。
7. cross-layer investigation と隣接 provider 間の coordination を演習する。
8. IP blocklist だけでなく、infrastructure cluster と behavior を追跡する。

## 分析上の規律

確信度を示す言葉を使用する。

- **Observed:** sensor／provider の記録が、その関係を直接示している。
- **Strongly supported:** 複数の独立した観測が、他の可能性よりもその関係を支持している。
- **Assessed:** 明示した仮定と証拠に基づく推論である。
- **Unknown:** 可視性が不足しており、結論を出せない。

常に少なくとも2つの仮説を維持する。actor が運用するインフラストラクチャ対、侵害された／共有された intermediary、単一 actor 対 multi-tenant service、意図的な回避対正当な privacy／CDN behavior である。不確実性を説明できることは、正しい検知の一部である。

## References

- [1] [Google Cloud/Mandiant — China-nexus の espionage actor が ORB network を使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Assets の red flag 指標](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actor が侵害し、persistent access を維持](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — communications infrastructure の visibility 強化および hardening guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
