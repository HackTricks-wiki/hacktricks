# Attribution、Detection、Countermeasures

{{#include ../banners/hacktricks-training.md}}

Attribution-evasion infrastructureは、個々のindicatorを使い捨て可能にするよう設計されています。Defenderはraw evidenceを保持し、関係性をモデル化し、IP、domain、personaが変更されても残るbehaviorをhuntすべきです。

## Evidence hierarchy

| Evidence | Useful for | Main caveat |
|---|---|---|
| Source IP/ASN/geolocation | 目に見えるexitとproviderの特定 | exitはrelay、NAT、またはvictimの可能性があり、geolocationはおおよそのもの |
| Passive DNS/registration | infrastructureの履歴とco-hosting | privacy/redactionとshared hostingによって欠落が生じる |
| Certificate/TLS/HTTP fingerprint | 繰り返されるdeploymentのcluster化 | 一般的なsoftwareとmimicryによってfalse positiveが生じる |
| Flow timing and byte shape | relay stagesと繰り返されるbeaconの関連付け | CDN/NATと限られたvisibilityによって確度が低下する |
| Endpoint process/identity | なぜconnectionが発生したのかの説明 | edge/IoTには存在せず、attackerはnative toolsを使用する可能性がある |
| Cloud/CDN/API audit | tenantとinfrastructure controlの特定 | retentionとprovider/legal accessにはばらつきがある |
| Payment/account/device | procurementと人物/entityの関連付け | nominee、compromise、shared devicesを考慮する必要がある |
| Seized implant/configuration | keys、peers、controllers、build linksの露見 | collection integrityとseizureの時期が重要 |
| Human/physical evidence | digital eventと場所/operatorの関連付け | 侵襲的で、jurisdictionに依存し、厳格な取り扱いが必要 |

単一の行だけで、high-confidenceなstate attributionを成立させるべきではありません。競合する仮説を用い、それぞれを反証する観測結果を明示してください。

## Minimum telemetry

1. **DNS:** client、question、type、answers、TTL、response code、resolver、timestamp。
2. **Network flow:** source/destination/port、start/end、packets/bytes、TCP flags、sensor location。
3. **TLS/HTTP:** 表示可能な場合のSNI、certificate、negotiated protocol、client/server fingerprint、method、authority/path category、status、byte count。機密性の高いfull URLsを保護する。
4. **Identity:** authentication result、factor/certificate/device、source、application、session ID、risk decision。
5. **Endpoint:** initiating process、parent、user、binary signature/hash、destination。
6. **Edge/network device:** configuration diff、admin login、process/file/firmware integrity、interface、flow logs。
7. **Cloud/SaaS/CDN:** actor、tenant/project、API action、source、object/resource、token、result。
8. **Wireless/NAC:** station、randomized-MAC flag、AP、signal、EAP identity/certificate、assigned VLAN/IP、posture。

Clockを同期し、original time zonesを保持し、NAT/proxy boundariesを文書化し、31日間存続するORB nodeを上回るのに十分な履歴を保持してください。

## Build an attribution graph

観測結果を、typed nodesとedgesとして表現します。
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
有用なノードには、IP、prefix、ASN、domain、DNS account、certificate/key、JA3/JA4-like fingerprint、HTTP grammar、file/config hash、cloud tenant、API token、email、persona、payment instrument、physical deviceなどがあります。すべてのエッジには、`first_seen`、`last_seen`、sensor/source、confidence、および observed か inferred かを示す情報が必要です。

グラフの密度だけで判断するのは誤解を招きます。CDNやcertificate authorityは、関係のない多数のアクターを接続します。一般的なhostingよりも、同一のAPI account、SSH key、origin allowlist、固有のresponse body、control protocolなど、operatorが管理する希少な関係に大きな重みを付けます。

## ORBとcompromised-router hunting

### 観測されたexitから

1. そのaddressがhosting、residential、mobile、education、businessのいずれに該当するかを判定します。residential sourceを除外してはいけません。
2. 限定した期間について、過去のDNS、services/certificates、open ports、観測されたscan/exploitation behaviorを取得します。
3. 希少なservice fingerprint、controller destination、certificate material、rotation timingを共有するpeerを検索します。
4. 想定されるroleを、access、traversal、exit/staging、administrationに分類します。
5. 複数の無関係なintrusion clusterが同じpoolを使用していないか確認します。multi-tenancyは直接的なactor attributionの確度を弱めますが、ORB hypothesisを強化します。
6. 古いIPが消失した後、role profileに一致する新しいnodeを追跡します。

### network owner側

- 新たにInternetへ公開されたmanagement、およびdefault/legacy authenticationを検知します。
- router/firewall/VPN configuration changesとadmin authenticationをdevice外へ送信します。
- 通常はほとんどsessionを開始しないinfrastructureからのoutbound connectionをbaseline化します。
- 新しいproxy/listener process、tunnel、scheduled task、firmware change、予期しないDNSを検知します。
- end-of-life deviceを交換します。rebootによってvolatile malwareが削除されても、exposureは解消されません。
- managementをauthenticated administration planeと既知のsourceに限定します。

Mandiantは、短期間のIP blockingではtopologyとlifecycleを把握できないため、ORB infrastructureを変化するentityとして追跡することを推奨しています。<sup>[[1]](#references)</sup>

## Fast-fluxとdynamic-DNS analytics

registered domainとsliding windowごとに集約します。実用的なscoreには、次の要素を組み合わせることができます。
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
複数の独立した特徴を持つドメインを調査し、単一のしきい値だけに依存しないでください。CDN/anti-DDoS の許可モデルと比較し、権威ネームサーバーのローテーションを確認して、single flux と double flux を区別します。DGA については、クライアントごとの NXDOMAIN バースト、長さ/文字分布、ホスト間で同期したクエリ、およびそれらを生成しているプロセスを追加します。MITRE の最新のガイダンスでも、高頻度の変更、短い TTL、プロセスとネットワークの相関が重視されています。<sup>[[2]](#references)</sup>

## Domain-fronting detection

企業のエンドポイントまたは認可された検査ポイントが両方の識別情報を取得できる場合は、比較します：
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
SNI と authority が無関係なテナントに属している、プロセスが承認済みのクライアントではない、セッションが周期的または長時間継続している、そして内部の origin が稀である場合は、確信度を高めます。空の SNI は記録すべき特徴であり、自動的に悪意があることを示すものではありません。ECH によって wire 上の SNI が隠される可能性があるため、endpoint、DNS、provider/CDN のログがより重要になります。MITRE は不一致の SNI と空の SNI の両方のバリエーションを記載しています。<sup>[[3]](#references)</sup>

## Dead-drop resolver シーケンスの検出

高シグナルな挙動は、ブロックされたドメインではなく、次のようなシーケンスです：
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
フリート全体を対象に、同一のオブジェクトパス、レスポンスハッシュ、API識別子、後続の接続先をハントする。取得したコンテンツは、攻撃者が編集または削除できるため保存する。不要なサービスAPIを制限し、承認済みアプリケーションにはエンタープライズプロキシの使用を義務付ける。ただし、開発者ツールや自動化は考慮する。MITREは、実際の手順において GitHub、フォーラム、ドキュメント、ソーシャル/Webサービスを挙げている。<sup>[[4]](#references)</sup>

## Redirectorと再利用可能なデプロイメントのクラスタリング

ドメインやアドレスが変わっても、オペレーターは同じ自動化を再デプロイすることが多い。次の組み合わせでクラスタリングする。

- 証明書フィールド/鍵の再利用と発行タイミング
- TLSバージョン、暗号スイート、拡張機能の順序、サーバーの挙動
- 同一のHTTPステータス、ヘッダー順序、キャッシュ挙動、アイコン/本文、エラーページ
- 通常とは異なるポートの組み合わせとリダイレクトチェーン
- DNSプロバイダー/ネームサーバーのパターンとTTLスケジュール
- デプロイ時刻、稼働時間、メンテナンス時間帯
- バックエンドのオリジン露出、または同一の許可リスト

単一の汎用Nginxページは、証拠として弱い。複数の稀な独立一致に時間的な連続性が加われば、インフラストラクチャ・クラスタ仮説を立てる根拠になる。

## Residential proxyと不可能なセッションの検知

IPレイヤーより上位でセッションのアイデンティティを維持する。次のような組み合わせにフラグを立てる。

- 1つのセッション/デバイスフィンガープリントが、移動では説明できない速さで国/ASNを変更する
- CookieとTLS/ブラウザーのアイデンティティが固定されたまま、コンシューマーIPがリクエストごとに変化する
- 申告されたローカルデバイスのレイテンシー、タイムゾーン、言語が出口側と一致しない
- 1つのアドレスが無関係なアカウント集団を交互に使用する、または backconnect proxy の挙動を示す
- 特権セッションが、組織のデバイス証明書なしに Residential access から出現する

Carrier NAT、アクセシビリティツール、企業VPN、移動によって、正当な異常が生じる。単に「Residential proxy」というラベルだけを根拠に不可逆的なブロックを行うのではなく、追加認証または調査を要求する。

## Wirelessと秘匿デバイスの検知

RADIUS/NACをAPおよび物理的コンテキストと結合する。

1. 初めて確認されたアカウント–デバイス–APの組み合わせを特定する
2. 管理対象のEAP証明書/ポスチャなしで使用された認証情報を特定する
3. 同時セッションとバッジ/建物内の存在を比較する
4. 異常に弱い、または境界的な信号と、AP間の移動を調査する
5. 近隣の管理対象エンドポイントで、Wireless scanning、新たに有効化されたインターフェースブリッジ/NAT、仮想アダプター、トンネルを検索する
6. 新しいswitchport、DHCP、USB network、PoEのアクティビティをインベントリ化する
7. 証拠が裏付ける場合、承認済みのRF/物理スイープを実施する

これにより、APT28-styleの最近傍経路と、演習用のdropの両方を検知できる。MAC randomizationをアイデンティティや有罪の根拠として扱ってはならない。

## Financial-attributionの検知

- 正確なチェーン、トークン、アドレス、トランザクション、ブロック識別子を保存する。
- change、peel chain、fan-out/in、mixer、bridge、service depositを通じて価値を追跡し、ヒューリスティックであることを明示する。
- 時刻、手数料控除後の金額、contract event、流動性、destination-chain withdrawalを相関させる。
- 合法的な手段で取得または保存されたexchange、bridge、merchant、account、device、deliveryの記録を確保する。
- 適用されるプログラムに基づき、現在の制裁対象エンティティ/アドレスと派生対象をスクリーニングする。古い静的リストに依存してはならない。
- privacy protocolの使用はリスクコンテキストへの入力として扱い、不正行為の証拠とはしない。

FATFのレッドフラグは明確にコンテキスト依存である。異常なパターン、金額/頻度、地理、資金源、匿名性を高めるサービスは、組み合わさることで意味を持つ。<sup>[[5]](#references)</sup>

## Deceptionとcanary

防御側は、通常のユーザーの匿名化を試みることなく、高信頼度のシグナルを作成できる。

- 1つのシステムから外部に出るはずのない一意の認証情報またはドキュメント
- 偽の管理エンドポイントとdecoy share
- 管理下のアーティファクトにのみ埋め込まれた、計装済みのDNS名
- 正当な用途のないcanary cloud key
- 管理対象デバイスが保有しないdecoy Wi-Fi identity

Deceptionの範囲と運用を慎重に管理する。canaryは、防御側自身のアセットの不正使用を特定するものであり、無関係な第三者のトラフィックを収集するものであってはならない。

## Countermeasureの優先順位

1. サポート対象外のインターネット公開router、VPN、applianceを排除する。
2. 内部/Wireless accessを含め、phishing-resistant MFAとdevice-bound certificateを要求する。
3. identity、endpoint、DNS、flow、proxy、cloud、network-deviceのログを、十分な改ざん耐性を持つ形で一元化する。
4. 管理とegressを制限し、外部から到達可能なすべてのサービスをインベントリ化する。
5. DNS、certificate transparency、cloud configurationを監視し、未承認のアセットを検知する。
6. process-to-networkとオブジェクトレベルのSaaS可視性を維持する。
7. レイヤー横断の調査と、近隣プロバイダーとの連携を演習する。
8. IP blocklistだけでなく、インフラストラクチャのクラスタと挙動を追跡する。

## 分析上の規律

確信度を示す表現を使用する。

- **Observed:** センサー/プロバイダーの記録が、その関係を直接示している。
- **Strongly supported:** 複数の独立した観測が、他の可能性よりもその関係を支持している。
- **Assessed:** 明示した前提と証拠に基づく推論である。
- **Unknown:** 可視性が不足しており、結論を出せない。

常に少なくとも2つの仮説を維持する。攻撃者が運用するインフラストラクチャか、侵害された/共有された中継点か。単一の攻撃者か、マルチテナントサービスか。意図的な回避か、正当なprivacy/CDNの挙動か。不確実性を説明できることも、正しい検知の一部である。

## References

- [1] [Google Cloud/Mandiant — China-nexusの諜報アクターが ORB networks を使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Assetsのレッドフラグ指標](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRCのアクターによる侵害と永続的アクセスの維持](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — 通信インフラストラクチャの可視性向上とhardeningに関するガイダンス](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
