# 秘匿的な物理アクセスとワイヤレスアクセス

{{#include ../banners/hacktricks-training.md}}

アウトバウンドのランデブー、電源／アップリンクの復旧、デバイスが保持する秘密情報の最小化、キャプチャテスト、発見の可能性を監視する手順を含む、所有者の承認を得た詳細な実装については、[Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)を参照してください。

ネットワーク経路を変えると、見かけ上の物理的な発信元も変わることがあります。高度な攻撃者は、近隣の侵害済みシステム、隠しデバイス、公衆アクセス、セルラーバックホール、衛星受信機を利用し、標的のログにオペレーターとは異なる場所を記録させる可能性があります。これらによって物理的、無線、またはプロバイダー側の証拠が消えるわけではありません。帰属調査の対象が別のデータセットに移るだけです。

## 手法マトリクス

| 手法 | 見かけ上の発信元 | 必要な条件 | 価値の高い証拠 |
|---|---|---|---|
| 近隣のワイヤレスピボット | 標的の隣にある企業／住宅 | デュアルホームホストの侵害と標的のWi-Fiへのアクセス | 近隣ホストのエンドポイントログ、RFアソシエーション、標的側のRADIUS／DHCP |
| 公衆／ゲストネットワーク | 会場のNATまたはトンネル出口 | 合法的なアクセス、またはアクセス制御のバイパス | キャプティブポータル、DHCP、APアソシエーション、CCTV、決済／位置情報記録 |
| 秘匿型ドロップデバイス | 標的／近隣の有線、Wi-Fi、またはセルラーアドレス | 物理的な設置または配送 | スイッチポート／USB、RF、資産台帳、電源、アウトバウンドトンネルのテレメトリ |
| セルラールーター／eSIM | キャリアNATまたは専用APN | モデム／SIM／サブスクリプション | IMEI／IMSI／eSIM、セルセクター、キャリアアカウント、通信タイミング |
| 衛星リンクの悪用 | ビーム照射範囲内の加入者アドレス | プロトコルおよびサービス固有の脆弱性 | RF位置、アップリンクフロー、不自然なRTT／ルーティング、プロバイダー記録 |

## Nearest Neighbor Attack

Volexityは、攻撃者が最終的な標的から離れた場所にいた、2022年のAPT28／GRUによる作戦を記録しました。攻撃者は標的の公開サービスにpassword sprayingを行い、有効な認証情報を取得しましたが、MFAによってインターネットからの直接ログインは阻止されました。一方、標的の企業Wi-FiはMFAなしでその認証情報を受け入れました。攻撃者は標的の物理的な近隣にある組織を侵害し、無線接続が可能なデュアルホームシステムを見つけて、そのシステムを使って標的のWi-Fiに認証しました。Volexityはこれを**Nearest Neighbor Attack**と名付けました。<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

新規性は、これらの要素の組み合わせにあります。オペレーターは標的の場所へ移動せず、インターネットに公開されたサービスの MFA も引き続き機能します。侵害された隣接システムが物理的な近接性を提供し、窃取した標的の認証情報が論理アクセスを提供し、標的の Wi-Fi が境界を越える経路になります。

### 前提条件と可視性

- 近くに、リモート制御が可能で、互換性のある無線機能を備えたシステム、または別の近隣ピボットへのアクセスが必要です。
- 標的の SSID がそのシステムまで届き、Wi-Fi の接続制御が再利用可能な認証情報、証明書、またはデバイス状態を受け入れる必要があります。
- ピボットには多くの場合、オペレーターへの経路と標的の WLAN への経路という、同時に利用できる2つの経路が必要です。
- 標的側には、新しいステーション MAC アドレスと正規のユーザー名が見える一方、対応する管理対象デバイスの証明書、ポスチャ、履歴、または予想される建物への入館記録が見えない場合があります。
- 隣接するエンドポイントのログには、無線スキャン、新しいプロファイル、インターフェースの変更、トンネリング、リモート制御アクティビティが記録されることがあります。

### 検知と防止

1. 企業 Wi-Fi では証明書ベースの EAP-TLS と管理対象デバイスのポスチャを必須にします。インターネット経由で MFA に失敗したパスワードが、無線経由で届いたというだけで十分な認証手段にならないようにします。
2. RADIUS 認証を、MDM/NAC の ID、過去のステーションとデバイスの紐付け、AP の場所、物理アクセスの記録、同時セッションと照合します。
3. アカウントが初めて、通常と異なる AP の端から、管理対象証明書なしで接続した場合、または同じ ID が別の場所でも有効な場合にアラートを出します。
4. インターフェースをブリッジできるエンドポイントを監視します。Windows、Linux、ネットワーク機器で、予期しない WLAN プロファイル、転送/NAT の設定、仮想アダプター、永続的なトンネルを調査します。
5. 適切な AP の配置と送信出力の計画により、不要な電波の漏れを減らします。これは補助的な制御であり、認証の代わりにはなりません。
6. 隣接テナントとインシデント対応を連携します。最後に電波を発信した機器自体が、被害者である可能性があります。

[2組織間の自組織所有ラボ](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)では、隣接組織を攻撃せずにこれらの観測可能な事象を再現します。

### Windows ピボット経路の検証

デュアルホームの Windows ホストは、インターフェースを自動的にブリッジしません。まずアダプター、ルート、WLAN の状態を確認し、その後、承認済みプロファイルを通じてのみ接続します。`netsh wlan connect` の `name` 引数は、任意の SSID とパスワードではなく、インストール済みプロファイルを指定します。接続の前後でルーティングテーブルを比較し、新しいデフォルトルートによって制御経路が切断されたり、結果の妥当性が損なわれたりしないことを確認します。意図したインターフェースとルートを確認してから、[接続後の確認項目](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md)に進みます。<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexityが公開したインシデントのアーティファクトは、もう1つの有用な違いを示しています。埋め込まれたC#はWLAN APIを開き、インターフェースを列挙し、ディスクからEAP XMLを読み込み、最初の無線インターフェース上の名前付きプロファイルに対して`WlanSetProfileEapXmlUserData`を呼び出します。このAPIは既存の802.1XプロファイルにEAPユーザー認証情報を設定しますが、公開されたコンポーネントには`WlanConnect`も、レポートで説明されている検出ロジックも含まれていません。これは完全な接続ツールではなく、プロファイルのプロビジョニングとして扱い、[client and supplicant assessment](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md)の一環として、作成されたプロファイルを調査してください。<sup>[[5]](#references)[[7]](#references)</sup>

## 公共施設および第三者のWi-Fi

カフェ、ホテル、空港、自治体のWi-Fiを利用すると、接続先に表示されるIPアドレスは変わりますが、匿名性が得られるわけではありません。施設またはそのプロバイダーは、APへの接続、デバイスのMACアドレス、DHCPリース、キャプティブポータルのアカウント、SMS/メール認証、通信フローのログを保存している可能性があります。現地への立ち入り、CCTV、購入記録、携帯電話の位置情報、移動記録を照合すれば、デジタル上の行動と個人を結びつけられる場合があります。

攻撃者は、MACアドレスのランダム化、別のデバイスの使用、現金払い、トンネル接続などで、手掛かりを1つ減らそうとする場合があります。それでも、到着時刻、同じ施設への繰り返しの訪問パターン、無線フィンガープリント、ポータルでの操作、通信のタイミング、カメラ映像、トンネルプロバイダーを通じた相関分析が可能です。VPNを使うと、接続先から見えるログの記録先が施設からVPNに移るだけであり、デバイスが施設にあったという事実を施設から隠すことはできません。

公共アクセスを提供する側は、クライアントを分離し、横方向の通信をブロックし、可能であればWPA2/3-Enterpriseまたはデバイスごとのキーを使用し、必要な範囲でDHCP/RADIUS/セキュリティログを保存し、キャプティブポータルを保護し、悪用への対応手順を公開してください。レッドチームは、施設の利用規約とエンゲージメントの許可範囲内でのみ、そのような施設を利用してください。ポータルの回避、アクセス情報の窃取、他の利用者への攻撃は、許可されたテストの近道ではありません。

## Covert drop devicesとWarshipping

ドロップとは、施設内に設置するか施設内へ持ち込み、その後、アウトバウンドEthernet、Wi-Fi、または携帯回線を通じて制御する小型システムです。「Warshipping」では、通常の配送に紛れ込ませてデバイスを無線通信範囲内へ運び込みます。ハードウェアには、シングルボードコンピューターから、改造した充電器、USB周辺機器、ネットワーク機器、バッテリー駆動モデムまで、さまざまなものが考えられます。

運用アーキテクチャ：

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

このデバイスは、リモート foothold の提供、無線測定の実施、許可された演習用 peripheral のエミュレーション、またはトラフィックの中継に利用される可能性があります。発信元はローカルに見えますが、シリアル番号、梱包材、指紋、カメラ、アクセスログ、消費電力、USB descriptor、switchport ネゴシエーション、DHCP fingerprint、MAC OUI／randomization の挙動、RF emissions、定期的な rendezvous 接続といった物理的な痕跡が残ります。

### 防御策

- 荷受け場所と資産管理の手順を整備し、予期しない電子機器や、実在しない職員宛ての荷物を確認する。
- 有線・無線アクセスに 802.1X/NAC を導入し、未使用のポートを無効化して、不明なデバイスを制限付きの remediation VLAN に配置する。
- 新しい DHCP fingerprint、長期間残る locally administered MAC、新しい USB network/HID デバイス、未許可の Wi-Fi Direct/Bluetooth、長時間継続するアウトバウンド tunnel を検知して警告する。
- switchport、Power over Ethernet、DNS、TLS の挙動をベースライン化する。資産記録にない小型ホストが定期的に暗号化接続を行う場合、「Raspberry Pi OUI」だけよりも重要な兆候となる。
- 演習では、資産を記録してラベルを貼り、スコープを定めて暗号化し、リモート kill を用意して回収期限を設定し、紛失しても再利用可能な認証情報が漏れないようにする。

## Cellular と eSIM によるバックホール

Cellular modem は標的のインターネットゲートウェイを回避し、アウトバウンド rendezvous を通じて、carrier NAT の背後でも drop への到達性を維持できます。モバイルアドレスは変更されたり共有されたりする可能性がありますが、cellular operator には依然として強力な加入者情報とネットワーク記録が残ります。これには SIM/eSIM identity、IMSI、device IMEI、割り当てられたアドレス／ポート、cell／sector のタイミング、アカウント／支払い記録、ローミング記録が含まれます。

企業側では、無線／RF 調査、endpoint の USB/PCI inventory、MDM 制限、不正な SSID の監視、物理検査によって、予期しない modem や個人用 hotspot を検出します。cellular を制御用に使う drop も、ローカルの Ethernet/Wi-Fi の挙動や無線放射によって検知できます。

許可された演習では、組織が subscription と modem を所有し、識別子を controller とともに記録して、通信が carrier/provider の利用規約で許可されていることを確認します。プリペイドのラベルや暗号通貨で購入しても、基地局、デバイス、小売店の記録は消去されません。

## MAC randomization とデバイス fingerprinting

最新のシステムでは、ネットワークごとに locally administered なランダム MAC を使用できます。これにより、安定した工場出荷時 MAC による受動的な長期追跡は減りますが、以下は隠せません。

- probe／association のタイミングと、要求するネットワーク機能の種類
- 802.11 information element、対応レート、vendor 固有の挙動
- DHCP option／hostname、IPv6 identifier、captive portal／browser fingerprint
- 認証済み 802.1X identity または certificate
- 上位レイヤーのアカウント、tunnel、トラフィックパターン
- 物理的な観察

防御側は、MAC allowlist を認証手段として使うべきではありません。無線上の identity を certificate／デバイスの posture と結び付け、他の状況に異常がない限り、MAC の変更は通常の挙動として扱います。

## Satellite link の hijacking

Kaspersky は、Turla が古い片方向 DVB-S satellite Internet の脆弱性を利用した事例を記録しています。報告された方式では、正規のリモート加入者は地上回線でアウトバウンド要求を送信しますが、ダウンストリームデータは暗号化されていない広域 satellite broadcast で受信していました。衛星のサービス範囲内にいる攻撃者はダウンリンクを観測し、通信中の加入者 IP を選んで、C2 の応答がその IP 宛てになるように手配できます。正規の加入者と攻撃者の両方が broadcast を受信し、攻撃者は選択したポート宛てのトラフィックを抽出する一方、正規の加入者は未承諾パケットを破棄します。その結果、C2 の運用者は別の地域にある satellite provider のアドレスを使用しているように見えます。<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

これはプロトコル／サービス固有で、帯域幅に制約があり、最新の双方向暗号化衛星端末を侵害することと同等ではありません。また、十分な能力を持つ観測者から、攻撃者のアウトバウンド要求経路を隠すものでもありません。検知の機会としては、非対称／不可能なルーティング、フローを開始していない加入者へのトラフィック、異常な宛先ポート、プロバイダーのテレメトリ、受信機の位置情報／RF調査、マルウェアの設定などがあります。この事例は、C2 IPのジオロケーションによってその制御者の位置も特定できるという思い込みを問い直すために使い、手順書としては使わないでください。

## 物理からデジタルへの相関ワークシート

ローカルに見える送信元が疑わしい場合は、次の手順で1つのタイムラインを作成します。

1. AP、RADIUS、DHCP、DNS、プロキシ、VPN、EDR、スイッチ、物理アクセスの各時刻を正規化する。
2. 最初のアラートだけでなく、最初の無線接続またはリンクアップを特定する。
3. ステーションを、証明書、デバイスのセキュリティ状態、DHCPフィンガープリント、スイッチ／APの場所に対応付ける。
4. 近隣システムで、同時刻のリモート制御／トンネル活動を調べる。
5. 適用されるポリシー／法律に従い、納品記録、訪問者、在庫の例外、カメラ映像、RF調査結果を確認する。
6. 疑わしいデバイスと揮発性ネットワーク状態を保全する。むやみに電源を再投入しない。
7. 見かけ上の送信元が攻撃者の管理するインフラなのか、別の被害者なのかを判断する。

## References

- [1] [Volexity — 最近隣攻撃：ロシアのAPTが近隣のWi-Fiネットワークを武器化した手法](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla：空からのAPTコマンド＆コントロール](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — ハードウェアの追加（T1200）](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — 無線LANのセキュリティに関するガイドライン](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — 編集済みPowerShell/C# WLANプロファイルコード](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData関数](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
