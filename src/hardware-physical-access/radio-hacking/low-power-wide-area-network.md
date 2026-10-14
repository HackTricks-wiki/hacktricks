# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## はじめに

**Low-Power Wide Area Network**（LPWAN）は、低ビットレートでの**長距離通信**を目的に設計された、無線・低消費電力・広域ネットワーク技術の総称です。
無線パラメータ、アンテナ、規制地域、地形、デューティサイクルによって、LPWANの導入ではスループットと引き換えに、数キロメートルのカバレッジや数年間のバッテリー寿命を実現できます。ベンダーが示す通信距離やバッテリー寿命は保証値ではなく、設計目標として扱ってください。<sup>[[3]](#references)</sup>

Long Range（**LoRa**）は現在、最も広く導入されているLPWAN物理層であり、そのオープンなMAC層仕様が**LoRaWAN**です。

---

## LPWAN、LoRa、LoRaWAN

* LoRa – Semtechが開発したChirp Spread Spectrum（CSS）物理層（プロプライエタリだが仕様は公開されている）。
* LoRaWAN – LoRa-Allianceが管理するオープンなMAC/Network層。バージョン1.0.xと1.1が現場で広く使われている。
* 典型的なアーキテクチャ：*エンドデバイス → ゲートウェイ（packet-forwarder） → network-server → application-server*。<sup>[[3]](#references)</sup>

> LoRaWAN 1.1では、**security model**において、OTAA中に役割別のセッションキーを導出するため、アプリケーション用とネットワーク用のAES-128ルートキーを分けて使用します。以前の1.0.xの導入環境では通常、1つのAppKeyからネットワークおよびアプリケーションのセッションキーを導出します。一方、ABPではセッションキーを直接設定します。そのため、漏えいしたキーで可能になることは、LoRaWANのバージョンと漏えいしたキーの種類によって異なります。<sup>[[3]](#references)</sup>

---

## 攻撃対象領域の概要

| 層 | 脆弱性 | 実際の影響 |
|-------|----------|------------------|
| PHY | リアクティブ／選択的ジャミング | 局所的なパケット損失。効果はリンクバジェット、タイミング、帯域幅、規制上の制約に依存 |
| MAC | nonce/counterの状態が再利用された場合のJoinおよびデータフレームのリプレイ | サーバー／デバイスがリプレイ対策に違反している場合、デバイスの同期ずれ、なりすまし、またはインジェクション |
| Network-Server | 安全でないpacket-forwarder、脆弱なMQTT/UDPフィルター、古いゲートウェイファームウェア | ゲートウェイ上でのRCE → OT/ITネットワークへのピボット |
| Application | ハードコードされた、または予測可能なAppKeys | 通信の総当たり／復号、センサーのなりすまし |

---

## 代表的な実装上の脆弱性

* **CVE-2024-29862** – ChirpStack Gateway Bridge 4.0.11より前のバージョン、およびMQTT Forwarder 4.2.1より前のバージョンでは、TLSサーバー証明書の検証が無効になっていたため、攻撃者が制御するMQTTブローカーに接続する可能性がありました。これにより認証情報やゲートウェイのトラフィックが漏えいするおそれがあります。修正済みバージョンにアップグレードしてください。<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227は、認証なしでアクセスでき、ダウンロード可能なバックアップファイルを含む`/lib/`ディレクトリ一覧表示について記述しています。CVE-2022-45228は、ログアウトページにおける低深刻度のCSRFです。これらの記録は、主張されているLG308への影響、設定の上書き、対象機器数、または2025年時点のパッチ適用状況を裏付けるものではありません。<sup>[[6]](#references)[[7]](#references)</sup>
* このページの以前の版では、Semtech UDP packet-forwarderに関する問題として、**細工された255バイト超のアップリンクによりスタック破壊が起こり、SX130xリファレンスゲートウェイでRCEが可能になる**とする内容が記載されていました。この問題は、Black Hat Europe 2023の「LoRa Exploitation Reloaded」という発表と、2023年10月の非公開パッチに関連付けられていました。これらの具体的な詳細は、調査の手がかりとしてここに残していますが、該当する公開アドバイザリ、発表、パッチは確認できていません。影響を受ける製品／バージョンと検証可能な一次情報を入手するまでは、既知の脆弱性として扱わないでください。

---

## 実践的な攻撃手法

### 1. Sniff & Decrypt トラフィック

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

これらのコマンドは、元のワークフローを**構文例**として示しています。リポジトリの構成やフラグは、プロジェクトやリリースによって異なります。受動的なキャプチャでは、強度の高い AppKey は判明しません。オフラインでの推測が有効なのは、ルートキーが弱く発見可能であり、かつキャプチャした Join 交換から候補を検証できる値が得られる場合に限られます。<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA のリプレイ保護と nonce 状態をテストする

1. 許可されたテストネットワークで、正規の **JoinRequest** をキャプチャする。
2. 同じリクエストをリプレイし、ネットワークサーバーが再利用された `DevNonce` を拒否することを確認する。
3. テストデバイスを再起動またはリセットして、nonce 状態が失われていないか同じテストを繰り返す。準拠したサーバーは使用済み nonce を追跡しなければなりません。JoinRequest をリプレイしただけでは、新たに導出されたセッションキーは漏えいせず、リプレイした側がセッションを制御することもできません。<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) のダウングレード

ネットワーク層の MAC コマンドを認証できる攻撃者は（たとえば、該当するネットワークセッションキーまたはネットワークサーバーを侵害した後）、非効率なデータレートパラメーターを強制し、airtime を増やそうとする可能性があります。近くにいる未認証の送信機は、デバイスアドレスを知っているだけでは、正規の ADR コマンドを発行できません。<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer は LoRa のプリアンブルを検知した後に送信し、フレームを選択的に妨害できます。前のページでは HackRF/GNU Radio の構成により**2 km で 200 mW 以下**の出力で全面的な通信障害が発生したと記載されていましたが、裏付けとなる測定ソースは示されていません。これらの数値は再現目標としてのみ扱い、期待される結果とはみなさないでください。必要な送信出力、タイミング、帯域幅、影響を受ける spreading factor、通信距離は環境によって異なります。テストは許可された RF 遮蔽環境内でのみ行い、現地の電波規制を遵守してください。

---

## Offensive tooling (2025)

| Tool | 用途 | 備考 |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN フレームの作成・解析・攻撃、DB ベースのアナライザー、brute-forcer | Docker image。Semtech UDP 入力に対応<sup>[[1]](#references)</sup> |
| **LoRaPWN** | OTAA の brute、downlink の生成、payload の復号を行う Trend Micro の Python utility | 公開されている研究用 utility。対応する hardware と protocol version を確認すること<sup>[[2]](#references)</sup> |
| **LoRAttack** | マルチチャネル LoRaWAN のキャプチャ、セッション解析、キー導出、リプレイテストを行う研究用 framework | 2024 年の修士論文で説明されています。記載例のフラグに依存する前に、正確な実装を入手して確認してください<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa の baseband 受信または transceiver 研究用の GNU Radio out-of-tree blocks | GNU Radio との互換性や機能セットはプロジェクトによって異なります<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. **OTAA** を優先し、デバイスとサーバーが必要な nonce 状態を永続化することを確認する。拒否された重複 join を監視する。
2. 対応している場合は **LoRaWAN 1.1** を優先し、ネットワーク機能が個別のセッションキーと更新された nonce 処理を使用するようにする。<sup>[[3]](#references)</sup>
3. フレームカウンターを不揮発性メモリーに保存する（**ABP**）か、OTAA に移行する。
4. 適切な **secure element**（たとえば、対応設計での ATECC608A）を導入し、通常の firmware ストレージに保存されたルートキーの露出を減らす。
5. 設定済みの packet-forwarder UDP listener（一般的には 1700）を信頼できないネットワークに公開しない。gateway の backhaul は認証・暗号化するか、VPN で制限する。
6. gateway はベンダーがサポートする firmware を使用し、該当する advisories に照らして正確なモデルとバージョンを確認する。
7. **traffic anomaly detection**（例：LAF analyzer）を実装し、カウンターのリセット、重複 join、急激な ADR 変更にフラグを立てる。<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN の概要](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 仕様](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 の地域パラメーターと join 同期](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU 論文カタログ - SDR Technology を活用した LPWAN Protocol Security Analysis](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
