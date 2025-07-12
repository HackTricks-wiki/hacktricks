# 低電力広域ネットワーク

{{#include ../../banners/hacktricks-training.md}}

## はじめに

**低電力広域ネットワーク** (LPWAN) は、**低ビットレート**での**長距離通信**を目的とした無線の低電力広域ネットワーク技術のグループです。
これらは**6マイル以上**の距離に到達でき、**バッテリー**は**20年**まで持続することができます。

ロングレンジ (**LoRa**) は、現在最も展開されているLPWANの物理層であり、そのオープンなMAC層仕様は**LoRaWAN**です。

---

## LPWAN、LoRa、およびLoRaWAN

* LoRa – Semtechによって開発されたチャープスプレッドスペクトル (CSS) 物理層（独自だが文書化されている）。
* LoRaWAN – LoRa-Allianceによって維持されているオープンなMAC/ネットワーク層。バージョン1.0.xおよび1.1が現場で一般的です。
* 典型的なアーキテクチャ: *エンドデバイス → ゲートウェイ (パケットフォワーダー) → ネットワークサーバー → アプリケーションサーバー*。

> **セキュリティモデル**は、*ジョイン*手続き中にセッションキーを導出する2つのAES-128ルートキー (AppKey/NwkKey) に依存しています (OTAA) またはハードコーディングされています (ABP)。いずれかのキーが漏洩すると、攻撃者は対応するトラフィックに対して完全な読み書き権限を得ます。

---

## 攻撃面の概要

| レイヤー | 脆弱性 | 実際の影響 |
|-------|----------|------------------|
| PHY | 反応的/選択的ジャミング | 単一のSDRと<1 W出力で100%のパケットロスが実証されました |
| MAC | ジョイン・アクセプトおよびデータフレームのリプレイ (ノンスの再利用、ABPカウンターのロールオーバー) | デバイスの偽装、メッセージの注入、DoS |
| ネットワークサーバー | 不secureなパケットフォワーダー、弱いMQTT/UDPフィルター、古いゲートウェイファームウェア | ゲートウェイでのRCE → OT/ITネットワークへのピボット |
| アプリケーション | ハードコーディングされたまたは予測可能なAppKeys | トラフィックのブルートフォース/復号、センサーの偽装 |

---

## 最近の脆弱性 (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* が、Kerlinkゲートウェイ上のステートフルファイアウォールルールをバイパスするTCPパケットを受け入れ、リモート管理インターフェースの露出を許可しました。4.0.11 / 4.2.1で修正されました。
* **Dragino LG01/LG308シリーズ** – 2022-2024年の複数のCVE（例: 2022-45227 ディレクトリトラバーサル、2022-45228 CSRF）が2025年でも未修正のまま観察されており、数千の公共ゲートウェイで認証なしのファームウェアダンプまたは設定の上書きを可能にします。
* Semtech *パケットフォワーダーUDP* オーバーフロー（未発表のアドバイザリー、2023-10にパッチ適用）：255 Bを超えるアップリンクを作成するとスタックスマッシュが引き起こされ、SX130xリファレンスゲートウェイでのRCEが発生しました（Black Hat EU 2023 “LoRa Exploitation Reloaded”で発見）。

---

## 実践的な攻撃技術

### 1. トラフィックのスニッフィングと復号
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAAジョインリプレイ（DevNonce再利用）

1. 正当な **JoinRequest** をキャプチャします。
2. 元のデバイスが再度送信する前に、すぐに再送信します（またはRSSIを増加させます）。
3. ネットワークサーバーは新しいDevAddrとセッションキーを割り当てますが、ターゲットデバイスは古いセッションを続行します → 攻撃者は空いているセッションを所有し、偽のアップリンクを注入できます。

### 3. 適応データレート（ADR）ダウングレード

SF12/125 kHzを強制してエアタイムを増加させます → ゲートウェイのデューティサイクルを枯渇させます（サービス拒否）し、攻撃者へのバッテリーへの影響を低く保ちます（ネットワークレベルのMACコマンドを送信するだけ）。

### 4. 反応的ジャミング

*HackRF One* がGNU Radioフローフローグラフを実行し、プレアンブルが検出されると広帯域のチープをトリガーします – ≤200 mW TXで全てのスプレッディングファクターをブロックします；2 kmの範囲で完全なアウトageが測定されました。

---

## 攻撃的ツール（2025）

| ツール | 目的 | ノート |
|------|---------|-------|
| **LoRaWAN監査フレームワーク（LAF）** | LoRaWANフレームの作成/解析/攻撃、DBバックのアナライザー、ブルートフォース | Dockerイメージ、Semtech UDP入力をサポート |
| **LoRaPWN** | OTAAをブルートフォースし、ダウンリンクを生成し、ペイロードを復号化するTrend MicroのPythonユーティリティ | 2023年にデモリリース、SDR非依存 |
| **LoRAttack** | USRPによるマルチチャネルスニファー + リプレイ；PCAP/LoRaTapをエクスポート | 良好なWireshark統合 |
| **gr-lora / gr-lorawan** | ベースバンドTX/RX用のGNU Radio OOTブロック | カスタム攻撃の基盤 |

---

## 防御推奨事項（ペンテスターチェックリスト）

1. 真のランダムDevNonceを持つ**OTAA**デバイスを優先し、重複を監視します。
2. **LoRaWAN 1.1**を強制します：32ビットフレームカウンター、異なるFNwkSIntKey / SNwkSIntKey。
3. フレームカウンターを不揮発性メモリ（**ABP**）に保存するか、OTAAに移行します。
4. ルートキーをファームウェア抽出から保護するために**セキュアイレメント**（ATECC608A/SX1262-TRX-SE）を展開します。
5. リモートUDPパケットフォワーダーポート（1700/1701）を無効にするか、WireGuard/VPNで制限します。
6. ゲートウェイを最新の状態に保ちます；Kerlink/Draginoは2024年パッチ済みのイメージを提供します。
7. **トラフィック異常検出**（例：LAFアナライザー）を実装します – カウンターリセット、重複ジョイン、突然のADR変更をフラグします。

## 参考文献

* LoRaWAN監査フレームワーク（LAF） – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Trend Micro LoRaPWNの概要 – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
