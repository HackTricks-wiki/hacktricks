# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network**（LPWAN）は、低い bit rate での**長距離通信**向けに設計された、wireless、low-power、wide-area network technologies のグループです。
radio parameters、antenna、規制地域、terrain、duty cycle に応じて、LPWAN deployment は throughput と引き換えに、数キロメートル規模の coverage と数年間の battery life を実現できます。vendor が示す range と battery の数値は、保証ではなく design target として扱ってください。<sup>[[3]](#references)</sup>

Long Range（**LoRa**）は現在、最も広く deployment されている LPWAN physical layer であり、その open MAC-layer specification が **LoRaWAN** です。

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Semtech が開発した Chirp Spread Spectrum（CSS）physical layer（proprietary だが文書化されている）。
* LoRaWAN – LoRa-Alliance が維持する Open MAC/Network layer。Versions 1.0.x と 1.1 が field で一般的に使用されている。
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*。<sup>[[3]](#references)</sup>

> LoRaWAN 1.1 では、**security model** は別々の AES-128 application および network root keys を使用し、OTAA 中に role-specific session keys を導出します。以前の 1.0.x deployment では通常、1 つの AppKey を使用して network および application session keys を導出します。一方、ABP では session keys を直接 provision します。leaked key から得られる capability は、LoRaWAN version と、どの key が exposed したかによって異なります。<sup>[[3]](#references)</sup>

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Localized packet loss。effectiveness は link budget、timing、bandwidth、regulatory constraints に依存 |
| MAC | nonce/counter state が再利用された場合の join および data-frame replay | server/device が replay protections に違反すると、device desynchronization、spoofing、または injection |
| Network-Server | Insecure packet-forwarder、weak MQTT/UDP filters、outdated gateway firmware | gateways 上の RCE → OT/IT network への pivot |
| Application | Hard-coded または predictable AppKeys | Brute-force/decrypt traffic、sensors の impersonate |

---

## Representative implementation vulnerabilities

* **CVE-2024-29862** – 4.0.11 より前の ChirpStack Gateway Bridge versions および 4.2.1 より前の MQTT Forwarder versions では、TLS server-certificate validation が disabled だったため、attacker-controlled MQTT broker に接続できました。これにより credentials と gateway traffic が exposed する可能性があります。fixed releases に upgrade してください。<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 は、download 可能な backup file を含む unauthenticated `/lib/` directory listing について説明しています。CVE-2022-45228 は logout page に存在する low-severity CSRF です。これらの records から、主張されている LG308 impact、configuration overwrite、population size、または 2025 patch state が立証されるわけではありません。<sup>[[6]](#references)[[7]](#references)</sup>
* この page の以前の version では、Semtech UDP packet-forwarder に関する alleged issue を、**greater-than-255-byte crafted uplink causing a stack smash and RCE on SX130x reference gateways** と説明していました。この issue は “LoRa Exploitation Reloaded” Black Hat Europe 2023 presentation と October 2023 private patch に帰属されていました。これらの具体的な details は research lead としてここに保持していますが、一致する public advisory、presentation、または patch は corroborate できませんでした。affected product/version と検証可能な primary source を入手しない限り、この issue を既知の vulnerability として扱わないでください。

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
これらのコマンドは、元のワークフローを**説明用の構文**として維持しています。リポジトリの構成やフラグは、プロジェクトやリリースによって異なります。Passive capture では強力な AppKey は明らかになりません。Offline guessing が有効なのは、root key が発見できるほど弱く、なおかつ取得した join exchange に候補を検証できる値が含まれている場合に限られます。<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay protection と nonce state のテスト

1. 認可されたテストネットワークで、正規の **JoinRequest** を取得します。
2. 同じ request を Replay し、ネットワークサーバーが再利用された `DevNonce` を拒否することを確認します。
3. テストデバイスを再起動または reset して、この確認を繰り返し、nonce state の消失を検出します。準拠したサーバーは使用済み nonce を追跡する必要があります。JoinRequest を Replay しただけでは、新たに導出された session keys は開示されず、Replay 実行者が session を制御できるようにもなりません。<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) downgrading

network-layer MAC commands を認証できる攻撃者（たとえば、該当する network session key または network server を compromise した後）は、非効率な data-rate パラメータを強制し、airtime を増加させようとする可能性があります。近隣の unauthenticated transmitter は、デバイスアドレスを知っているだけでは、正当な ADR commands を発行できません。<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer は LoRa preamble を検出した後に送信し、フレームを選択的に妨害できます。以前のページでは、HackRF/GNU Radio の構成により、**200 mW 以下で 2 km** の範囲を完全に停止させられると主張していましたが、裏付けとなる測定ソースは提示されていませんでした。したがって、これらの数値は期待される結果ではなく、再現目標としてのみ扱ってください。必要な送信出力、タイミング、帯域幅、影響を受ける spreading factors、到達距離は環境によって異なります。テストは認可された RF-contained setup 内でのみ実施し、地域の spectrum rules に従ってください。

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames の作成・解析・attack、DB-backed analyzers、brute-forcer | Docker image。Semtech UDP input をサポート<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro の Python utility。OTAA の brute、downlinks の生成、payloads の decrypt | Public research utility。対応する hardware と protocol versions を確認してください<sup>[[2]](#references)</sup> |
| **LoRAttack** | multi-channel LoRaWAN capture、session analysis、key derivation、replay testing 向けの research framework | 2024 年の master's thesis で説明されています。example flags に依存する前に、正確な実装を入手して確認してください<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband reception または transceiver research 向けの GNU Radio out-of-tree blocks | GNU Radio との互換性や feature set はプロジェクトごとに異なります<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. **OTAA** を優先し、デバイスとサーバーが必要な nonce state を persist することを確認します。拒否された duplicate joins を monitor します。
2. 対応している場合は **LoRaWAN 1.1** を優先し、network functions が個別の session keys と更新された nonce handling を使用するようにします。<sup>[[3]](#references)</sup>
3. frame-counter を non-volatile memory（**ABP**）に保存するか、OTAA に migrate します。
4. 適切な **secure element**（たとえば、対応する設計での ATECC608A）を導入し、通常の firmware storage 内にある root keys の exposure を低減します。
5. 設定済みの packet-forwarder UDP listeners（一般的には 1700）を untrusted networks に expose しないでください。gateway backhaul を authenticate/encrypt するか、VPN で restrict します。
6. gateways を vendor-supported firmware に保ち、該当する advisories に対して正確な model/version を確認します。
7. **traffic anomaly detection**（例：LAF analyzer）を実装し、counter resets、duplicate joins、突然の ADR changes に flag を立てます。<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN の概要](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 仕様](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 の regional parameters と join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - SDR Technology を活用した LPWAN Protocol Security Analysis](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
