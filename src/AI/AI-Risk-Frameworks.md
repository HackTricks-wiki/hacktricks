# AI リスク

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OwaspはAIシステムに影響を与えるトップ10の機械学習脆弱性を特定しています。これらの脆弱性は、data poisoning、model inversion、adversarial attacksなど、さまざまなセキュリティ問題を引き起こす可能性があります。これらを理解することは安全なAIシステム構築に不可欠です。

最新かつ詳細なトップ10の一覧については、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) プロジェクトを参照してください。

- **Input Manipulation Attack**: 攻撃者が受信データに微小でしばしば目に見えない変更を加え、モデルに誤った判断をさせます。\
*例*: 停止標識に少量の塗料を付けるだけで、自動運転車がそれを速度制限標識と「認識」してしまう。

- **Data Poisoning Attack**: **training set** が意図的に不正なサンプルで汚染され、モデルに有害な規則を学習させます。\
*例*: マルウェアのバイナリがアンチウイルスの学習コーパスで「benign」と誤ラベルされることで、類似のマルウェアがその後見逃される。

- **Model Inversion Attack**: 出力を探ることで、攻撃者が元の入力の機微な特徴を再構築する**reverse model**を構築します。\
*例*: 癌検出モデルの予測から患者のMRI画像を再現する。

- **Membership Inference Attack**: 攻撃者は信頼度の差を見分けることで、**specific record** が学習に使われたかを判定します。\
*例*: ある人物の銀行取引が不正検知モデルの学習データに含まれていることを確認する。

- **Model Theft**: 繰り返しクエリを行うことで、攻撃者は意思決定境界を学び、**clone the model's behavior**（および知的財産）を複製します。\
*例*: ML-as-a-Service APIから十分なQ&Aペアを収集して、ほぼ同等のローカルモデルを作る。

- **AI Supply‑Chain Attack**: **ML pipeline** 内の任意のコンポーネント（データ、ライブラリ、pre‑trained weights、CI/CD）を侵害して下流のモデルを汚染します。\
*例*: model-hub上の汚染された依存が多数のアプリにバックドア入りの感情分析モデルを配布する。

- **Transfer Learning Attack**: 悪意あるロジックが**pre‑trained model**に植え付けられ、被害者のタスクへのfine‑tuning後も残存します。\
*例*: 隠れたトリガーを持つvision backboneが医用画像用に適応された後でもラベルを反転させる。

- **Model Skewing**: 微妙に偏った、または誤ラベルされたデータがモデルの出力を**shifts the model's outputs** し、攻撃者の意図を有利にします。\
*例*: 「クリーンな」spamメールをhamとして注入し、将来の類似スパムをフィルタが通すようにする。

- **Output Integrity Attack**: 攻撃者がモデル自体ではなく**alters model predictions in transit**して下流システムを騙します。\
*例*: ファイル隔離処理の前にマルウェア分類器の「malicious」判定を「benign」に書き換える。

- **Model Poisoning** --- 書き込み権を獲得した後などに、**model parameters** 自体に直接的・ターゲットを絞った変更を加え、挙動を変えます。\
*例*: 本番の不正検知モデルの重みを調整して特定のカードからの取引だけ常に承認されるようにする。


## Google SAIF Risks

Googleの [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) は、AIシステムに関連するさまざまなリスクを概説しています:

- **Data Poisoning**: 悪意ある者がtraining/tuningデータを改ざん・注入し、精度劣化、バックドア埋め込み、結果の偏りを引き起こし、data-lifecycle全体でモデルの整合性を損ないます。

- **Unauthorized Training Data**: 著作権や機密性のある、または許可されていないデータセットを取り込むと、法的・倫理的・性能上の責任が生じ、モデルが使用を許されていないデータから学習してしまいます。

- **Model Source Tampering**: 供給連鎖や内部者によるモデルコード、依存関係、weightsの改竄は、訓練前後を問わず隠れたロジックを埋め込む可能性があります。

- **Excessive Data Handling**: データ保持やガバナンスの弱さにより、必要以上の個人データが保存・処理され、露出やコンプライアンスリスクが高まります。

- **Model Exfiltration**: 攻撃者がモデルファイル／weightsを盗むことで知的財産の喪失や模倣サービス、追随攻撃を許します。

- **Model Deployment Tampering**: 攻撃者がモデルアーティファクトやservingインフラを改変し、実行中のモデルが検証済みのバージョンと異なり、挙動が変わる可能性があります。

- **Denial of ML Service**: APIへの洪水や“sponge”入力によりcompute/energyを枯渇させ、モデルをオフラインにすることができます（従来のDoS攻撃に類似）。

- **Model Reverse Engineering**: 大量の入出力ペアを収集することで、攻撃者はモデルを複製または蒸留し、模倣製品やカスタマイズされた敵対的攻撃を助長します。

- **Insecure Integrated Component**: 脆弱なプラグイン、エージェント、上流サービスが攻撃者にコード注入や権限昇格の足掛かりを与えます。

- **Prompt Injection**: プロンプト（直接的または間接的）を作成して、システムの意図を上書きする命令を密輸し、モデルに意図しない動作をさせます。

- **Model Evasion**: 綿密に設計された入力がモデルを誤分類させたり、hallucinateさせたり、許可されていない出力をさせ、安全性と信頼を損ないます。

- **Sensitive Data Disclosure**: モデルが学習データやユーザコンテキストからプライベートまたは機密情報を漏洩し、プライバシーや規制に違反します。

- **Inferred Sensitive Data**: モデルが提供されていない個人属性を推定し、推論による新たなプライバシー被害を生み出します。

- **Insecure Model Output**: 消毒されていない応答が有害なコード、誤情報、不適切なコンテンツをユーザーや下流システムに渡します。

- **Rogue Actions**: 自律的に統合されたエージェントが、十分なユーザ監視なしに意図しない実世界の操作（ファイル書き込み、APIコール、購入など）を実行します。

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) は、AIシステムに関連するリスクを理解し軽減するための包括的なフレームワークを提供します。これは、攻撃者がAIモデルに対して使用するさまざまな攻撃手法と戦術を分類するとともに、AIシステムを用いて異なる攻撃を実行する方法も示します。


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻撃者はアクティブなセッショントークンやクラウドAPIの資格情報を盗み、無許可で有料のクラウドホスト型LLMを呼び出します。アクセスはしばしば被害者アカウントを裏で利用するreverse proxies経由で再販されます（例: "oai-reverse-proxy" の展開）。結果として金銭的損失、ポリシー外でのモデル濫用、テナントへの帰属問題が発生します。

TTPs:
- 感染した開発者端末やブラウザからトークンを収集する；CI/CDのシークレットを盗む；leaked cookiesを買う。
- 正規プロバイダへリクエストを転送して上流キーを隠蔽し、多数の顧客を多重化するreverse proxyを立ち上げる。
- enterprise guardrailsやレート制限を回避するために直接base-model endpointsを悪用する。

Mitigations:
- トークンをdevice fingerprint、IPレンジ、client attestationにバインドする；短い有効期限を強制しMFAで更新する。
- キーのスコープを最小限にする（ツールアクセス禁止、可能ならread-only）；異常時にローテーションする。
- policy gatewayの背後でサーバー側で全トラフィックを終了させ、safety filters、経路ごとのクォータ、tenant isolationを強制する。
- 異常な使用パターン（急な支出増、非典型的なリージョン、UA文字列）を監視し、疑わしいセッションを自動取り消しする。
- 長期間有効な静的APIキーよりも、mTLSやIdPが発行した署名付きJWTを優先する。

## Self-hosted LLM推論のハードニング

機密データのためにローカルのLLMサーバを運用することは、クラウドホストAPIとは異なる攻撃面を生みます: inference/debug endpointsはプロンプトをleakする可能性があり、servingスタックは通常reverse proxyを公開し、GPUデバイスノードは大きな `ioctl()` サーフェスを提供します。オンプレのinference serviceを評価または導入する場合は、少なくとも以下の点を確認してください。

### Prompt leakage via debug and monitoring endpoints

inference APIを**マルチユーザの機密サービス**として扱ってください。Debugやmonitoring経路はプロンプト内容、slot state、model metadata、内部キュー情報を露出する可能性があります。`llama.cpp` においては、`/slots` エンドポイントが特に敏感で、各スロットの状態を露出し、slot inspection/managementのためだけに存在します。

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

Example allowlist with nginx:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Rootlessコンテナ（ネットワーク無効・UNIXソケット）

推論デーモンがUNIXソケットでの待ち受けをサポートしている場合は、TCPよりもそちらを優先し、コンテナを**ネットワークスタックなし**で実行してください:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Benefits:
- `--network none` はインバウンド／アウトバウンドの TCP/IP 露出を排除し、rootless コンテナが通常必要とするユーザーモードのヘルパーを回避します。
- UNIX ソケットは、最初のアクセス制御レイヤとしてソケットパスに対して POSIX の permissions/ACLs を適用できます。
- `--userns=keep-id` と rootless Podman は、コンテナの root がホストの root ではないため、コンテナのブレイクアウト時の影響を低減します。
- モデルを読み取り専用でマウントすることで、コンテナ内からのモデル改ざんの可能性を減らします。

### GPU device-node minimization

GPU 対応の推論では、`/dev/nvidia*` ファイルが重要なローカル攻撃対象面になります。これは大規模なドライバ側の `ioctl()` ハンドラや、共有される可能性のある GPU メモリ管理経路を露出させるためです。

- `/dev/nvidia*` を world writable のままにしない。
- `nvidia`、`nvidiactl`、`nvidia-uvm` を `NVreg_DeviceFileUID/GID/Mode`、udev rules、ACLs で制限し、マッピングされたコンテナの UID のみが開けるようにする。
- ヘッドレス推論ホストでは、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` のような不要なモジュールをブラックリスト化する。
- 推論の起動時にランタイムが機会的に `modprobe` するのを許すのではなく、起動時に必要なモジュールだけを事前ロードする。

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp should be used as defense in depth around the inference process:

- Allow only the shared libraries, model paths, socket directory, and GPU device nodes that are actually required.
- Explicitly deny high-risk capabilities such as `sys_admin`, `sys_module`, `sys_rawio`, and `sys_ptrace`.
- Keep the model directory read-only and scope writable paths to the runtime socket/cache directories only.
- Monitor denial logs because they provide useful detection telemetry when the model server or a post-exploitation payload tries to escape its expected behaviour.

Example AppArmor rules for a GPU-backed worker:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## 参考文献
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
