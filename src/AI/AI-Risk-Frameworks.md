# AIのリスク

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASPはAIシステムに影響を与える上位10件の機械学習の脆弱性を特定しています。これらの脆弱性は、data poisoning、model inversion、adversarial attacks などのさまざまなセキュリティ問題につながる可能性があります。安全なAIシステムを構築するには、これらの脆弱性を理解することが重要です。

最新かつ詳細なトップ10リストは、[OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) プロジェクトを参照してください。

- **Input Manipulation Attack**: 攻撃者が**incoming data**に微小でほとんど見えない変更を加え、モデルを誤判断させます。\
*Example*: 停止標識に少量の塗料を付けるだけで、自動運転車がそれを速度制限標識と誤認する。

- **Data Poisoning Attack**: **training set**が意図的に悪意あるサンプルで汚染され、モデルに有害な規則を学習させます。\
*Example*: マルウェアのバイナリがアンチウイルス研修コーパスで「benign」と誤ラベル付けされ、類似マルウェアが後に見逃されるようになる。

- **Model Inversion Attack**: 出力をプローブすることで、攻撃者が元の入力の機密特徴を再構成する**reverse model**を構築します。\
*Example*: がん検出モデルの予測から患者のMRI画像を再構築する。

- **Membership Inference Attack**: 攻撃者が信頼度の差を見分けることで、**specific record**がトレーニングに使われたかどうかを判定します。\
*Example*: ある人物の銀行取引が不正検知モデルのトレーニングデータに含まれていることを確認する。

- **Model Theft**: 繰り返しクエリを行うことで、攻撃者が意思決定境界を学習し**clone the model's behavior**（およびIP）を再現します。\
*Example*: ML-as-a-Service APIから十分なQ&Aペアを収集して、ほぼ同等のローカルモデルを構築する。

- **AI Supply‑Chain Attack**: データ、ライブラリ、pre‑trained weights、CI/CDなどの**ML pipeline**のいずれかのコンポーネントを妥協させ、下流のモデルを破損させます。\
*Example*: model-hub上の依存関係が汚染され、バックドア入りのsentiment‑analysisモデルが多数のアプリに配られる。

- **Transfer Learning Attack**: 悪意あるロジックが**pre‑trained model**に植え付けられ、被害者のタスクでのfine‑tuning後も生き残ります。\
*Example*: 隠れたトリガーを持つvision backboneが医療画像向けに適用された後でもラベルを反転させ続ける。

- **Model Skewing**: 微妙に偏ったあるいは誤ラベル付けされたデータが**shifts the model's outputs**し、攻撃者の意図に有利に働きます。\
*Example*: 「cleanな」スパムメールをhamとして注入し、スパムフィルタが将来の類似メールを通すようにする。

- **Output Integrity Attack**: 攻撃者がモデル自体ではなく**alters model predictions in transit**して、下流のシステムを騙します。\
*Example*: ファイル隔離段階に到達する前にマルウェア分類器の「malicious」判定を「benign」に書き換える。

- **Model Poisoning** --- 直接的に、しばしば書き込み権を得た後に**model parameters**自体を目標にして変更し、挙動を変えます。\
*Example*: 本番の不正検知モデルの重みを調整して、特定のカードからの取引が常に承認されるようにする。


## Google SAIF Risks

Googleの [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) は、AIシステムに関連するさまざまなリスクを示しています：

- **Data Poisoning**: 悪意ある行為者がトレーニング／チューニングデータを改ざんまたは注入して精度を低下させ、バックドアを植え付けたり結果を歪めたりすることで、データライフサイクル全体でモデルの整合性を損ないます。

- **Unauthorized Training Data**: 著作権のある、機密の、または許可されていないデータセットを取り込むと、モデルが使用してはいけないデータから学習するため、法的・倫理的・性能上の責任が生じます。

- **Model Source Tampering**: サプライチェーンや内部関係者によるモデルコード、依存関係、weightsの操作がトレーニング前後に隠れたロジックを埋め込み、再トレーニング後も残存する可能性があります。

- **Excessive Data Handling**: 不十分なデータ保持やガバナンスにより、システムが必要以上に個人データを保存・処理してしまい、露出やコンプライアンスリスクが高まります。

- **Model Exfiltration**: 攻撃者がモデルファイル／weightsを盗むことで、知的財産の喪失や模倣サービス、追随攻撃を可能にします。

- **Model Deployment Tampering**: 攻撃者がモデルアーティファクトやservingインフラを改ざんし、稼働中のモデルが検証済みバージョンと異なり、挙動が変わる可能性があります。

- **Denial of ML Service**: APIを氾濫させたり「sponge」入力を送ることで計算資源／エネルギーを枯渇させ、モデルをオフラインにする。古典的なDoS攻撃に類似します。

- **Model Reverse Engineering**: 多数の入出力ペアを収集することで、攻撃者がモデルをクローンまたは蒸留し、模倣製品やカスタマイズされた敵対的攻撃の材料にします。

- **Insecure Integrated Component**: 脆弱なプラグイン、エージェント、上流サービスは、攻撃者がコード注入や権限昇格を行いAIパイプライン内に侵入する道を開きます。

- **Prompt Injection**: 直接的または間接的にプロンプトを作成して、システムの意図を上書きする命令を密輸し、モデルに意図しない操作を実行させます。

- **Model Evasion**: 注意深く設計された入力がモデルに誤分類、hallucinate、または許可されていない出力を引き起こし、安全性と信頼を損ないます。

- **Sensitive Data Disclosure**: モデルがトレーニングデータやユーザコンテキストから機密情報や私人情報を明らかにし、プライバシーや規制に違反します。

- **Inferred Sensitive Data**: モデルが提供されていない個人属性を推測し、推論を通じて新たなプライバシー被害を生みます。

- **Insecure Model Output**: 消毒されていないレスポンスが有害なコード、誤情報、不適切な内容をユーザや下流システムに渡してしまいます。

- **Rogue Actions**: 自律統合されたエージェントが十分な監視なしに意図しない現実世界の操作（ファイル書き込み、API呼び出し、購入など）を実行します。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) は、AIシステムに関連するリスクを理解し緩和するための包括的なフレームワークを提供します。これは、攻撃者がAIモデルに対して使用するさまざまな攻撃手法と戦術を分類するとともに、AIシステムを使って異なる攻撃を行う方法もまとめています。


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻撃者はアクティブなセッショントークンやクラウドAPI資格情報を盗み、許可なくpaidなcloud-hosted LLMsを呼び出します。アクセスは被害者のアカウントをフロントにするリバースプロキシ（例："oai-reverse-proxy" 展開）を通じて転売されることが多いです。結果として、金銭的損失、ポリシー外でのモデル濫用、被害テナントへの帰属などが発生します。

TTPs:
- 感染したdeveloper machinesやブラウザからトークンを収集；CI/CDのシークレットを盗む；buy leaked cookies。 
- 本物のプロバイダにリクエストを転送するreverse proxyを立ち上げ、upstream keyを隠して多くの顧客を多重化する。
- enterprise guardrailsやrate limitsを回避するために直接base-model endpointsを乱用する。

Mitigations:
- トークンをdevice fingerprint、IPレンジ、client attestationにバインド；短い有効期間を強制しMFAでリフレッシュする。
- keysのスコープを最小限にする（ツールアクセス不可、可能ならread-only）；異常時はローテーションする。
- 各ルートのクォータとテナント分離を強制するポリシーゲートウェイの背後でサーバー側で全トラフィックを終了させ、安全フィルタを適用する。
- 異常な使用パターン（突発的な支出増、通常と異なるリージョン、UA文字列）を監視し、疑わしいセッションを自動的に取り消す。
- 長期の静的API keysよりも、IdP発行のmTLSまたはsigned JWTsを優先する。

## Self-hosted LLM inference hardening

ローカルのLLMサーバを機密データ用に稼働させると、cloud-hosted APIとは異なる攻撃面が生じます：inference/debug endpointsがプロンプトをleakする可能性があり、servingスタックは通常reverse proxyを露出し、GPU device nodesは大きな ioctl() サーフェスへのアクセスを与えます。オンプレのinferenceサービスを評価またはデプロイする場合は、少なくとも以下の点を確認してください。

### Prompt leakage via debug and monitoring endpoints

inference APIを**multi-user sensitive service**として扱ってください。デバッグや監視ルートはプロンプト内容、スロット状態、モデルメタデータ、内部キュー情報を露出する可能性があります。`llama.cpp`では、`/slots`エンドポイントが特に敏感で、スロット毎の状態を露出し、スロット検査／管理専用です。

- inference serverの前にreverse proxyを置き、**deny by default**にする。
- client/UIが必要とする正確なHTTP method + pathの組み合わせだけをallowlistする。
- 可能な限りバックエンド自体でintrospection endpointsを無効にする。例：`llama-server --no-slots`。
- reverse proxyを`127.0.0.1`にバインドし、LAN上に公開する代わりにSSH local port forwardingなどの認証されたトランスポート経由で公開する。

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
### ネットワークなしの Rootless コンテナ と UNIX sockets

推論デーモンが UNIX socket でのリスニングをサポートしている場合は、TCP よりもそちらを優先し、コンテナを **ネットワークスタック無し** で実行してください：
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
利点:
- `--network none` は着信/発信の TCP/IP 露出を除去し、rootless containers が通常必要とする user-mode helpers を回避します。
- UNIX socket により、最初のアクセス制御層としてソケットパスに対して POSIX permissions/ACLs を適用できます。
- `--userns=keep-id` と rootless Podman は、container root が host root ではないため、container breakout の影響を軽減します。
- モデルを読み取り専用でマウントすることで、container 内からの model tampering の可能性を低減します。

### GPU device-node minimization

GPU を用いた推論では、`/dev/nvidia*` ファイルは大きなドライバ `ioctl()` ハンドラや共有されうる GPU メモリ管理経路を露出するため、重要なローカル攻撃対象になります。

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- ヘッドレス推論ホストでは、`nvidia_drm`、`nvidia_modeset`、`nvidia_peermem` のような不要なモジュールをブラックリストに登録してください。
- 推論起動中に runtime が随時 `modprobe` するのを許すのではなく、起動時に必要なモジュールだけをプリロードしてください。

例：
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
- [Unit 42 – Code Assistant LLMs のリスク：有害なコンテンツ、悪用、欺瞞](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (盗まれた LLM アクセスの転売)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - on-premise の低権限 LLM サーバのデプロイに関する詳細解析](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) 仕様](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
