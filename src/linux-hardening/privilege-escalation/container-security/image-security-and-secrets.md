# イメージのセキュリティ、署名、およびシークレット

{{#include ../../../banners/hacktricks-training.md}}

## 概要

コンテナのセキュリティは、ワークロードが起動する前から始まります。イメージは、どのバイナリ、インタープリタ、ライブラリ、起動スクリプト、および組み込み設定が本番環境に到達するかを決定します。イメージにバックドアが仕込まれていたり、古くなっていたり、シークレットが焼き込まれている場合、その後に行うランタイムのハードニング（runtime hardening）は、すでに改ざんされたアーティファクト上で動作していることになります。

だからこそ、イメージの出所（provenance）、脆弱性スキャン、署名検証、シークレットの取り扱いは、namespaces や seccomp と同じ議論の場に含めるべきです。これらはライフサイクルの別のフェーズを保護しますが、ここでの失敗が後のランタイムが封じ込めなければならない攻撃面を決定することがよくあります。

## イメージレジストリと信頼

イメージは Docker Hub のようなパブリックレジストリから来る場合もあれば、組織が運用するプライベートレジストリから来る場合もあります。セキュリティ上の問題は単にイメージがどこに存在するかではなく、チームがその出所と整合性を確立できるかどうかです。署名されていない、または追跡が不十分なイメージをパブリックソースから取得すると、悪意あるコンテンツや改ざんされたコンテンツが本番環境に入り込むリスクが高まります。内部でホストされたレジストリであっても、明確な所有権、レビュー、信頼ポリシーが必要です。

Docker Content Trust は歴史的に Notary と TUF の概念を用いて、イメージに署名を要求してきました。エコシステムは進化していますが、変わらない教訓は有用です：イメージのアイデンティティと整合性は仮定するのではなく、検証可能であるべきです。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
この例の主旨は、すべてのチームが同じツールを使い続けるべきだということではなく、署名やキー管理が抽象的な理論ではなく運用業務である、という点です。

## 脆弱性スキャン

イメージのスキャンは、2つの異なる問いに答えるのに役立ちます。第一に、イメージに既知の脆弱なパッケージやライブラリが含まれているか。第二に、攻撃対象領域を広げる不要なソフトウェアが含まれているか。デバッグ用ツール、シェル、インタプリタ、古いパッケージだらけのイメージは、悪用されやすく、把握しにくくなります。

一般的に使用されるスキャナーの例には以下があります:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
これらのツールの結果は注意深く解釈する必要があります。未使用のパッケージの脆弱性は公開されたRCEパスと同じリスクではありませんが、どちらもハードニングの判断において重要です。

## ビルド時のシークレット

コンテナのビルドパイプラインで古くからあるミスの1つは、シークレットをイメージに直接埋め込んだり、後で `docker inspect`、ビルドログ、あるいは復元されたレイヤーから見えてしまう環境変数経由で渡すことです。ビルド時のシークレットは、イメージのファイルシステムにコピーするのではなく、ビルド中に一時的にマウントするべきです。

BuildKit は専用のビルド時シークレット処理を可能にすることでこのモデルを改善しました。シークレットをレイヤーに書き込むのではなく、ビルドステップがそれを一時的に消費できます:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
これは、イメージレイヤーが永続的なアーティファクトであるため重要です。シークレットがコミットされたレイヤーに入ると、別のレイヤーで後からファイルを削除しても、イメージの履歴から元の漏洩を完全に取り除くことはできません。

## ランタイムシークレット

稼働中のワークロードが必要とするシークレットは、可能な限りプレーンな環境変数のような場当たり的なパターンを避けるべきです。Volumes、専用のシークレット管理統合、Docker secrets、Kubernetes Secrets は一般的な仕組みです。どれもリスクを完全に排除するわけではなく、特に攻撃者が既にワークロード内でコード実行を得ている場合はそうですが、それでもイメージに認証情報を恒久的に保存したり、検査ツールで軽率に露出させたりするよりは望ましい方法です。

簡単な Docker Compose スタイルのシークレット宣言は次のようになります:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
In Kubernetes, Secret objects、projected volumes、service-account tokens、cloud workload identities はより広く強力なモデルを構築しますが、同時に host mounts、広範な RBAC、または脆弱な Pod 設計を通じて偶発的な露出の機会も増やします。

## 悪用

ターゲットをレビューする際の目的は、secrets が image に組み込まれていないか、layers に leaked していないか、または予測可能な runtime locations に mounted されていないかを発見することです:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
これらのコマンドは、アプリケーション構成のleaks、イメージ層のleaks、ランタイム注入されたシークレットファイルの3つの異なる問題を区別するのに役立ちます。もしシークレットが`/run/secrets`、projected volume、またはcloud identity token pathの下に現れる場合、次に行うべきはそれが現在のワークロードにのみアクセス権を与えるのか、それともより大きなコントロールプレーンにまで及ぶのかを判断することです。

### Full Example: Embedded Secret In Image Filesystem

もしビルドパイプラインが`.env`ファイルや資格情報を最終イメージにコピーしてしまっていた場合、post-exploitationは簡単になります：
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影響はアプリケーションによって異なりますが、embedded signing keys、JWT secrets、または cloud credentials があると、container compromise が容易に API compromise、lateral movement、あるいは信頼されたアプリケーショントークンの偽造につながる可能性があります。

### 完全な例: Build-Time Secret Leakage Check

もし懸念が、image history が secret-bearing layer をキャプチャしていることにあるならば：
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
この種のレビューは有用です。なぜなら、secret が最終的なファイルシステムの表示から削除されていても、以前のレイヤーやビルドメタデータに残っている可能性があるからです。

## チェック

これらのチェックは、image および secret-handling pipeline が実行前に攻撃面を増大させている可能性があるかどうかを確認することを目的としています。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
ここで興味深い点:

- 不審なビルド履歴は、コピーされた credentials、SSH material、または安全でないビルド手順を露呈する可能性があります。
- projected volume paths 以下の Secrets は、ローカルアプリケーションへのアクセスだけでなく、クラスタやクラウドへのアクセスにつながる可能性があります。
- プレーンテキストの credentials を含む大量の設定ファイルは、通常、image やデプロイメントモデルが必要以上の信頼情報を保持していることを示します。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
