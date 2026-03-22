# イメージのセキュリティ、署名、そしてシークレット

{{#include ../../../banners/hacktricks-training.md}}

## 概要

コンテナのセキュリティはワークロードが起動する前から始まります。イメージはどのバイナリ、インタプリタ、ライブラリ、起動スクリプト、および組み込まれた設定が本番環境に届くかを決定します。イメージにバックドアが仕込まれている、古くなっている、あるいはシークレットが埋め込まれた状態でビルドされている場合、その後に行うランタイムのハードニングは既に侵害されたアーティファクト上で実行されることになります。

このため、イメージの出所(provenance)、脆弱性スキャン、署名の検証、シークレットの扱いは、namespaces や seccomp と同じ議論の場にあるべきです。これらはライフサイクルの別段階を保護しますが、ここでの失敗が後のランタイムが対処すべき攻撃面を決定することが多いです。

## イメージレジストリと信頼

イメージは Docker Hub のような公開レジストリから来ることも、組織が運用するプライベートレジストリから来ることもあります。セキュリティ上の問題は単にイメージがどこにあるかではなく、チームが出所と完全性を確立できるかどうかです。公開ソースから署名されていない、または追跡が不十分なイメージをプルすると、悪意あるものや改ざんされたコンテンツが本番環境に入り込むリスクが高まります。内部でホストされているレジストリであっても、明確な所有権、レビュー、信頼ポリシーが必要です。

Docker Content Trust は歴史的に Notary と TUF の概念を使って署名されたイメージを要求してきました。エコシステムは進化しましたが、残る教訓は有用です：イメージの識別性と完全性は仮定するのではなく検証可能であるべきです。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
この例の要点は、すべてのチームが同じツールを使い続けるべきだということではなく、signingとkey managementは抽象的な理論ではなく運用上のタスクである、という点です。

## 脆弱性スキャン

イメージのスキャンは、2つの異なる問いに答えるのに役立ちます。まず、そのイメージに既知の脆弱なパッケージやライブラリが含まれているか。次に、そのイメージに攻撃対象を広げる不要なソフトウェアが含まれていないか。デバッグツール、シェル、インタプリタ、古いパッケージで満たされたイメージは、悪用されやすく、また扱いにくくなります。

Examples of commonly used scanners include:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
これらのツールからの結果は注意深く解釈する必要があります。使われていないパッケージの脆弱性は露出したRCE経路のリスクと同等ではありませんが、どちらもハードニングの判断において重要です。

## Build-Time Secrets

コンテナのビルドパイプラインで古くからあるミスの一つは、シークレットをイメージに直接埋め込んだり、後で`docker inspect`やビルドログ、復元されたレイヤーから見えてしまう環境変数経由で渡すことです。ビルド時のシークレットは、イメージのファイルシステムにコピーするのではなく、ビルド中に一時的にマウントするべきです。

BuildKitは、専用のビルド時シークレット処理を可能にすることでこのモデルを改善しました。シークレットをレイヤーに書き込む代わりに、ビルドステップはそれを一時的に消費できます:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
これは image layers が耐久性のあるアーティファクトであるため重要です。一度 secret が committed layer に入ると、別のレイヤでファイルを後から削除しても、元の開示が image history から完全に除去されるわけではありません。

## Runtime Secrets

実行中のワークロードで必要な secret は、可能な限り plain environment variables のようなその場しのぎのパターンを避けるべきです。Volumes、dedicated secret-management integrations、Docker secrets、Kubernetes Secrets は一般的なメカニズムです。これらはいずれもリスクを完全に取り除くわけではなく、特に攻撃者がすでにワークロード内で code execution を持っている場合はそうですが、それでもイメージに credentials を恒久的に保存したり、inspection tooling を通じて軽率に公開するよりは望ましい選択です。

A simple Docker Compose style secret declaration looks like:
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
In Kubernetesでは、Secret objects、projected volumes、service-account tokens、cloud workload identities によってより広範で強力なモデルが生まれますが、host mounts、広範な RBAC、または脆弱な Pod 設計を通じて偶発的な露出の機会も増えます。

## 悪用

ターゲットをレビューする際の目的は、secrets がイメージに組み込まれているか、layers に leaked しているか、または予測可能な runtime ロケーションに mounted されているかを発見することです:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
これらのコマンドは、次の3つの異なる問題を区別するのに役立ちます: application configuration leaks、image-layer leaks、およびランタイム注入されたシークレットファイル。`/run/secrets`、projected volume、またはクラウドの identity token パスの下に secret が存在する場合、次のステップはそれが現在のワークロードのみにアクセス権を与えるのか、より大きなコントロールプレーンにまで及ぶのかを判断することです。

### 完全な例: イメージファイルシステムに埋め込まれたシークレット

ビルドパイプラインが `.env` ファイルや認証情報を最終イメージにコピーしていた場合、post-exploitation は簡単になります:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影響はアプリケーションによって異なりますが、埋め込まれた署名キー、JWT secrets、または cloud credentials は、container compromise を容易に API compromise、lateral movement、または信頼されたアプリケーショントークンの forgery に変え得ます。

### フル例: Build-Time Secret Leakage Check

もし懸念がイメージの履歴が秘密を含むレイヤをキャプチャしていることにある場合:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
この種のレビューは有用です。なぜなら、secret が最終的なファイルシステムの表示から削除されていても、以前のレイヤーやビルドメタデータに残っている可能性があるからです。

## チェック

これらのチェックは、image と secret-handling pipeline がランタイム前に攻撃面を拡大している可能性があるかどうかを判断することを目的としています。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
ここで注目すべき点:

- 疑わしい build history はコピーされた認証情報、SSH 関連の情報、または安全でないビルド手順を明らかにする可能性がある。
- Secrets が projected volume パス下に存在すると、ローカルアプリケーションへのアクセスだけでなくクラスタやクラウドへのアクセスにつながる可能性がある。
- プレーンテキストの認証情報を含む多数の設定ファイルは、image やデプロイメントモデルが必要以上の信頼情報を持ち運んでいることを示すことが多い。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | 安全なビルド時シークレットマウントをサポートするが、自動ではない | シークレットは`build`中に一時的にマウントできる。イメージの署名やスキャンは明示的なワークフロー選択が必要 | シークレットをイメージにコピーする、`ARG`や`ENV`でシークレットを渡す、由来チェックの無効化 |
| Podman / Buildah | OCIネイティブのビルドとシークレット対応ワークフローをサポート | 強力なビルドワークフローは利用可能だが、オペレータが意図的にそれらを選択する必要がある | Containerfilesにシークレットを埋め込む、広範なビルドコンテキスト、ビルド中の寛容なバインドマウント |
| Kubernetes | ネイティブなSecretオブジェクトとprojectedボリューム | ランタイムでのシークレット配布はファーストクラスだが、暴露はRBAC、Pod設計、ホストマウントに依存する | 過度に広いSecretマウント、service-accountトークンの誤用、`hostPath`経由でのkubelet管理ボリュームへのアクセス |
| Registries | 強制されない限り整合性は任意 | パブリックとプライベートの両方のレジストリはポリシー、署名、アドミッション判断に依存する | 署名されていないイメージを自由にpullすること、弱いアドミッションコントロール、貧弱なキー管理 |
{{#include ../../../banners/hacktricks-training.md}}
