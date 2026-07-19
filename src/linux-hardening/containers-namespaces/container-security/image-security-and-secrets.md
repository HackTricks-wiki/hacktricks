# Image のセキュリティ、署名、Secrets

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Container security は workload が起動される前から始まります。Image によって、どの binary、interpreter、library、startup script、埋め込まれた configuration が production に到達するかが決まります。Image に backdoor が仕込まれている、古い状態である、または secrets が組み込まれた状態で build されている場合、その後に行われる runtime hardening は、すでに compromise された artifact に対して動作することになります。

そのため、image provenance、vulnerability scanning、signature verification、secret handling は、namespace や seccomp と同じ議論に含めるべきです。これらは lifecycle の別の phase を保護しますが、この段階での失敗によって、後から runtime が封じ込めなければならない attack surface が決まることがよくあります。

## Image Registry と Trust

Image は Docker Hub などの public registry、または組織が運用する private registry から取得できます。セキュリティ上の問題は、単に image がどこに存在するかではなく、team が provenance と integrity を確認できるかどうかです。public source から unsigned または十分に追跡されていない image を pull すると、悪意のある、または改ざんされた content が production に入り込むリスクが高まります。内部でホストされている registry であっても、明確な ownership、review、trust policy が必要です。

Docker Content Trust は、歴史的に Notary と TUF の概念を使用して signed image を必須にしていました。正確な ecosystem は変化していますが、現在も有効な教訓は残っています。つまり、image の identity と integrity は、仮定するのではなく検証可能にすべきです。

過去の Docker Content Trust workflow の例:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
この例のポイントは、すべてのチームが今も同じ tooling を使い続けなければならないということではなく、signing と key management は抽象的な理論ではなく、運用上のタスクだということです。

## Vulnerability Scanning

Image scanning は、2つの異なる問いへの回答に役立ちます。1つ目は、その image に既知の脆弱な package や library が含まれているかどうかです。2つ目は、その image が attack surface を広げる不要な software を含んでいるかどうかです。debugging tools、shell、interpreter、古い package で満たされた image は、exploit されやすいだけでなく、状況の把握も困難です。

一般的に使用される scanner の例には、次のものがあります。
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
これらのツールの結果は、慎重に解釈する必要があります。未使用のパッケージに存在する脆弱性は、公開されたRCE経路とリスクが同一ではありませんが、どちらもhardeningの判断において関連性があります。

## Build-Time Secrets

containerのbuild pipelineにおける最も古いミスの1つは、Secretsをimageに直接埋め込むこと、または後から`docker inspect`、build logs、復元されたlayerを通じて表示可能になるenvironment variables経由で渡すことです。Build-Time Secretsは、imageのfilesystemにコピーするのではなく、build中に一時的にmountする必要があります。

BuildKitは、専用のBuild-Time Secrets処理を可能にすることで、このモデルを改善しました。Secretをlayerに書き込む代わりに、build stepはSecretを一時的に使用できます。
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
これは、image layerが永続的なartifactだからです。secretがcommit済みのlayerに入ると、後から別のlayerでファイルを削除しても、image historyに残った元の情報開示が真に削除されるわけではありません。

## Runtime Secrets

実行中のworkloadに必要なsecretについても、可能な限り、平文の環境変数のような場当たり的なパターンは避けるべきです。一般的な仕組みとしては、volume、専用のsecret-management integration、Docker secrets、Kubernetes Secretsなどがあります。これらの方法でも、特に攻撃者がすでにworkload内でcode executionを獲得している場合は、すべてのリスクがなくなるわけではありません。それでも、credentialをimage内に永続的に保存したり、inspection toolingを通じて不用意に公開したりするよりは望ましい方法です。

シンプルなDocker Compose形式のsecret宣言は次のようになります。
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
In Kubernetes では、Secret objects、projected volumes、service-account tokens、cloud workload identities によって、より広範で強力なモデルが形成されますが、host mounts、広範な RBAC、または不適切な Pod 設計を通じて、意図せず露出する機会も増えます。

## Abuse

target を確認する際の目的は、secrets が image に組み込まれていたか、layers に leak していたか、または予測可能な runtime locations に mount されていたかを明らかにすることです：
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
これらのコマンドは、application configuration leaks、image-layer leaks、runtime-injected secret filesという3種類の異なる問題を区別するのに役立ちます。`/run/secrets`、projected volume、またはcloud identity token pathの下にsecretが現れた場合、次のステップは、それが現在のworkloadのみにアクセスを許可するのか、それともはるかに広範なcontrol planeへのアクセスを許可するのかを把握することです。

### Image Filesystemに埋め込まれたSecretの完全な例

build pipelineが`.env`ファイルやcredentialsをfinal imageにコピーしていた場合、post-exploitationは単純です。
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影響はアプリケーションによって異なりますが、埋め込まれた signing keys、JWT secrets、または cloud credentials によって、container compromise が容易に API compromise、lateral movement、または信頼されたアプリケーション token の偽造へと発展する可能性があります。

### Build-Time Secret Leakage Check

懸念が image history に secret を含む layer が記録されていることの場合：
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
この種の review は、secret が最終的な filesystem view から削除されていても、以前の layer や build metadata に残っている可能性があるため有用です。

## Checks

これらの checks は、runtime 前に image と secret-handling pipeline によって attack surface が増加した可能性があるかどうかを確認することを目的としています。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
ここで重要な点：

- 不審な build history から、コピーされた credentials、SSH material、または安全でない build steps が明らかになる可能性がある。
- projected volume のパス下にある secrets は、単なるローカルアプリケーションへのアクセスではなく、cluster や cloud へのアクセスにつながる可能性がある。
- plaintext credentials を含む configuration files が大量に存在する場合、通常は image または deployment model が必要以上の trust material を保持していることを示している。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker / BuildKit | secure な build-time secret mounts をサポートしているが、自動ではない | `build` 中に secrets を一時的に mount できるが、image signing と scanning には明示的な workflow の選択が必要 | secrets を image にコピーする、`ARG` または `ENV` で secrets を渡す、provenance checks を無効にする |
| Podman / Buildah | OCI-native builds と secret-aware workflows をサポート | 強力な build workflows を利用できるが、operators は意図的にそれらを選択する必要がある | Containerfiles に secrets を埋め込む、build context を広くする、build 中に permissive な bind mounts を使用する |
| Kubernetes | Native Secret objects と projected volumes | Runtime secret delivery は first-class だが、exposure は RBAC、pod design、host mounts に依存する | Secret mounts を過度に広くする、service-account token を誤用する、kubelet が管理する volumes に `hostPath` でアクセスする |
| Registries | 強制されない限り integrity は任意 | Public と private の registries はどちらも policy、signing、admission の判断に依存する | unsigned images を自由に pull する、admission control が弱い、key management が不十分 |
{{#include ../../../banners/hacktricks-training.md}}
