# Image Security、Signing、And Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Container security は workload が起動される前から始まります。image によって、どの binary、interpreter、library、startup script、embedded configuration が production に到達するかが決まります。image に backdoor が仕込まれている、古い状態である、または secret が埋め込まれた状態で build されている場合、その後に行われる runtime hardening は、すでに侵害された artifact に対して実施されることになります。

そのため、image provenance、vulnerability scanning、signature verification、secret handling は、namespace や seccomp と同じ文脈で扱う必要があります。これらは lifecycle の別の段階を保護しますが、ここでの問題が、後から runtime が封じ込めなければならない attack surface を決定することがよくあります。

## Image Registries And Trust

image は Docker Hub のような public registry や、組織が運用する private registry から取得されます。security 上の問題は、単に image がどこに存在するかではなく、team が provenance と integrity を確認できるかどうかです。public source から unsigned または追跡が不十分な image を pull すると、malicious または改ざんされた content が production に入り込む risk が高まります。内部でホストされている registry であっても、明確な ownership、review、trust policy が必要です。

Docker Content Trust は、歴史的に Notary と TUF の概念を使用して signed image を要求していました。正確な ecosystem は進化していますが、変わらず有用な教訓は、image の identity と integrity は仮定するのではなく、検証可能にすべきだということです。

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
この例の要点は、すべてのチームが今でも同じ tooling を使うべきだということではなく、signing と key management は抽象的な理論ではなく、運用上のタスクだということです。

## Vulnerability Scanning

Image scanning は、2つの異なる疑問への回答に役立ちます。1つ目は、その image に既知の脆弱な package や library が含まれているかどうかです。2つ目は、その image が attack surface を拡大する不要な software を持ち込んでいないかどうかです。debugging tools、shell、interpreter、古い package でいっぱいの image は、exploit しやすいだけでなく、把握も困難です。

一般的に使用される scanner の例には、次のようなものがあります：
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
これらの tool の結果は、慎重に解釈する必要があります。使用されていない package の vulnerability は、公開された RCE path と同じ risk ではありませんが、どちらも hardening の判断には関係します。

## Build-Time Secrets

container の build pipeline における最も古いミスの 1 つは、secret を image に直接埋め込むこと、または後から `docker inspect`、build logs、復元された layers を通じて見えるようになる environment variables 経由で渡すことです。Build-time secrets は image の filesystem にコピーするのではなく、build 中に一時的に mount する必要があります。

BuildKit は、専用の build-time secret handling を可能にすることで、このモデルを改善しました。secret を layer に書き込む代わりに、build step は secret を一時的に消費できます。
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
これは、image layerが永続的なartifactだからです。secretがcommit済みのlayerに入ると、後から別のlayerでファイルを削除しても、image historyから元のdisclosureが完全に削除されるわけではありません。

## Runtime Secrets

実行中のworkloadで必要なsecretについても、可能な限りplain environment variableのような場当たり的な方法は避けるべきです。一般的な仕組みとして、volume、専用のsecret-management integration、Docker secrets、Kubernetes Secretsなどがあります。workload内ですでにcode executionを取得しているattackerに対しては、これらの方法でもすべてのriskを排除できるわけではありません。それでも、credentialsをimage内に恒久的に保存したり、inspection toolingを通じて不用意に公開したりするよりは望ましい方法です。

シンプルなDocker Compose形式のsecret declarationは、次のようになります。
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
Kubernetes では、Secret objects、projected volumes、service-account tokens、cloud workload identities によって、より広範で強力なモデルが構築されますが、host mounts、広範な RBAC、または脆弱な Pod 設計を通じて、意図せず情報が露出する機会も増えます。

## Abuse

target をレビューする際の目的は、secrets が image に焼き込まれていないか、layers に leak していないか、または予測可能な runtime locations に mount されていないかを明らかにすることです：
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
これらのコマンドは、application configuration leaks、image-layer leaks、runtime-injected secret filesという3種類の異なる問題を区別するのに役立ちます。secretが`/run/secrets`、projected volume、またはcloud identity token pathの下に存在する場合、次のステップは、それが現在のworkloadにのみアクセスを許可するのか、それともはるかに広範なcontrol planeへのアクセスを許可するのかを把握することです。

### Full Example: Image Filesystemに埋め込まれたSecret

build pipelineが`.env`ファイルやcredentialsをfinal imageにコピーしていた場合、post-exploitationは単純になります。
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
影響は application によって異なりますが、埋め込まれた signing keys、JWT secrets、または cloud credentials によって、container compromise が容易に API compromise、lateral movement、または信頼された application tokens の偽造へと発展する可能性があります。

### 完全な例: Build-Time Secret Leak Check

懸念が image history に secret-bearing layer が記録されていることである場合:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
この種のレビューは、secret が最終的な filesystem view から削除されていても、以前の layer または build metadata に残っている可能性があるため有用です。

## チェック

これらのチェックは、runtime 前に image および secret-handling pipeline が attack surface を増大させた可能性があるかどうかを確認することを目的としています。
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
ここで注目すべき点：

- 不審な build history から、コピーされた credentials、SSH material、または安全でない build steps が明らかになることがあります。
- projected volume paths 配下の Secrets は、ローカル application へのアクセスだけでなく、cluster や cloud へのアクセスにつながる可能性があります。
- plaintext credentials を含む configuration files が大量に存在する場合、通常は image または deployment model が必要以上の trust material を保持していることを示します。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | secure build-time secret mounts をサポートしますが、自動ではありません | `build` 中に Secrets を一時的に mount できますが、image signing と scanning には明示的な workflow の選択が必要です | Secrets を image にコピーする、`ARG` または `ENV` で Secrets を渡す、provenance checks を無効化する |
| Podman / Buildah | OCI-native builds と secret-aware workflows をサポートします | 強力な build workflows を利用できますが、operators は依然として意図的にそれらを選択する必要があります | Containerfiles に Secrets を埋め込む、広範な build contexts、build 中の permissive bind mounts |
| Kubernetes | Native Secret objects と projected volumes | Runtime secret delivery は first-class ですが、exposure は RBAC、pod design、host mounts に依存します | 過度に広範な Secret mounts、service-account token misuse、kubelet-managed volumes への `hostPath` access |
| Registries | 強制されない限り integrity は optional です | Public と private の両方の registries は、policy、signing、admission decisions に依存します | unsigned images を自由に pull する、weak admission control、poor key management |

{{#include ../../../banners/hacktricks-training.md}}
