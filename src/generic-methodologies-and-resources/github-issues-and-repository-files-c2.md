# GitHub Issues 和 Repository Files 作为 C2 通道

{{#include ../banners/hacktricks-training.md}}

私有 repository 可以将**会话状态**与**payload 传输**分开：issues 记录每台主机及其握手状态，而 repository 文件则在两个方向传输加密数据。这不仅仅是轮询 issue 正文来获取命令。观察到的实现使用 GitHub personal access token (PAT) 访问这两个 API。<sup>[[1]](#references)</sup> 对于 fine-grained PAT，创建或更新 issues 需要 Issues 写入权限，上传文件需要 Contents 写入权限。classic PAT 则需要 `repo` scope。任何获得权限足够的 token 的人都能访问同一通道。<sup>[[2]](#references)[[3]](#references)</sup>

## Issue 和文件握手

一种观察到的工作流使用短十六进制主机 ID 和以下状态机。具体的 ID 范围、字符串和前缀是协议标记，并非 GitHub API 的要求。<sup>[[1]](#references)</sup>

1. 启动时，使用 `GET /repos/{owner}/{repo}/issues?state=open`（以及 `state=closed`）查询 open 和 closed issues，以查找之前的会话状态。使用 `POST /repos/{owner}/{repo}/issues` 创建标题为 `1[ID]`、正文为 `hel` 的 open issue。
2. 读取一个名称以 `2[ID]` 开头的 repository 文件；该文件提供服务器的 RSA 公钥。生成一个新的 16 字节会话密钥，用 RSA 加密后，将结果上传到一个前缀为 `1[ID]` 的文件中。
3. 通过将嵌入的 IV 与该会话密钥进行 XOR，推导后续 IV。对于每个交换的文件，使用其文件名中的随机 16 字节密钥对内容进行 AES 加密或解密。前缀 `2` 表示服务器到主机的数据；前缀 `1` 表示主机到服务器的数据。因此，文件名携带路由信息和每个文件的密钥材料，而 issue 携带状态。
4. 读取下一个带 `2` 前缀的文件，并要求其解密后的内容等于 `hel`。上传加密后的主机信息，然后通过 `PATCH /repos/{owner}/{repo}/issues/{issue_number}` 将 issue 正文改为 `hey`。只有完成这些步骤后，才开始轮询命令。

GitHub 的 Contents API 使用 `GET /repos/{owner}/{repo}/contents/{path}` 读取文件，并使用该路径上的 `PUT` 创建或替换文件。对于不超过 1 MB 的文件，默认 JSON 响应会包含 Base64 编码的内容；对于 1 到 100 MB 的文件，则需要使用 raw media type 才能获取内容。上传请求正文需要包含 commit message 和 Base64 编码的文件内容；替换现有文件时还需要其当前的 blob SHA。这些 API 细节与上述加密协议并不相同。<sup>[[2]](#references)[[3]](#references)</sup>

对于经过授权的测试 repository，可以使用 REST API 测试 issue 控制部分（替换为测试 repository 和测试 PAT）。不要将有效 token 放在 URL、issue 正文或已提交的文件中。<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

这种机制**不**要求使用此处展示的 issue 标题、`hel`/`hey` 标记或特定的密码算法；这些只是某一种实现的特征。可复用的思路是将可变的主机状态与双向加密对象分离，并将两者绑定到一个主机 ID。<sup>[[1]](#references)</sup> 关于另一种 GitHub issue 传输方式，请参阅 [AdaptixC2 custom listener notes](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema)。关于一种通过轮换仓库凭据而非携带会话状态实现的 issue 评论备用方案，请参阅 [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers)。

## References

- [1] [Kaspersky Securelist – FlashHole 行动](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – issue 的 REST API 端点](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – 仓库内容的 REST API 端点](https://docs.github.com/en/rest/repos/contents)
