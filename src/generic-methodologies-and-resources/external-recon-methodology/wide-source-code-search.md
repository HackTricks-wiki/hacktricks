# Tìm kiếm mã nguồn trên diện rộng

{{#include ../../banners/hacktricks-training.md}}

Mục tiêu của trang này là liệt kê **các nền tảng cho phép tìm kiếm mã nguồn** (theo chuỗi ký tự, regex, nhận biết symbol hoặc giới hạn theo đường dẫn) trên **hàng nghìn/hàng triệu repo**.

Việc này hữu ích để:

- **Tìm kiếm thông tin bị leak**
- **Tìm kiếm các mẫu dễ bị tấn công**
- **Lập bản đồ công nghệ, host nội bộ, CI/CD và Infrastructure as Code**
- **Pivot từ tên công ty/tổ chức sang repo, branch và các file có nhiều tín hiệu**

- [**Sourcebot**](https://www.sourcebot.dev/): Công cụ tìm kiếm mã nguồn mở/self-hosted, hỗ trợ regex, symbol và tìm kiếm có bộ lọc trên nhiều repo. Cấu hình thêm branch/tag rồi truy vấn bằng `rev:` khi cần bao quát branch.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- [**Sourcegraph**](https://sourcegraph.com/search): Tìm kiếm mã nguồn với truy vấn regex, boolean, symbol, repo/file/ngôn ngữ, branch/commit, diff và thông điệp commit.<sup>[[8]](#references)[[10]](#references)</sup> Tìm kiếm cấu trúc là tùy chọn vì tài liệu hiện tại cho biết tính năng này bị tắt theo mặc định và bị giới hạn về hiệu năng.<sup>[[9]](#references)</sup>
- [**GitHub Code Search**](https://github.com/search): Hỗ trợ regex, logic boolean và các qualifier như `repo:`, `org:`, `user:`, `path:`, `language:`, `symbol:`, `content:` và `is:`.<sup>[[1]](#references)</sup>
- [**GitLab Exact Code Search**](https://docs.gitlab.com/user/search/exact_code_search/): Tìm kiếm mã nguồn được hỗ trợ bởi Zoekt, có chế độ exact và regex cùng các bộ lọc như `file:`, `lang:`, `repo:` và `sym:`.<sup>[[2]](#references)</sup>
  - [**GitLab Advanced Search**](https://docs.gitlab.com/user/search/advanced_search/) là phương án dự phòng có phạm vi rộng hơn vì có thể tìm kiếm mã nguồn, bình luận, commit, merge request và wiki.<sup>[[11]](#references)</sup>
- [**SearchCode**](https://searchcode.com/): Dịch vụ phân tích mã nguồn với tính năng tìm kiếm mã bằng boolean/regex/cấu trúc, đồng thời truy xuất file và symbol.<sup>[[12]](#references)</sup>
- [**Grep**](https://grep.app/): Tìm kiếm mã nguồn công khai trên một triệu repo GitHub, hỗ trợ tìm kiếm nội dung, file và đường dẫn.<sup>[[13]](#references)</sup>

## Các tính năng tìm kiếm hữu ích

Khi audit một tổ chức trong bối cảnh bug bounty/red team, những tính năng hữu ích nhất thường là:

- Hỗ trợ **Regex** để tìm kiếm định dạng token, lược đồ URL, tên hàm nguy hiểm hoặc các đoạn nhiều dòng.
- **Bộ lọc đường dẫn** để chuyển thẳng đến các file có giá trị cao như `.github/workflows/`, `terraform/`, `helm/`, `.env`, `values.yaml`, `secrets.*`, `credentials.*`, `Dockerfile`, `Jenkinsfile` hoặc `nginx.conf`.
- **Bộ lọc ngôn ngữ** để tách mã ứng dụng khỏi IaC và pipeline.
- **Tìm kiếm nhận biết symbol** để liệt kê handler, middleware xác thực, webhook consumer, hàm helper nguy hiểm hoặc các class/method cụ thể.
- **Toán tử Boolean** để giảm nhiễu: `NOT path:test`, `NOT is:generated`, `NOT is:vendored`, `foo OR bar`.
- **Tìm kiếm revision/diff** nếu có, để khôi phục **các chuỗi đã bị xóa**, theo dõi **những thay đổi liên quan đến bảo mật** hoặc kiểm tra **branch/tag không mặc định** mà chưa cần clone mọi thứ.

## Phương pháp thực tế

1. **Bắt đầu với các nền tảng đã lập chỉ mục** để nhanh chóng xác định repo, chủ sở hữu, đường dẫn và nhóm mã nguồn.
2. **Pivot vào các vị trí có nhiều tín hiệu** thay vì chỉ tìm những chuỗi chung chung như `password`/`secret`.
3. **Tìm kiếm bề mặt tấn công, không chỉ thông tin xác thực**:
   - CI/CD workflow, reusable workflow, composite action và script triển khai
   - File khởi tạo Dev Containers / Codespaces và custom feature
   - Manifest Terraform/Helm/Kubernetes
   - Tích hợp SSO/OIDC/SAML
   - URL nội bộ, host staging, bảng quản trị, message broker và endpoint callback
   - Đường dẫn mã nguy hiểm (`exec`, render template, SSRF fetcher, deserializer, giải nén ZIP, YAML loader, v.v.)
4. **Clone và tìm kiếm cục bộ** khi cần branch không mặc định, toàn bộ lịch sử, hỗ trợ regex tốt hơn hoặc tự động hóa hàng loạt.
5. **Chuyển sang các scanner chuyên dụng** khi mục tiêu là phân loại hoặc xác minh secret (ví dụ: xem trang chuyên biệt bên dưới).

### Gợi ý truy vấn có nhiều tín hiệu

Các truy vấn này được cố ý viết ở dạng tổng quát để bạn có thể điều chỉnh cho cú pháp GitHub, GitLab, Sourcegraph hoặc Sourcebot:

```text
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "ACTIONS_STEP_DEBUG")
org:target (path:terraform OR path:helm OR language:HCL OR language:YAML) ("role_arn" OR "assume_role" OR "client_secret" OR "access_key")
org:target ("BEGIN PRIVATE KEY" OR "ghp_" OR "github_pat_" OR "AIza" OR "xoxb-")
org:target (path:.env OR path:values.yaml OR path:application-prod OR path:credentials)
org:target path:.github/workflows ("pull_request_target" OR "workflow_run" OR "workflow_call" OR "secrets: inherit" OR "id-token: write" OR "self-hosted")
org:target path:.github/workflows ("uses:" AND NOT /@[0-9a-f]{40}/)
org:target (path:.devcontainer OR path:devcontainer.json) ("remoteEnv" OR "containerEnv" OR "initializeCommand" OR "postCreateCommand" OR "mounts")
org:target ("devcontainer-feature.json" OR "install.sh") ("curl " OR "wget " OR "docker.sock" OR "sudo ")
org:target ("internal" OR "corp" OR "staging") ("https://" OR "ssh://") NOT path:test
```

### Các tệp mới hơn có tín hiệu cao cần ưu tiên

- **`.github/workflows/*.yml`**: Kiểm tra các trigger `pull_request_target` và `workflow_run` có đặc quyền, cùng các dòng `uses:` của bên thứ ba chỉ được ghim vào tag/branch thay vì full commit SHA.<sup>[[3]](#references)</sup> Đồng thời tìm `workflow_call`, `secrets: inherit`, `id-token: write` và `runs-on: self-hosted`.
- **`.devcontainer/devcontainer.json`**, **`.devcontainer/<variant>/devcontainer.json`** và **`.devcontainer.json`**: Tìm `remoteEnv`, `containerEnv`, `initializeCommand`, `postCreateCommand`, `mounts` và các Dockerfile/script được tham chiếu để phát hiện các giá trị môi trường, lệnh bootstrap, mount và tệp liên quan.<sup>[[4]](#references)</sup>
- **Dev Container Features** (`devcontainer-feature.json`, `install.sh`): Kiểm tra cả hai tệp vì cấu trúc tối thiểu của một Feature gồm metadata và script entrypoint `install.sh`.<sup>[[14]](#references)</sup>
- **Các tệp CI/control-plane khác**: `.gitlab-ci.yml`, `azure-pipelines.yml`, `cloudbuild.yaml`, `Jenkinsfile`, `buildkite*`, `atlantis.yaml`, `terragrunt.hcl`, `helmfile.yaml`, `skaffold.yaml`, `argocd*`.

### Tìm kiếm hàng loạt trên máy cục bộ khi tìm kiếm theo chỉ mục chưa đủ

```bash
gh repo list TARGET_ORG --limit 1000 --json nameWithOwner,sshUrl \
| jq -r '.[].sshUrl' \
| while read -r repo; do
    dst="repos/$(basename "$repo" .git)"
    git clone --depth 1 "$repo" "$dst" 2>/dev/null || true
  done

rg -n --pcre2 \
  -g '!{.git,node_modules,vendor,dist,build,coverage}' \
  '(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AIza[0-9A-Za-z\-_]{35}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' \
  repos/
```

Sử dụng tìm kiếm cục bộ khi cần:

- Tìm kiếm **các nhánh không mặc định** hoặc **tag**
- Tìm kiếm **lịch sử git**
- Chạy các truy vấn **PCRE2/đa dòng** chuyên sâu hơn
- Phân loại hàng loạt nhiều repository mà không bị giới hạn bởi UI

### Tìm kiếm lịch sử, nhánh và diff một cách rõ ràng

```bash
REPO_DIR=repos/some-repo
git -C "$REPO_DIR" fetch --all --tags --prune

git -C "$REPO_DIR" for-each-ref --format='%(refname:short)' refs/remotes/origin refs/tags \
| while read -r ref; do
    git -C "$REPO_DIR" grep -nI -E 'pull_request_target|workflow_call|id-token: write|secrets: inherit|remoteEnv|containerEnv' "$ref" || true
  done

git -C "$REPO_DIR" log --all -p -G 'gh[pousr]_|github_pat_|BEGIN [A-Z ]+PRIVATE KEY|internal.*https?://' -- .
```

Điều này đặc biệt hữu ích khi chuỗi đáng chú ý chỉ xuất hiện trong **release branch**, **tag** hoặc **commit đã bị xóa**. Nếu bản triển khai Sourcegraph của bạn hỗ trợ, các truy vấn `type:diff` và `type:commit` là cách rất tốt để chuyển hướng tìm kiếm mà không cần clone repo nhằm xử lý cùng vấn đề.<sup>[[8]](#references)[[10]](#references)</sup>

## Những điểm mù thường gặp

- **Chỉ lập chỉ mục nhánh mặc định** là tình trạng phổ biến. Đừng cho rằng code search bao phủ mọi branch/tag/lịch sử.
- **File lớn, code được vendor, code được tạo tự động hoặc archive** có thể bị bỏ qua hoặc tạo nhiều kết quả nhiễu.
- **Comment, issue, PR, gist và wiki** thường nằm ngoài phạm vi của code search thông thường và có thể cần công cụ dành riêng cho nền tảng.
- **Cấu hình Codespaces / devcontainer có thể khác nhau theo branch**. Chúng có thể nằm trong nhiều đường dẫn `.devcontainer/<variant>/devcontainer.json`, vì vậy nhánh mặc định sạch không có nghĩa là môi trường dev sạch ở mọi nơi.<sup>[[4]](#references)</sup>
- **Reusable workflow/action và devcontainer feature có thể nằm ngoài file dễ thấy**. Hãy tìm trong `.github/actions/`, `action.yml`, `action.yaml`, `devcontainer-feature.json` và `install.sh`, chứ không chỉ trong file workflow ở cấp cao nhất.
- **Cú pháp tìm kiếm khác nhau giữa các nền tảng**. Một dork chạy được trên GitHub Code Search có thể cần chỉnh sửa đôi chút để dùng trên GitLab, Sourcegraph hoặc Sourcebot.

### Các lưu ý riêng theo nền tảng

- **GitHub Code Search** hữu ích cho recon nhanh, nhưng chỉ tìm kiếm trên **nhánh mặc định**. Nếu cần tìm feature branch, secret đã bị xóa hoặc code trong quá khứ, hãy clone repo và tìm kiếm cục bộ.<sup>[[15]](#references)</sup>
- **GitLab Exact Code Search** bị giới hạn ở **nhánh mặc định** và chỉ lập chỉ mục các file nhỏ hơn 1 MB, có ít hơn 20.000 trigram.<sup>[[2]](#references)</sup> **Advanced Search** vẫn có thể tìm trong comment, commit và wiki.<sup>[[11]](#references)</sup>
- **Sourcebot** mặc định lập chỉ mục **nhánh mặc định**, nhưng có thể được cấu hình để lập chỉ mục thêm branch/tag rồi tìm bằng bộ lọc `rev:` khi bạn kiểm soát index.<sup>[[7]](#references)</sup>
- **Sourcegraph** hỗ trợ truy vấn regex, symbol, diff và commit; chỉ dùng structural search khi tính năng này được bật và lưu ý các giới hạn hiệu năng đã được tài liệu hóa.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

> [!WARNING]
> Khi tìm leak trong repo và chạy lệnh như `git log -p`, đừng quên rằng có thể còn **những branch khác chứa các commit khác** có secret!

Để săn tìm secret chuyên biệt, dùng GitHub dork trên toàn tổ chức và các công cụ như TruffleHog/Gitleaks, hãy xem [trang GitHub leaked secrets](github-leaked-secrets.md).

## References

- [1] [Cú pháp GitHub Code Search](https://docs.github.com/en/search-github/github-code-search/understanding-github-code-search-syntax)
- [2] [GitLab Exact Code Search](https://docs.gitlab.com/user/search/exact_code_search/)
- [3] [Tài liệu tham khảo về cách sử dụng GitHub Actions an toàn](https://docs.github.com/en/actions/reference/security/secure-use)
- [4] [Tài liệu tham khảo về metadata của Dev Container](https://containers.dev/implementors/json_reference/)
- [5] [Sourcebot](https://www.sourcebot.dev/)
- [6] [Search API của Sourcebot](https://docs.sourcebot.dev/api-reference/search-%26-navigation/search-code)
- [7] [Lập chỉ mục nhiều branch trên Sourcebot](https://docs.sourcebot.dev/docs/features/search/multi-branch-indexing)
- [8] [Sourcegraph Code Search](https://sourcegraph.com/docs/code-search)
- [9] [Sourcegraph Structural Search](https://sourcegraph.com/docs/code-search/types/structural)
- [10] [Cú pháp truy vấn tìm kiếm của Sourcegraph](https://sourcegraph.com/docs/code-search/queries)
- [11] [GitLab Advanced Search](https://docs.gitlab.com/user/search/advanced_search/)
- [12] [SearchCode](https://searchcode.com/)
- [13] [Grep.app](https://grep.app/)
- [14] [Hướng dẫn tạo Dev Container Feature](https://containers.dev/guide/author-a-feature)
- [15] [Công cụ điều tra sự cố bảo mật](https://docs.github.com/en/enterprise-cloud%40latest/code-security/reference/security-incident-response/investigation-tools)
{{#include ../../banners/hacktricks-training.md}}
