# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder 包含以下内置的 payload 生成器和转换功能：<sup>[[1]](#references)</sup>

- **Simple list:** 使用配置的字符串列表作为 payload。
- **Runtime file:** 在运行时每行读取一个 payload。对于大型列表很有用，因为 Burp 不会将整个文件加载到内存中。
- **Case modification:** 生成未修改的值、小写和大写形式、`Propername`（首字母大写，其余字母小写）或 `ProperName`（首字母大写，其余字符保持不变）。Burp 会丢弃重复结果。
- **Numbers:** 在配置的范围内生成连续或随机数字。
- **Brute forcer:** 针对所选字符集和最小/最大长度生成所有排列。

## Extensions and companion tools

- **Collabfiltrator** 生成可执行命令并通过 DNS 查询将其输出 exfiltrate 到 Burp Collaborator 的 payload。<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** 导出 Burp findings，以便用于其他报告工作流。<sup>[[3]](#references)</sup>
- **HTTP Script Generator** 将 HTTP 请求转换为多种语言的脚本。<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
