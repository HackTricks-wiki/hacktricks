# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

- **Simple list:** 使用配置好的字符串列表作为 payload。
- **Runtime file:** 在运行时逐行读取 payload。对于大型列表很有用，因为 Burp 不会将整个文件加载到内存中。
- **Case modification:** 更改输入字符串的大小写，例如改为小写、大写、句首字母大写或标题格式。
- **Numbers:** 在配置的范围内生成连续或随机数字。
- **Brute forcer:** 为选定的字符集以及最小/最大长度生成所有排列组合。<sup>[[1]](#references)</sup>

## Extensions and companion tools

- **Collabfiltrator** 生成可执行命令并通过 DNS 查询将其输出 exfiltrate 到 Burp Collaborator 的 payload。<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** 导出 Burp findings，以便用于其他报告工作流。<sup>[[3]](#references)</sup>
- **HTTP Script Generator** 将 HTTP requests 转换为多种语言的 scripts。<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
