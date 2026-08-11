# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection 会在设备运行期间对其进行有意干扰，使其执行错误的计算。有效的 fault 可能跳过一条指令、破坏数据、绕过安全检查，或产生错误的加密输出，并可从中推导出机密信息。<sup>[[1]](#references)</sup>

常见技术包括操纵供电电压或时钟、注入电磁干扰，或使用光学刺激或激光刺激。<sup>[[1]](#references)</sup> 这些技术在精确度和侵入性方面各不相同，但成功的测试通常需要可重复的 trigger，并对时序、脉冲宽度和强度进行系统性扫描。应从稳定的基线开始，分别记录重置和格式错误的输出，并且每次只改变一个参数。<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi 等 - 基于有意电磁干扰的非侵入式无触发 Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - 捕获硬件概述与比较](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
