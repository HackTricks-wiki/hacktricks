# 故障注入攻击

{{#include ../../banners/hacktricks-training.md}}

故障注入（在硬件安全领域通常称为 **glitching**）是指在设备运行时故意干扰它，使其执行错误的计算。有效的故障可能跳过一条指令、破坏数据、绕过安全检查，或产生可用于推导机密信息的错误加密输出。<sup>[[1]](#references)</sup>

常见技术包括操纵电源电压或时钟、注入电磁干扰，或使用光学或激光刺激。<sup>[[1]](#references)</sup>这些技术的精度和侵入性各不相同，但成功测试通常需要可重复的触发条件，并系统地扫描时序、脉冲宽度和强度。先建立稳定的基线，分别记录重置和格式错误的输出，每次只更改一个参数。<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi 等 - 基于有意电磁干扰的非侵入式无触发故障注入方法](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer 文档 - 采集硬件概览与比较](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
