# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection—often called **glitching** in hardware-security work—deliberately disturbs a device while it is operating so that it performs an incorrect computation. A useful fault may skip an instruction, corrupt data, bypass a security check, or produce faulty cryptographic output from which secret information can be derived.<sup>[[1]](#references)</sup>

Common techniques manipulate the supply voltage or clock, inject electromagnetic interference, or use optical or laser stimulation.<sup>[[1]](#references)</sup> Their precision and invasiveness differ, but successful testing generally requires a repeatable trigger and systematic sweeps over timing, pulse width, and intensity. Begin with a stable baseline, record resets and malformed outputs separately, and change one parameter at a time.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Non-invasive Trigger-free Fault Injection Method Based on Intentional Electromagnetic Interference](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware Overview and Comparison](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)

{{#include ../../banners/hacktricks-training.md}}
