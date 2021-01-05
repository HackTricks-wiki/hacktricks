# Memory dump analysis

Start **searching** for **malware** inside the pcap. Use the **tools** mentioned in [**Malware Analysis**](malware-analysis.md).

## 

## [Volatility](volatility-examples.md)

The premiere open-source framework for memory dump analysis is [Volatility](volatility-examples.md). Volatility is a Python script for parsing memory dumps that were gathered with an external tool \(or a VMware memory image gathered by pausing the VM\). So, given the memory dump file and the relevant "profile" \(the OS from which the dump was gathered\), Volatility can start identifying the structures in the data: running processes, passwords, etc. It is also extensible using plugins for extracting various types of artifact.  
From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

## Mini dump crash report

When the dump is small \(just some KB, maybe a few MB\) the it's probably a mini dump crash report and not a memory dump.

![](../.gitbook/assets/image%20%28305%29.png)

If you hat Visual Studio installed, you can open this file and bind some basic information like process name, architecture, exception info and modules being executed:

![](../.gitbook/assets/image%20%28164%29.png)

You can also load the exception and see the decompiled instructions

![](../.gitbook/assets/image%20%282%29.png)

![](../.gitbook/assets/image%20%28149%29.png)

Anyway Visual Studio isn't the best tool to perform a analysis in depth of the dump.

You should **open** it using **IDA** or **Radare** to inspection it in **depth**.





