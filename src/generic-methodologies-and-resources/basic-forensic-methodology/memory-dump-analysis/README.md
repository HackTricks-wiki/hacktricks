# Memory dump analysis

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## Start

Start **searching** for **malware** inside the pcap. Use the **tools** mentioned in [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility is the main open-source framework for memory dump analysis**. This Python tool analyzes dumps from external sources or VMware VMs, identifying data like processes and passwords based on the dump's OS profile. It's extensible with plugins, making it highly versatile for forensic investigations.

[**Find here a cheatsheet**](volatility-cheatsheet.md)

## Mini dump crash report

When the dump is small (just some KB, maybe a few MB) then it's probably a mini dump crash report and not a memory dump.

![](<../../../images/image (532).png>)

If you have Visual Studio installed, you can open this file and bind some basic information like process name, architecture, exception info and modules being executed:

![](<../../../images/image (263).png>)

You can also load the exception and see the decompiled instructions

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

Anyway, Visual Studio isn't the best tool to perform an analysis of the depth of the dump.

You should **open** it using **IDA** or **Radare** to inspection it in **depth**.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

{{#include ../../../banners/hacktricks-training.md}}
