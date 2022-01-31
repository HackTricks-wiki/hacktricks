# Basic Forensic Methodology

{% hint style="danger" %}
Do you use **Hacktricks every day**? Did you find the book **very** **useful**? Would you like to **receive extra help** with cybersecurity questions? Would you like to **find more and higher quality content on Hacktricks**?\
[**Support Hacktricks through github sponsors**](https://github.com/sponsors/carlospolop) **so we can dedicate more time to it and also get access to the Hacktricks private group where you will get the help you need and much more!**
{% endhint %}

If you want to know about my **latest modifications**/**additions** or you have **any suggestion for HackTricks** or **PEASS**, **join the** [**💬**](https://emojipedia.org/speech-balloon/)[**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass), or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**\
If you want to **share some tricks with the community** you can also submit **pull requests** to [**https://github.com/carlospolop/hacktricks**](https://github.com/carlospolop/hacktricks) that will be reflected in this book and don't forget to **give ⭐** on **github** to **motivate** **me** to continue developing this book.



In this section of the book we are going to learn about some **useful forensics tricks**.\
We are going to talk about partitions, file-systems, carving, memory, logs, backups, OSs, and much more.

So if you are doing a professional forensic analysis to some data or just playing a CTF you can find here useful interesting tricks.

## Creating and Mounting an Image

{% content-ref url="image-adquisition-and-mount.md" %}
[image-adquisition-and-mount.md](image-adquisition-and-mount.md)
{% endcontent-ref %}

## Malware Analysis

This **isn't necessary the first step to perform once you have the image**. But you can use this malware analysis techniques independently if you have a file, a file-system image, memory image, pcap... so it's good to **keep these actions in mind**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Inspecting an Image

if you are given a **forensic image** of a device you can start **analyzing the partitions, file-system** used and **recovering** potentially **interesting files** (even deleted ones). Learn how in:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

Depending on the used OSs and even platform different interesting artifacts should be searched:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## Deep inspection of specific file-types and Software

If you have very **suspicious** **file**, then **depending on the file-type and software** that created it several **tricks** may be useful.\
Read the following page to learn some interesting tricks:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

I want to do a special mention to the page:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## Memory Dump Inspection

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap Inspection

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **Anti-Forensic Techniques**

Keep in mind the possible use of anti-forensic techniques:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## Threat Hunting

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

