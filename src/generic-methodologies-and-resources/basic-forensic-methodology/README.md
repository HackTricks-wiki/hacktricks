# Basic Forensic Methodology

{{#include ../../banners/hacktricks-training.md}}

## Creating and Mounting an Image

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

This **isn't necessary the first step to perform once you have the image**. But you can use this malware analysis techniques independently if you have a file, a file-system image, memory image, pcap... so it's good to **keep these actions in mind**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Inspecting an Image

if you are given a **forensic image** of a device you can start **analyzing the partitions, file-system** used and **recovering** potentially **interesting files** (even deleted ones). Learn how in:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Depending on the used OSs and even platform different interesting artifacts should be searched:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Deep inspection of specific file-types and Software

If you have very **suspicious** **file**, then **depending on the file-type and software** that created it several **tricks** may be useful.\
Read the following page to learn some interesting tricks:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

I want to do a special mention to the page:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection

{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Keep in mind the possible use of anti-forensic techniques:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}



