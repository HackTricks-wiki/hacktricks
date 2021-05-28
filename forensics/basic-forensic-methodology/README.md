# Basic Forensic Methodology

In this section of the book we are going to learn about some **useful forensics tricks**.  
We are going to talk about partitions, file-systems, carving, memory, logs, backups, OSs, and much more.

So if you are doing a professional forensic analysis to some data or just playing a CTF you can find here useful interesting tricks.

## Creating and Mounting an Image

{% page-ref page="image-adquisition-and-mount.md" %}

## Malware Analysis

This **isn't necessary the first step to perform once you have the image**. But you can use this malware analysis techniques independently if you have a file, a file-system image, memory image, pcap... so it's good to **keep these actions in mind**:

{% page-ref page="malware-analysis.md" %}

## Inspecting an Image

if you are given a **forensic image** of a device you can start **analyzing the partitions, file-system** used and **recovering** potentially **interesting files** \(even deleted ones\). Learn how in:

{% page-ref page="partitions-file-systems-carving/" %}

Depending on the used OSs and even platform different interesting artifacts should be searched:

{% page-ref page="windows-forensics/" %}

{% page-ref page="linux-forensics.md" %}

{% page-ref page="docker-forensics.md" %}

## Deep inspection of specific file-types and Software

If you have very **suspicious** **file**, then **depending on the file-type and software** that created it several **tricks** may be useful.  
Read the following page to learn some interesting tricks:

{% page-ref page="specific-software-file-type-tricks/" %}

I want to do a special mention to the page:

{% page-ref page="specific-software-file-type-tricks/browser-artifacts.md" %}

## Memory Dump Inspection

{% page-ref page="memory-dump-analysis/" %}

## Pcap Inspection

{% page-ref page="pcap-inspection/" %}

## **Anti-Forensic Techniques**

Keep in mind the possible use of anti-forensic techniques:

{% page-ref page="anti-forensic-techniques.md" %}

