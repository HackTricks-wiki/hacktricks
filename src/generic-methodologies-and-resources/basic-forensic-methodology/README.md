# Базова методологія криміналістичного аналізу

{{#include ../../banners/hacktricks-training.md}}

## Створення та монтування образу


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Це **не обов'язково перший крок, який слід виконувати після отримання образу**. Але ці методи malware analysis можна використовувати незалежно, якщо у вас є файл, образ файлової системи, образ пам'яті, pcap... тому варто **пам'ятати про ці дії**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Перевірка образу

Якщо вам надали **forensic image** пристрою, ви можете почати **аналізувати розділи та файлову систему**, що використовуються, а також **відновлювати** потенційно **цікаві файли** (навіть видалені). Дізнайтеся, як це робити:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Залежно від використовуваних ОС і навіть платформи слід шукати різні цікаві артефакти:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

## Поглиблена перевірка певних типів файлів і Software

Якщо у вас є дуже **підозрілий** **файл**, то **залежно від типу файлу та software**, який його створив, можуть бути корисними різні **tricks**.\
Прочитайте наступну сторінку, щоб дізнатися про цікаві tricks:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Окремо хочу звернути увагу на сторінку:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Перевірка дампа пам'яті


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Перевірка Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Пам'ятайте про можливе використання anti-forensic techniques:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
