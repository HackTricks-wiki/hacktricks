# Основна Судово-Медична Методологія

{{#include ../../banners/hacktricks-training.md}}

## Створення та Монтування Зображення

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Аналіз Шкідливого ПЗ

Це **не обов'язково перший крок, який потрібно виконати після отримання зображення**. Але ви можете використовувати ці техніки аналізу шкідливого ПЗ незалежно, якщо у вас є файл, образ файлової системи, образ пам'яті, pcap... тому добре **тримати ці дії в пам'яті**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Інспекція Зображення

Якщо вам надано **судово-медичне зображення** пристрою, ви можете почати **аналізувати розділи, файлову систему** та **відновлювати** потенційно **цікаві файли** (навіть видалені). Дізнайтеся як у:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

В залежності від використовуваних ОС та навіть платформи слід шукати різні цікаві артефакти:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Глибока інспекція специфічних типів файлів та ПЗ

Якщо у вас є дуже **підозрілий** **файл**, тоді **в залежності від типу файлу та програмного забезпечення**, яке його створило, можуть бути корисні кілька **трюків**.\
Прочитайте наступну сторінку, щоб дізнатися деякі цікаві трюки:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Хочу особливо згадати сторінку:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Інспекція Дампів Пам'яті

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Інспекція Pcap

{{#ref}}
pcap-inspection/
{{#endref}}

## **Анти-Судово-Медичні Техніки**

Майте на увазі можливе використання анти-судово-медичних технік:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Полювання на Загрози

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
