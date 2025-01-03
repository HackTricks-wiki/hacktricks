# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Це мова сценаріїв, що використовується для автоматизації завдань **взаємодіючи з віддаленими процесами**. Це досить просто **запитати інші процеси виконати деякі дії**. **Шкідливе ПЗ** може зловживати цими функціями для зловживання функціями, експортованими іншими процесами.\
Наприклад, шкідливе ПЗ може **впроваджувати довільний JS код у відкриті сторінки браузера**. Або **автоматично натискати** деякі дозволи, запитані у користувача;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ось кілька прикладів: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Знайдіть більше інформації про шкідливе ПЗ, використовуючи AppleScripts [**тут**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple скрипти можуть бути легко "**скомпільовані**". Ці версії можуть бути легко "**декомпільовані**" за допомогою `osadecompile`

Однак ці скрипти також можуть бути **експортовані як "Тільки для читання"** (через опцію "Експортувати..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
і в цьому випадку вміст не може бути декомпільований навіть з `osadecompile`

Однак все ще існують деякі інструменти, які можна використовувати для розуміння такого роду виконуваних файлів, [**прочитайте це дослідження для отримання додаткової інформації**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Інструмент [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) з [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) буде дуже корисним для розуміння того, як працює скрипт.

{{#include ../../../../../banners/hacktricks-training.md}}
