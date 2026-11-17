# Аналіз файлів Office

{{#include ../../../banners/hacktricks-training.md}}

Докладніше див. на [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Це лише короткий огляд:<sup>[[2]](#references)</sup>

Документи Microsoft Office часто трапляються у застарілих форматах, як-от RTF і DOC, XLS та PPT на основі OLE/CFBF, або у новіших форматах **Office Open XML (OOXML)**, як-от DOCX, XLSX і PPTX. Документи Office можуть містити активний вміст, зокрема макроси, що робить їх поширеним засобом фішингу та розповсюдження шкідливого ПЗ. Файли OOXML — це ZIP-контейнери; їхню ієрархію файлів і вміст XML можна переглянути, розпакувавши їх.<sup>[[1]](#references)[[2]](#references)</sup>

Наведено команду для розпакування документа та структуру вихідних даних, щоб дослідити файли OOXML. Методи приховування даних у таких файлах задокументовані, що свідчить про постійне вдосконалення способів приховування даних у завданнях CTF.<sup>[[2]](#references)</sup>

Для аналізу **oletools** і **OfficeDissector** пропонують комплексні набори інструментів для дослідження документів OLE та OOXML. Ці інструменти допомагають виявляти й аналізувати вбудовані макроси, які часто використовують для доставки шкідливого ПЗ, зазвичай завантажуючи та запускаючи додаткові шкідливі корисні навантаження. Аналіз макросів VBA можна проводити без Microsoft Office за допомогою Libre Office, де доступне налагодження з точками зупинки та змінними для спостереження.<sup>[[2]](#references)</sup>

Установити й використовувати **oletools** просто: наведено команди для встановлення через pip і вилучення макросів із документів. У Word автоматичні макроси включають `AutoExec` і `AutoOpen`, а `Document_Open` — це процедура, що виконується під час відкриття документа.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Аналіз макросів VBA: сміттєвий код і UserForms

## Сміттєвий код

Макроси можуть містити **недосяжний або нерелевантний код**, призначений для уповільнення аналізу. Перш ніж витрачати час на реверсинг гілки, визначте умови, що завжди мають одне й те саме значення, і простежте виконання доступного коду. У наведеному нижче прикладі використано умову `If`, яка ніколи не може бути істинною, щоб приховати сміттєвий код.

![Макрос Word із недосяжною умовною гілкою зі сміттєвим кодом](<../../../images/image (369).png>)

## Форми макросів

VBA UserForms можуть зберігати дані в елементах керування, таких як текстові поля. Оскільки форми, фрейми та сторінки можуть мати власну колекцію `Controls`, аналітикам слід перебирати всю ієрархію елементів керування, а не покладатися лише на те, що відображає форма. У наведеному нижче прикладі приховані дані зберігаються в текстових полях, що накладаються одне на одне.<sup>[[6]](#references)</sup>

Під час динамічного аналізу функція VBA `GetObject` може отримати Automation object із файлу або під’єднатися до вже запущеного Automation-сервера. Макроси можуть використовувати такий доступ до об’єктів, щоб отримати дані, які не помітні у видимому документі; перевіряйте і повернений об’єкт, і дерево елементів керування UserForm.<sup>[[7]](#references)</sup>

![UserForm макросу з даними, прихованими в текстових полях, що накладаються одне на одне](<../../../images/image (344).png>)

Документи Office, зашифровані паролем: див. [процес офлайн-відновлення на основі граматики](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Файли Revit RFA, що використовують OLE/CFBF: див. [перерахунок ECC, керований gzip і експлуатацію десеріалізатора](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); цей процес експлуатації парсера відрізняється від первинного аналізу документів Office.

## References

- [1] [Документація OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Посібник із цифрової криміналістики для CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Документація olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Автоматичні макроси (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Подія Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn — колекції, елементи керування та об’єкти (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn — функція `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
