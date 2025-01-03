# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Командні інструменти** для управління **zip файлами** є необхідними для діагностики, ремонту та злому zip файлів. Ось деякі ключові утиліти:

- **`unzip`**: Виявляє, чому zip файл може не розпаковуватися.
- **`zipdetails -v`**: Пропонує детальний аналіз полів формату zip файлу.
- **`zipinfo`**: Перераховує вміст zip файлу без його розпакування.
- **`zip -F input.zip --out output.zip`** та **`zip -FF input.zip --out output.zip`**: Спробуйте відремонтувати пошкоджені zip файли.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Інструмент для брутфорс злому паролів zip, ефективний для паролів до приблизно 7 символів.

[Специфікація формату zip файлу](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) надає всебічні деталі про структуру та стандарти zip файлів.

Важливо зазначити, що zip файли з паролем **не шифрують імена файлів або розміри файлів** всередині, що є недоліком безпеки, який не поділяють файли RAR або 7z, які шифрують цю інформацію. Крім того, zip файли, зашифровані старим методом ZipCrypto, вразливі до **атаки з відкритим текстом**, якщо доступна незашифрована копія стиснутого файлу. Ця атака використовує відомий вміст для злому пароля zip, вразливість, детально описану в [статті HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) та додатково пояснену в [цьому науковому документі](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Однак zip файли, захищені шифруванням **AES-256**, є стійкими до цієї атаки з відкритим текстом, що підкреслює важливість вибору безпечних методів шифрування для чутливих даних.

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
