# iButton

{{#include ../../banners/hacktricks-training.md}}

## Вступ

iButton — це загальна назва електронного ключа-ідентифікатора, упакованого в **монетоподібний металевий корпус**. Його також називають пам’яттю Dallas Touch або контактною пам’яттю. Хоча його часто помилково називають «магнітним» ключем, у ньому **немає нічого магнітного**. Насправді всередині прихована повноцінна **мікросхема**, що працює за цифровим протоколом.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Що таке iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Назва iButton описує міцний монетоподібний корпус і розташування контактів. Існують пластикові брелоки, кільця та підвіски.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Коли обидва контакти торкаються зчитувача, пристрій отримує живлення й обмінюється даними. Якщо заглиблена форма контактів заважає зовнішнім контактам заземлення торкнутися зчитувача, нахиліть ключ до його стінки, щоб відновити контакт.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Протокол 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Ключі Dallas/Maxim використовують протокол 1-Wire: один контакт даних передає двосторонній трафік і може також забезпечувати паразитне живлення, а металевий корпус слугує зворотним контактом. Контролер ініціює транзакції, а пристрій відповідає.<sup>[[2]](#references)</sup>

Коли ключ (підлеглий пристрій) торкається домофона (головного пристрою), мікросхема всередині ключа вмикається, отримуючи живлення від домофона, і ключ ініціалізується. Після цього домофон запитує ідентифікатор ключа. Далі розглянемо цей процес докладніше.

Flipper може працювати як контролер під час зчитування ключа, а також як емульований пристрій, передаючи зчитувачу збережений ідентифікатор.<sup>[[1]](#references)</sup>

### Ключі Dallas, Cyfral і Metakom

Інформацію про принцип роботи цих ключів дивіться на сторінці [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Атаки

На iButton можна здійснювати атаки за допомогою Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Приборкання iButton за допомогою Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — передавання даних через 1-Wire за допомогою програмного забезпечення](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
