# iButton

{{#include ../../banners/hacktricks-training.md}}

## Вступ

iButton — це загальна назва електронного ідентифікаційного ключа, вміщеного в **металевий контейнер у формі монети**. Його також називають Dallas Touch Memory або контактною пам'яттю. Хоча його часто помилково називають «магнітним» ключем, у ньому **немає нічого магнітного**. Насправді всередині прихований повноцінний **мікрочип**, що працює за цифровим протоколом.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Що таке iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Назва iButton описує міцний корпус у формі монети та розташування контактів. Серед тримачів є пластикові брелоки, кільця та підвіски.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Коли обидва контакти з'єднуються зі зчитувачем, пристрій отримує живлення та обмінюється даними. Якщо заглиблена геометрія контактів не дає зовнішнім контактам заземлення з'єднатися, нахил ключа до стінки зчитувача може відновити контакт.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Протокол 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Ключі Dallas/Maxim використовують протокол 1-Wire: один контакт даних передає двонаправлений трафік і також може забезпечувати паразитне живлення, тоді як металевий корпус є зворотним контактом. Контролер ініціює транзакції, а пристрій відповідає.<sup>[[2]](#references)</sup>

Коли ключ (Slave) контактує з домофоном (Master), чип усередині ключа вмикається, отримуючи живлення від домофона, і ключ ініціалізується. Після цього домофон запитує ідентифікатор ключа. Далі ми розглянемо цей процес докладніше.

Flipper може виступати як контролер під час читання ключа та як емульований пристрій, коли передає збережений ідентифікатор зчитувачу.<sup>[[1]](#references)</sup>

### Ключі Dallas, Cyfral і Metakom

Інформацію про принцип роботи цих ключів наведено на сторінці [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Атаки

iButton можна атакувати за допомогою Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Освоєння iButton за допомогою Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — програмна реалізація зв'язку 1-Wire](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
