{{#include ../banners/hacktricks-training.md}}

# Riepilogo dell'attacco

Immagina un server che **firma** alcuni **dati** **aggiungendo** un **segreto** a dei dati di testo chiaro noti e poi hashando quei dati. Se conosci:

- **La lunghezza del segreto** (questo può anche essere forzato a bruteforce da un dato intervallo di lunghezza)
- **I dati di testo chiaro**
- **L'algoritmo (e è vulnerabile a questo attacco)**
- **Il padding è noto**
- Di solito viene utilizzato uno predefinito, quindi se gli altri 3 requisiti sono soddisfatti, anche questo lo è
- Il padding varia a seconda della lunghezza del segreto + dati, ecco perché è necessaria la lunghezza del segreto

Allora, è possibile per un **attaccante** **aggiungere** **dati** e **generare** una **firma** valida per i **dati precedenti + dati aggiunti**.

## Come?

Fondamentalmente, gli algoritmi vulnerabili generano gli hash prima **hashando un blocco di dati**, e poi, **dallo** **hash** **precedentemente** creato (stato), **aggiungono il prossimo blocco di dati** e **lo hashano**.

Poi, immagina che il segreto sia "secret" e i dati siano "data", l'MD5 di "secretdata" è 6036708eba0d11f6ef52ad44e8b74d5b.\
Se un attaccante vuole aggiungere la stringa "append" può:

- Generare un MD5 di 64 "A"
- Cambiare lo stato dell'hash precedentemente inizializzato a 6036708eba0d11f6ef52ad44e8b74d5b
- Aggiungere la stringa "append"
- Completare l'hash e l'hash risultante sarà un **valido per "secret" + "data" + "padding" + "append"**

## **Strumento**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Riferimenti

Puoi trovare questo attacco ben spiegato in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
