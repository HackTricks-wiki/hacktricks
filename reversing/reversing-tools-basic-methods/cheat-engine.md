# Cheat Engine

****[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them.\
When you download and run it, you are **presented **with a **tutorial **of how to use the tool. If you want to learn how to use the tool it's highly recommended to complete it.

## What are you searching?

![](<../../.gitbook/assets/image (580).png>)

This tool is very useful to find **where some value** (usually a number) **is stored in the memory** of a program.\
**Usually numbers **are stored in **4bytes **form, but you could also find them in** double **or **float **formats, or you may want to look for something **different from a number**. For that reason you need to be sure you **select **what you want to **search for**:

![](<../../.gitbook/assets/image (581).png>)

Also you can indicate **different **types of **searches**:

![](<../../.gitbook/assets/image (582).png>)

You can also check the box to **stop the game while scanning the memory**:

![](<../../.gitbook/assets/image (584).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ you can set different **hotkeys **for different purposes like **stopping **the **game **(which is quiet useful if at some point you want to scan the memory). Other options are available:

![](<../../.gitbook/assets/image (583).png>)

## Modifying the value

Once you **found **where is the **value **you are **looking for **(more about this in the following steps) you can **modify it** double clicking it, then double clicking its value:

![](<../../.gitbook/assets/image (585).png>)

And finally **marking the check** to get the modification done in the memory:

![](<../../.gitbook/assets/image (586).png>)

The **change **to the **memory **will be immediately **applied **(note that until the game doesn't use this value again the value **won't be updated in the game**).

## Searching the value

So, we are going to suppose that there is an important value (like the life of your user) that you want to improve, and you are looking for this value in the memory)

### Through a known change

Supposing you are looking for the value 100, you **perform a scan** searching for that value and you find a lot of coincidences:

![](<../../.gitbook/assets/image (587).png>)

Then, you do something so that **value changes**, and you **stop **the game and **perform **a **next scan**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine will search for the **values **that **went from 100 to the new value**. Congrats, you **found **the **address **of the value you were looking for, you can now modify it.\
_If you still have several values, do something to modify again that value, and perform another "next scan" to filter the addresses._

### Unknown Value, known change

In the scenario you **don't know the value** but you know** how to make it change** (and even the value of the change) you can look for your number.

So, start by performing a scan of type "**Unknown initial value**":

![](<../../.gitbook/assets/image (589).png>)

Then, make the value change, indicate **how **the **value** **changed** (in my case it was decreased by 1)** **and perform a **next scan**:

![](<../../.gitbook/assets/image (590).png>)

You will be presented **all the values that were modified in the selected way**:

![](<../../.gitbook/assets/image (591).png>)

Once you have found your value, you can modify it.

Note that there are a** lot of possible changes** and you can do these **steps as much as you want** to filter the results:

![](<../../.gitbook/assets/image (592).png>)

### Random Memory Address - Finding the code

Until know we learnt how to find an address storing a value, but it's highly probably that in **different executions of the game that address is in different places of the memory**. So lets find out how to always find that address. 

Using some of the mentioned tricks, find the address where your current game is storing the important value. Then (stopping the game if you whish) do a** right click** on the found **address **and select "**Find out what accesses this address**" or "**Find out what writes to this address**":

![](<../../.gitbook/assets/image (593).png>)

The** first option** is useful to know which **parts **of the **code **are **using **this **address **(which is useful for more things like **knowing where you can modify the code** of the game).\
The **second option **is more **specific**, and will be more helpful in this case as we are interested in knowing **from where this value is being written**.

Once you have selected one of those options, the **debugger **will be **attached **to the program and a new **empty window **will appear. Now, **play **the **game **and **modify **that **value **(without restarting the game). The **window **should be **filled **with the **addresses **that are **modifying **the **value**:

![](<../../.gitbook/assets/image (594).png>)

Now that you found the address it's modifying the value you can** modify the code at your pleasure** (Cheat Engine allows you to modify it for NOPs real quick):

![](<../../.gitbook/assets/image (595).png>)

So, you can now modify it so the code won't affect your number, or will always affect in a positive way.

### Random Memory Address - Finding the pointer

Following the previous steps, find where the value you are interested is. Then, using "**Find out what writes to this address**" find out which address writes this value and double click on it to get the disassembly view:

![](<../../.gitbook/assets/image (596).png>)

Then, perform a new scan **searching for the hex value between "\[]"** (the value of $edx in this case):

![](<../../.gitbook/assets/image (597).png>)

(_If several appear you usually need the smallest address one_)\
Now, we have f**ound the pointer that will be modifying the value we are interested in**.

Click on "**Add Address Manually**":

![](<../../.gitbook/assets/image (598).png>)

Now, click on the "Pointer" check box and add the found address in the text box (in this scenario, the found address in the previous image was "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Note how the first "Address" is automatically populated from the pointer address you introduce)

Click OK and a new pointer will be created:

![](<../../.gitbook/assets/image (600).png>)

Now, every time you modifies that value you are **modifying the important value even if the memory address where the value is is different.**

### Code Injection

Code injection is a technique where you inject a piece of code into the target process, and then reroute the execution of code to go through your own written code (like giving you points instead of resting them).

So, imagine you have found the address that is subtracting 1 to the life of your player:

![](<../../.gitbook/assets/image (601).png>)

Click on Show disassembler to get the **disassemble code**.\
Then, click **CTRL+a** to invoke the Auto assemble window and select _**Template --> Code Injection**_

![](<../../.gitbook/assets/image (602).png>)

Fill the **address of the instruction you want to modify** (this is usually autofilled):

![](<../../.gitbook/assets/image (603).png>)

A template will be generated:

![](<../../.gitbook/assets/image (604).png>)

So, insert your new assembly code in the "**newmem**" section and remove the original code from the "**originalcode**" if you don't want it to be executed**. **In this example the injected code will add 2 points instead of substracting 1:

![](<../../.gitbook/assets/image (605).png>)

**Click on execute and so on and your code should be injected in the program changing the behaviour of the functionality!**

## **References**

* **Cheat Engine tutorial, complete it to learn how to start with Cheat Engine**

