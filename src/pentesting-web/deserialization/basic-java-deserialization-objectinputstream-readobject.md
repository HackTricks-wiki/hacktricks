# Basic Java Deserialization with ObjectInputStream readObject

{{#include ../../banners/hacktricks-training.md}}

In this POST it's going to be explained an example using `java.io.Serializable` **and why overriding `readObject()` can be extremely dangerous if the incoming stream is attacker-controlled**.

## Serializable

The Java `Serializable` interface (`java.io.Serializable`) is a marker interface your classes must implement if they are to be **serialized** and **deserialized**. Java object serialization (writing) is done with the [`ObjectOutputStream`](http://tutorials.jenkov.com/java-io/objectoutputstream.html) and deserialization (reading) is done with the [`ObjectInputStream`](http://tutorials.jenkov.com/java-io/objectinputstream.html).

### Reminder: Which methods are implicitly invoked during deserialization?

1. `readObject()` – class-specific read logic (if implemented and *private*).
2. `readResolve()` – can replace the deserialized object with another one.
3. `validateObject()` – via `ObjectInputValidation` callbacks.
4. `readExternal()` – for classes implementing `Externalizable`.
5. Constructors are **not** executed – therefore gadget chains rely exclusively on the previous callbacks.

Any method in that chain that ends up invoking attacker-controlled data (command execution, JNDI lookups, reflection, etc.) turns the deserialization routine into an RCE gadget.

Lets see an example with a **class Person** which is **serializable**. This class **overwrites the readObject** function, so when **any object** of this **class** is **deserialized** this **function** is going to be **executed**.\
In the example, the **readObject** function of the class Person calls the function `eat()` of his pet and the function `eat()` of a Dog (for some reason) calls a **calc.exe**. **We are going to see how to serialize and deserialize a Person object to execute this calculator:**

**The following example is from <https://medium.com/@knownsec404team/java-deserialization-tool-gadgetinspector-first-glimpse-74e99e493649>**

```java
import java.io.Serializable;
import java.io.*;

public class TestDeserialization {
    interface Animal {
        public void eat();
    }
    //Class must implements Serializable to be serializable
    public static class Cat implements Animal,Serializable {
        @Override
        public void eat() {
            System.out.println("cat eat fish");
        }
    }
    //Class must implements Serializable to be serializable
    public static class Dog implements Animal,Serializable {
        @Override
        public void eat() {
            try {
                Runtime.getRuntime().exec("calc");
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("dog eat bone");
        }
    }
    //Class must implements Serializable to be serializable
    public static class Person implements Serializable {
        private Animal pet;
        public Person(Animal pet){
            this.pet = pet;
        }
        //readObject implementation, will call the readObject from ObjectInputStream  and then call pet.eat()
        private void readObject(java.io.ObjectInputStream stream)
                throws IOException, ClassNotFoundException {
            pet = (Animal) stream.readObject();
            pet.eat();
        }
    }
    public static void GeneratePayload(Object instance, String file)
            throws Exception {
        //Serialize the constructed payload and write it to the file
        File f = new File(file);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(f));
        out.writeObject(instance);
        out.flush();
        out.close();
    }
    public static void payloadTest(String file) throws Exception {
        //Read the written payload and deserialize it
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
        Object obj = in.readObject();
        System.out.println(obj);
        in.close();
    }
    public static void main(String[] args) throws Exception {
        // Example to call Person with a Dog
        Animal animal = new Dog();
        Person person = new Person(animal);
        GeneratePayload(person,"test.ser");
        payloadTest("test.ser");
        // Example to call Person with a Cat
        //Animal animal = new Cat();
        //Person person = new Person(animal);
        //GeneratePayload(person,"test.ser");
        //payloadTest("test.ser");
    }
}
```

### Conclusion (classic scenario)

As you can see in this very basic example, the “vulnerability” here appears because the **readObject()** method is **calling other attacker-controlled code**. In real-world gadget chains, thousands of classes contained in external libraries (Commons-Collections, Spring, Groovy, Rome, SnakeYAML, etc.) can be abused – the attacker only needs *one* reachable gadget to get code execution.

---

## 2023-2025: What’s new in Java deserialization attacks?

* 2023 – CVE-2023-34040: Spring-Kafka deserialization of error-record headers when `checkDeserExWhen*` flags are enabled allowed arbitrary gadget construction from attacker-published topics. Fixed in 3.0.10 / 2.9.11. ¹
* 2023 – CVE-2023-36480: Aerospike Java client trusted-server assumption broken – malicious server replies contained serialized payloads that were deserialized by the client → RCE. ²
* 2023 – CVE-2023-25581: `pac4j-core` user profile attribute parsing accepted `{#sb64}`-prefixed Base64 blobs and deserialized them despite a `RestrictedObjectInputStream`. Upgrade ≥ 4.0.0.
* 2023 – CVE-2023-4528: JSCAPE MFT Manager Service (port 10880) accepted XML-encoded Java objects leading to RCE as root/SYSTEM.
* 2024 – Multiple new gadget chains were added to ysoserial-plus(mod) including Hibernate5, TomcatEmbed, and SnakeYAML 2.x classes that bypass some old filters.

## Modern mitigations you should deploy

1. **JEP 290 / Serialization Filtering (Java 9+)**  
   *Add an allow-list or deny-list of classes:*  
   ```bash
   # Accept only your DTOs and java.base, reject everything else
   -Djdk.serialFilter="com.example.dto.*;java.base/*;!*"
   ```
   Programmatic example:
   ```java
   var filter = ObjectInputFilter.Config.createFilter("com.example.dto.*;java.base/*;!*" );
   ObjectInputFilter.Config.setSerialFilter(filter);
   ```
2. **JEP 415 (Java 17+) Context-Specific Filter Factories** – use a `BinaryOperator<ObjectInputFilter>` to apply different filters per execution context (e.g., per RMI call, per message queue consumer).
3. **Do not expose raw `ObjectInputStream` over the wire** – prefer JSON/Binary encodings without code execution semantics (Jackson after disabling `DefaultTyping`, Protobuf, Avro, etc.).
4. **Defense-in-Depth limits** – Set maximum array length, depth, references:
   ```bash
   -Djdk.serialFilter="maxbytes=16384;maxdepth=5;maxrefs=1000"
   ```
5. **Continuous gadget scanning** – run tools such as `gadget-inspector` or `serialpwn-cli` in your CI to fail the build if a dangerous gadget becomes reachable.

## Updated tooling cheat-sheet (2024)

* `ysoserial-plus.jar` – community fork with > 130 gadget chains:
  ```bash
  java -jar ysoserial-plus.jar CommonsCollections6 'calc' | base64 -w0
  ```
* `marshalsec` – still the reference for JNDI gadget generation (LDAP/RMI).  
* `gadget-probe` – fast black-box gadget discovery against network services.
* `SerialSniffer` – JVMTI agent that prints every class read by `ObjectInputStream` (useful to craft filters).
* **Detection tip** – enable `-Djdk.serialDebug=true` (JDK 22+) to log filter decisions and rejected classes.

## Quick checklist for secure `readObject()` implementations

1. Make the method `private` and add the `@Serial` annotation (helps static analysis).
2. Never call user-supplied methods or perform I/O in the method – only read fields.
3. If validation is needed, perform it **after** deserialization, outside of `readObject()`.
4. Prefer implementing `Externalizable` and do explicit field reads instead of default serialization.
5. Register a hardened `ObjectInputFilter` even for internal services (compromise-resilient design).

## References

1. Spring Security Advisory – CVE-2023-34040 Java Deserialization in Spring-Kafka (Aug 2023)
2. GitHub Security Lab – GHSL-2023-044: Unsafe Deserialization in Aerospike Java Client (Jul 2023)

{{#include ../../banners/hacktricks-training.md}}
