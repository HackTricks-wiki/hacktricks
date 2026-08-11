# Basic Java Deserialization with ObjectInputStream readObject

{{#include ../../banners/hacktricks-training.md}}

This page explains an example using `java.io.Serializable` and why implementing `readObject()` can be extremely dangerous when the incoming stream is attacker-controlled.

## Serializable

The Java `Serializable` interface (`java.io.Serializable`) is a marker interface a class implements to participate in native Java object serialization. `ObjectOutputStream` writes object graphs and `ObjectInputStream` reconstructs them.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### Reminder: Which methods are implicitly invoked during deserialization?

1. `readObject()` – class-specific read logic (if implemented and *private*).
2. `readResolve()` – can replace the deserialized object with another one.
3. `validateObject()` – via `ObjectInputValidation` callbacks.
4. `readExternal()` – for classes implementing `Externalizable`.
5. Constructors and field initializers of serializable classes are not executed. However, the no-argument constructor of the first non-serializable superclass does run, and records use their canonical constructor.<sup>[[6]](#references)</sup>

Any method in that chain that ends up invoking attacker-controlled data (command execution, JNDI lookups, reflection, etc.) turns the deserialization routine into an RCE gadget.

The following example defines a serializable **`Person`** class with a private `readObject()` method, which Java invokes while deserializing an instance of that class.\
In the example, the **readObject** function of the class Person calls the function `eat()` of his pet and the function `eat()` of a Dog (for some reason) calls a **calc.exe**. **We are going to see how to serialize and deserialize a Person object to execute this calculator:**

**The following example is from <https://medium.com/@knownsec404team/java-deserialization-tool-gadgetinspector-first-glimpse-74e99e493649>**<sup>[[3]](#references)</sup>

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

## 2023-2025: What changed in real-world Java deserialization bugs?

Recent cases are a good reminder that `ObjectInputStream` bugs are no longer just “upload a `.ser` file to a legacy HTTP endpoint”:

* **Broker / queue consumers**: Spring-Kafka (`CVE-2023-34040`) showed that deserializing exception headers from attacker-controlled topics is enough if the consumer enables the unusual `checkDeserExWhen*` flags.<sup>[[4]](#references)</sup>
* **Client-side trust of remote servers**: the Aerospike Java client (`CVE-2023-36480`) deserialized objects received from the server. The vendor response was notable: newer clients removed Java runtime serialization/deserialization support instead of trying to preserve it behind a weak filter.<sup>[[5]](#references)</sup>
* **“Restricted” streams are often still too broad**: `pac4j-core` (`CVE-2023-25581`) tried to protect deserialization with `RestrictedObjectInputStream`, but the accepted class set was still large enough to make gadget abuse possible.<sup>[[2]](#references)</sup>

The offensive lesson is that the dangerous trust boundary is often **not** “user uploads a blob”, but “some component the developer considered trusted can inject bytes into a stream that eventually reaches `readObject()`”.

If you need low-noise reachability checks before spending time on full gadget research, use the dedicated Java pages for:

{{#ref}}
java-dns-deserialization-and-gadgetprobe.md
{{#endref}}

## `readObject()` anti-patterns that still create gadget entrypoints

Even if your class itself is not an obvious RCE gadget, the following patterns are enough to make it exploitable when attacker-controlled objects are embedded in the graph:

1. Calling overridable methods or interface methods from `readObject()` (`pet.eat()` in the PoC above is the classic example).
2. Performing lookups, reflection, class loading, expression evaluation, or JNDI operations during deserialization.
3. Iterating over attacker-controlled collections or maps, which may trigger `hashCode()`, `equals()`, comparators, or transformers as side effects.
4. Registering `ObjectInputValidation` callbacks that perform dangerous post-processing.
5. Assuming “private `readObject()`” is enough protection. It only controls dispatch semantics; it does **not** make deserialization safe.

## Modern mitigations you should deploy

1. **JEP 290 / Serialization Filtering (Java 9+)**  
   Use an allow-list and explicit graph limits:
   ```bash
   -Djdk.serialFilter="com.example.dto.*;java.base/*;maxdepth=5;maxrefs=1000;maxbytes=16384;!*"
   ```
2. **Apply a filter on every untrusted stream, not just globally**:
   ```java
   try (var ois = new ObjectInputStream(input)) {
       var filter = ObjectInputFilter.Config.createFilter(
           "com.example.dto.*;java.base/*;maxdepth=5;maxrefs=1000;!*"
       );
       ois.setObjectInputFilter(filter);
       return (Message) ois.readObject();
   }
   ```
3. **JEP 415 (Java 17+) Context-Specific Filter Factories**<sup>[[1]](#references)</sup>  
   Prefer this when the same JVM has multiple deserialization contexts (RMI, cache replication, message consumers, admin-only imports) and each one needs a different allow-list.
4. **Keep `readObject()` boring**  
   Only call `defaultReadObject()` / explicit field reads, then perform strict invariant checks. Do not do I/O, logging that dereferences attacker-controlled objects, dynamic lookups, or method calls on deserialized sub-objects.
5. **If possible, remove Java native serialization from the design**  
   The Aerospike fix is a good model: when the feature is not essential, deleting `readObject()` / `writeObject()` usage is often safer than trying to maintain perfect filters forever.

## Detection and research workflow

* `ysoserial` remains the baseline for gadget validation and quick RCE/URLDNS probes.
* `marshalsec` is still useful when the sink pivots into JNDI/LDAP/RMI territory.
* `GadgetInspector` is useful when you have the target jars and need to look for application-specific gadget chains.
* Java 17 added the `jdk.Deserialization` Flight Recorder event, which is useful for seeing where `ObjectInputStream` is actually used and whether filters are being applied.

## Quick checklist for secure `readObject()` implementations

1. Make the method `private` and annotate serialization hooks with `@Serial` so compilers can catch mis-declared signatures.
2. Call `defaultReadObject()` first unless you have a strong reason to manually read the full object graph.
3. Treat every nested object as attacker-controlled until validated.
4. Never invoke methods on deserialized collaborators from inside `readObject()`.
5. Pair the code review with an `ObjectInputFilter` review; “safe-looking `readObject()` code” is not enough if the stream still accepts arbitrary classes.

## References

- [1] [OpenJDK JEP 415: Context-Specific Deserialization Filters](https://openjdk.org/jeps/415)
- [2] [GitHub Security Lab: GHSL-2022-085 / CVE-2023-25581 (`pac4j-core` deserialization leading to RCE)](https://securitylab.github.com/advisories/GHSL-2022-085_pac4j/)
- [3] [Java Deserialization Tool: GadgetInspector First Glimpse](https://medium.com/@knownsec404team/java-deserialization-tool-gadgetinspector-first-glimpse-74e99e493649)
- [4] [Spring Security Advisory: CVE-2023-34040 (Spring for Apache Kafka)](https://spring.io/security/cve-2023-34040)
- [5] [Aerospike Security Advisory: CVE-2023-36480 - Aerospike Java Client vulnerable to unsafe deserialization of server responses](https://github.com/aerospike/aerospike-client-java/security/advisories/GHSA-jj95-55cr-9597)
- [6] [Oracle – Java Object Serialization Specification: Object Input Classes](https://docs.oracle.com/en/java/javase/17/docs/specs/serialization/input.html)
- [7] [Jenkov – Java `ObjectOutputStream`](https://jenkov.com/tutorials/java-io/objectoutputstream.html)
- [8] [Jenkov – Java `ObjectInputStream`](https://jenkov.com/tutorials/java-io/objectinputstream.html)

{{#include ../../banners/hacktricks-training.md}}
