## Fastjson反序列化漏洞原理

### 漏洞原理

Fastjson是自己实现的一套序列化和反序列化机制，不是用的Java原生的序列化和反序列化机制。无论是哪个版本，Fastjson反序列化漏洞的原理都是一样的，只不过不同版本是针对不同的黑名单或者利用不同利用链来进行绕过利用而已。

通过Fastjson反序列化漏洞，攻击者可以传入一个恶意构造的JSON内容，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行。

**那么如何才能够反序列化出恶意类呢？**

Fastjson使用`parseObject()/parse()`进行反序列化的时候可以指定类型。如果指定的类型太大，包含太多子类，就有利用空间了。例如，如果指定类型为Object或JSONObject，则可以反序列化出来任意类。例如代码写`Object o = JSON.parseObject(poc,Object.class)`就可以反序列化出Object类或其任意子类，而Object又是任意类的父类，所以就可以反序列化出所有类。

**接着，如何才能触发反序列化得到的恶意类中的恶意函数呢？**

由前面知道，在某些情况下进行反序列化时会将反序列化得到的类的构造函数、getter方法、setter方法执行一遍，如果这三种方法中存在危险操作，则可能导致反序列化漏洞的存在。换句话说，就是攻击者传入要进行反序列化的类中的构造函数、getter方法、setter方法中要存在漏洞才能触发。

我们到DefaultJSONParser.parseObject(Map object, Object  fieldName)中看下，JSON中以@type形式传入的类的时候，调用deserializer.deserialize()处理该类，并去调用这个类的setter和getter方法：

```java
@SuppressWarnings({ "unchecked", "rawtypes" })
public final Object parseObject(final Map object, Object fieldName) {
    ...
    // JSON.DEFAULT_TYPE_KEY即@type
    if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
		...
        ObjectDeserializer deserializer = config.getDeserializer(clazz);
        return deserializer.deserialze(this, clazz, fieldName);
```

整个解析过程相当复杂，知道结论就ok了。

**小结一下**

若反序列化指定类型的类如`Student obj = JSON.parseObject(text, Student.class);`，该类本身的构造函数、setter方法、getter方法存在危险操作，则存在Fastjson反序列化漏洞；

若反序列化未指定类型的类如`Object obj = JSON.parseObject(text, Object.class);`，该若该类的子类的构造方法、setter方法、getter方法存在危险操作，则存在Fastjson反序列化漏洞；

### PoC写法

一般的，Fastjson反序列化漏洞的PoC写法如下，@type指定了反序列化得到的类：

```json
{
"@type":"xxx.xxx.xxx",
"xxx":"xxx",
...
}
```

关键是要找出一个特殊的在目标环境中已存在的类，满足如下两个条件：

1. 该类的构造函数、setter方法、getter方法中的某一个存在危险操作，比如造成命令执行；
2. 可以控制该漏洞函数的变量（一般就是该类的属性）；

### 漏洞Demo

由前面比较的案例知道，当反序列化指定的类型是Object.class，即代码为`Object obj = JSON.parseObject(jsonstring, Object.class, Feature.SupportNonPublicField);`时，反序列化得到的类的构造函数、所有属性的setter方法、properties私有属性的getter方法都会被调用，因此我们这里直接做最简单的修改，将Student类中会被调用的getter方法添加漏洞代码，这里修改getProperties()作为演示：

```java
import com.alibaba.fastjson.*;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;

import java.util.Properties;

public class Student {
    private String name;
    private int age;
    private String address;
    private Properties properties;

    public Student() {
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public Properties getProperties() throws Exception {
        System.out.println("getProperties");
        Runtime.getRuntime().exec("calc");
        return properties;
    }
    public static void main(String[] args){
        String jsonstring ="{\"@type\":\"fastjson.Student\",\"age\":20,\"name\":\"Snakin\",\"properties\":{}}";
        Object obj = JSON.parseObject(jsonstring, Object.class, Feature.SupportNonPublicField);
        System.out.println(obj);
    }
}
```

很明显，前面的Demo中反序列化的类是一个Object类，该类是任意类的父类，其子类Student存在Fastjson反序列化漏洞，当@type指向Student类是反序列化就会触发漏洞。

对于另一种反序列化指定类的情景，是该指定类本身就存在漏洞，比如我们将上述Demo中反序列化那行代码改成直接反序列化得到Student类而非Object类，这样就是另一个触发也是最直接的触发场景：

```
Student obj = JSON.parseObject(jsonstring, Student.class, Feature.SupportNonPublicField);
```

![image-20220404135708091](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404135708091.png)

