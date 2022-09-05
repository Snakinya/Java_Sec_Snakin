## 01 简介

fastjson 是阿里巴巴的开源 JSON 解析库，它可以解析 JSON 格式的字符串，支持将 Java Bean 序列化为 JSON 字符串，也可以从 JSON 字符串反序列化到 JavaBean。
 由于其特点是快，以性能为优势快速占领了大量用户，并且其 API  十分简洁，用户量十分庞大，这也就导致了这样的组件一旦爆出漏洞，危害也将会是巨大的，因此，fastjson  从第一次报告安全漏洞至今，进行了若干次的安全更新，也与安全研究人员进行了来来回回多次的安全补丁-绕过的流程。

## 02 下载

maven仓库下载

> [mvnrepository.com/artifact/com.alibaba/fastjson](https://mvnrepository.com/artifact/com.alibaba/fastjson)

## 03 基础使用

### Fastjson反序列化的类方法调用关系

![img1](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/1616458393831.png)

JSON：门面类，提供入口 

DefaultJSONParser：主类 

ParserConfig：配置相关类 

JSONLexerBase：字符分析类 

JavaBeanDeserializer：JavaBean反序列化类

### 序列化和反序列化

DEMO:

```java
import com.alibaba.fastjson.*;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class Student {
    private String name;
    private int age;

    public Student() {
        System.out.println("构造函数");
    }

    public void setName(String name) {
        this.name = name;
    }
    
    public void setAge(int age) {
        this.age = age;
    }
    
    public String getName() {
        return name;
    }

    public int getAge() {
        return age;
    }
}
```

#### JSON.toJSONString序列化

```java
 public static void main(String[] args){
        Student student = new Student();
        student.setName("Snakin");
        student.setAge(20);
        String jsonstring = JSON.toJSONString(student, SerializerFeature.WriteClassName);
        System.out.println(jsonstring);
    }
```

**SerializerFeature.WriteClassName，是JSON.toJSONString()中的一个设置属性值，设置之后在序列化的时候会多写入一个@type，即写上被序列化的类名，type可以指定反序列化的类，并且调用其getter/setter/is方法。**

Fastjson接受的JSON可以通过@type字段来指定该JSON应当还原成何种类型的对象，在反序列化的时候方便操作。

输出：

![image-20220404113002296](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404113002296.png)

当未使用`SerializerFeature.WriteClassName`时：

```
String jsonString = JSON.toJSONString(student);
```

![image-20220404113204009](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404113204009.png)

#### JSON.parseObject()反序列化

```java
public static void main(String[] args){
        String jsonstring ="{\"@type\":\"fastjson.Student\",\"age\":20,\"name\":\"Snakin\"}";
        Student obj = JSON.parseObject(jsonstring, Student.class, Feature.SupportNonPublicField);
        System.out.println(obj);
        System.out.println(obj.getClass().getName());
    }
```

输出

![image-20220404114031073](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404114031073.png)

#### Feature.SupportNonPublicField

如果需要还原出private属性的话，还需要在JSON.parseObject/JSON.parse中加上Feature.SupportNonPublicField参数。

```java
import com.alibaba.fastjson.*;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class Student {
    private String name;
    private int age;

    public Student() {
        System.out.println("构造函数");
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }
    public static void main(String[] args){
        String jsonstring = "{\"@type\":\"fastjson.Student\",\"age\":20,\"name\":\"Snakin\"}";
        Student obj = JSON.parseObject(jsonstring, Student.class);
        System.out.println(obj);
        System.out.println(obj.getClass().getName());
        System.out.println(obj.getName() + " " + obj.getAge());
    }
}
```

输出：

![image-20220404132937638](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404132937638.png)

此时并没有获取到age的值，我们加上`Feature.SupportNonPublicField`

```java
Student obj = JSON.parseObject(jsonstring, Student.class, Feature.SupportNonPublicField);
```

![image-20220404133045233](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404133045233.png)

成功还原

#### 总结

- 当反序列化为`JSON.parseObject(*)`形式即未指定class时，会调用反序列化得到的类的构造函数、所有属性的getter方法、JSON里面的非私有属性的setter方法，其中properties属性的getter方法调用了两次；
- 当反序列化为`JSON.parseObject(*,*.class)`形式即指定class时，只调用反序列化得到的类的构造函数、JSON里面的非私有属性的setter方法、properties属性的getter方法；
- 当反序列化为`JSON.parseObject(*)`形式即未指定class进行反序列化时得到的都是JSONObject类对象，而只要指定了class即`JSON.parseObject(*,*.class)`形式得到的都是特定的Student类；

### parse与parseObject区别

FastJson中的 parse() 和  parseObject()方法都可以用来将JSON字符串反序列化成Java对象，parseObject() 本质上也是调用 parse()  进行反序列化的。但是 parseObject() 会额外的将Java对象转为 JSONObject对象，即  JSON.toJSON()。所以进行反序列化时的细节区别在于，parse() 会识别并调用目标类的 setter 方法及某些特定条件的  getter 方法，而 parseObject() 由于多执行了 JSON.toJSON(obj)，所以在处理过程中会调用反序列化目标类的所有  setter 和 getter 方法。

> parse会去优先匹配调用字段的set方法，如果没有set方法，就会去寻找字段的get方法
>
> parseObject会调用set与get方法

```java
package fastjson;

import com.alibaba.fastjson.*;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class Student {
    private String name;
    private int age;

    public Student() {
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public void setAge(int age) {
        System.out.println("setAge");
        this.age = age;
    }
    public static void main(String[] args){
        String jsonstring = "{\"@type\":\"fastjson.Student\",\"age\":20,\"name\":\"Snakin\"}";
        System.out.println("===parseObject===");
        JSON.parseObject(jsonstring);
        System.out.println("===parse===");
        JSON.parse(jsonstring);

    }
}
```

输出

![image-20220404134226059](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404134226059.png)



参考：

https://github.com/Y4tacker/JavaSec/blob/main/3.FastJson%E4%B8%93%E5%8C%BA/Fastjson%E5%9F%BA%E6%9C%AC%E7%94%A8%E6%B3%95/Fastjson%E5%9F%BA%E6%9C%AC%E7%94%A8%E6%B3%95.md

https://blog.csdn.net/Xxy605/article/details/123253430
