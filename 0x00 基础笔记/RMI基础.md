## 什么是java RMI

RMI ( Remote Method Invocation , 远程方法调用 ) 能够让在某个 Java虚拟机  上的对象像调用本地对象一样调用另一个 Java虚拟机 中的对象上的方法 , 这两个 Java虚拟机 可以是运行在同一台计算机上的不同进程,   也可以是运行在网络中不同的计算机上 .`RMI`实现了`Java`程序之间跨`JVM`的远程通信。

## RMI 构成

RMI的主要由三部分组成

1. RMI Registry 注册表：服务实例将被注册表注册到特定的名称中
2. RMI Server 服务端
3. RMI Client 客户端：客户端通过查询注册表来获取对应名称的对象引用，以及该对象实现的接口

**交互流程：**

![img](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/1633322482542.png)

RMI 底层通讯采用了Stub (运行在客户端) 和 Skeleton (运行在服务端) 机制，**RMI 调用远程方法的大致如下：**

1. RMI 客户端在调用远程方法时会先创建 Stub ( `sun.rmi.registry.RegistryImpl_Stub` )。
2. Stub 会将 Remote 对象传递给远程引用层 ( `java.rmi.server.RemoteRef` ) 并创建 `java.rmi.server.RemoteCall`( 远程调用 )对象。
3. RemoteCall 序列化 RMI 服务名称、Remote 对象。
4. RMI 客户端的远程引用层传输 RemoteCall 序列化后的请求信息通过 Socket 连接的方式传输到 RMI 服务端的远程引用层。
5. RMI服务端的远程引用层( `sun.rmi.server.UnicastServerRef` )收到请求会请求传递给 Skeleton ( `sun.rmi.registry.RegistryImpl_Skel#dispatch` )。
6. Skeleton 调用 RemoteCall 反序列化 RMI 客户端传过来的序列化。
7. Skeleton 处理客户端请求：bind、list、lookup、rebind、unbind，如果是 lookup 则查找 RMI 服务名绑定的接口对象，序列化该对象并通过 RemoteCall 传输到客户端。
8. RMI 客户端反序列化服务端结果，获取远程对象的引用。
9. RMI 客户端调用远程方法，RMI服务端反射调用RMI服务实现类的对应方法并序列化执行结果返回给客户端。
10. RMI 客户端反序列化 RMI 远程方法调用结果。

## 例子

### Server

#### 远程接口

接口需要继承Remote，Remote用以标记一个可以被远程调用的接口，并且此接口内的所有方法必须抛出RemoteException

> **Remote 接口是一个标识接口 , 本身不包含任何方法 ,  该接口用于标识其子类的方法可以被非本地的Java虚拟机调用**
>
> **由于远程调用的本质依旧是 " 网络通信 " . 而网络通信是经常出现异常的 . 因此 , 继承 `Remote` 接口的接口的所有方法必须要抛出 `RemoteException` 异常 . 事实上 , `RemoteException` 也是继承于 `IOException` 的 .**

```java
package rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMIInterface extends Remote {
    String hello(String name) throws RemoteException;
}
```

#### 接口实现类

- 继承 **`UnicastRemoteObject`** 类

- 创建serialVersionUID（可选）用以支持序列化

**只有当接口的实现类继承了 `UnicastRemoteObject` 类 , 客户端访问获得远程对象时 , 远程对象才将会把自身的一个拷贝以 `Socket` 的形式传输给客户端**，这个拷贝也就是 `Stub` , 或者叫做 " 存根 " 。

```java
package rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMIImpl extends UnicastRemoteObject implements RMIInterface{

    private static final long serialVersionUID = 1L;

    protected RMIImpl() throws RemoteException {
        super();
    }

    @Override
    public String hello(String name) throws RemoteException {
        return "Hello! " + name;
    }
}
```

#### 主程序

- `LocateRegistry.createRegistry()`在指定端口注册服务
- `Naming.bind()`将服务与端口绑定，并且**自定义一个服务的名称**

```java
package rmi;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        RMIInterface skeleton = new RMIImpl();
        LocateRegistry.createRegistry(1099);
        Naming.bind("rmi://127.0.0.1/hello", skeleton);
    }
}
```

### Client

- `LocateRegistry.createRegistry()`获取远程服务注册，需要指定IP与端口

```java
package rmi;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry("localhost",1099);
        RMIInterface impl = (RMIInterface) registry.lookup("hello");
        System.out.println(impl.hello("snakin"));
    }
}
```

### 运行

先运行`RMIServer`再运行`RMIClient`

![image-20220312142344078](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220312142344078.png)

## 安全性问题

1. **远程对象方法调用，以序列化方式传递参数，反序列化时可能存在漏洞**

2. **反序列化构建Classpath不存在的类的对象时，如果允许加载远端类，加载并初始化恶意类会产生漏洞**

   

参考：

su18
