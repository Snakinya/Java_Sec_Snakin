## JDBC编程

JDBC定义了一个叫`java.sql.Driver`的接口类负责实现对数据库的连接，所有的数据库驱动包都必须实现这个接口才能够完成数据库的连接操作。

## JDBC连接数据库的一般步骤:

- **导入JDBC包**
- **注册JDBC驱动程序**：Class.forName("数据库驱动的类名")。
- **数据库URL配置**：创建一个正确格式化的地址，指向要连接到的数据库。
- **创建连接对象**：DriverManager.getConnection(xxx)

### 注册驱动

Java通过`java.sql.DriverManager`来管理所有数据库的驱动注册，所以如果想要建立数据库连接需要先在`java.sql.DriverManager`中注册对应的驱动类，然后调用`getConnection`方法才能连接上数据库。

```java
String CLASS_NAME = "com.mysql.jdbc.Driver";
Class.forName(CLASS_NAME);// 注册JDBC驱动类
```

#### Class.forName注册

![image-20220224130259693](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220224130259693.png)

`Class.forName("com.mysql.cj.jdbc.Driver")`实际上会触发类加载，`com.mysql.cj.jdbc.Driver`类将会被初始化，所以`static静态语句块`中的代码也将会被执行。

### 建立连接

加载驱动程序后，可以使用 **DriverManager.getConnection()** 方法建立连接 **返回 Connection 的一个对象**。`DriverManager`会自动扫描classpath，找到所有的JDBC驱动，然后根据我们传入的URL自动挑选一个合适的驱动。

```java
String URL = "jdbc:mysql://127.0.0.1:3306/mysql";
String USERNAME = "xxx";
String PASSWORD = "xxx";
Connection conn = DriverManager.getConnection(URL, USERNAME, PASSWORD);
```

以下为不同数据库的JDBC

| RDBMS      | JDBC驱动程序名称                | URL格式                                                      |
| ---------- | ------------------------------- | ------------------------------------------------------------ |
| MySQL      | com.mysql.jdbc.Driver           | jdbc:mysql://hostname/databaseName                           |
| ORACLE     | oracle.jdbc.driver.OracleDriver | jdbc:oracle:thin:[@hostname](https://github.com/hostname):portNumber:databaseName |
| PostgreSQL | org.postgresql.Driver           | jdbc:postgresql://hostname:port/dbname                       |
| DB2        | com.ibm.db2.jdbc.net.DB2Driver  | jdbc:postgresql://hostname:port/dbname                       |
| Sybase     | com.ibm.db2.jdbc.net.DB2Driver  | jdbc:sybase:Tds:hostname: portNumber/databaseName            |

### JDBC查询

第一步，通过`Connection`提供的`createStatement()`方法创建一个`Statement`对象，用于执行一个查询；

第二步，执行`Statement`对象提供的`executeQuery("SELECT * FROM students")`并传入SQL语句，执行查询并获得返回的结果集，使用`ResultSet`来引用这个结果集；

第三步，反复调用`ResultSet`的`next()`方法并读取每一行结果。

**SQL执行方式**

```
Statement.execute(); // 任意
Statement.executeQuery(); // 查询，返回一个 ResultSet 对象
Statement.executeUpdate(); // 增删改
```

示例：

```java
String sql = "select id,passwd from user";
Statement statement = con.createStatement();
if(statement.execute(sql)){
	System.out.println("成功");
}
```

**结果集**

SQL语句执行后从数据库查询读取数据，返回的数据放在结果集中。

```
ResultSet results = pre.executeQuery();
```

### 关闭连接

```
results.close();
pre.close();
conn.close();
```

也可以使用`try (resource)`来自动释放JDBC连接。

```java
try (Connection conn = DriverManager.getConnection(JDBC_URL, JDBC_USER, JDBC_PASSWORD)) {
    ...
}
```

### JDBC连接示例

```java
package com.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class jdbc {
    static final String URL = "jdbc:mysql://127.0.0.1:3306/security";
    static final String USERNAME = "root";
    static final String PASSWORD = "root";
    static final String JDBC_DRIVER = "com.mysql.cj.jdbc.Driver";
    public static void main(String[] args) throws Exception {
        Class.forName(JDBC_DRIVER);
        try (Connection conn = DriverManager.getConnection(URL, USERNAME, PASSWORD)) {
            try (Statement stmt = conn.createStatement()) {
                try (ResultSet rs = stmt.executeQuery("select id,password from security.users")) {
                    while (rs.next()) {
                        System.out.println(rs.getInt("id"));
                        System.out.println(rs.getString("password"));
                    }
                }
            }
        }
    }
}
```

![image-20220224125020202](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220224125020202.png)











