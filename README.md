# Phần mềm quản lý trạm đổi pin xe điện VIN
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-6DB33F?logo=Spring&logoColor=white&style=flat-square)](https://spring.io/)
[![MySQL Version](https://img.shields.io/badge/MySQL-8.0-blue)](https://dev.mysql.com/downloads/mysql/8.0.html)

<p align="center">
  <img src="https://github.com/user-attachments/assets/9006e978-eb81-4323-b0d8-285023d23424" alt="Logo">
</p>

## Công Nghệ Sử Dụng

<div style="border: 2px solid #f39c12; padding: 15px; background-color: #fffbe6; border-radius: 10px;">

<details open>
<summary><b>Công cụ làm việc</b></summary>

- Git
- VS Code
- Github
  
</details>
</div>


<div style="border: 2px solid #f39c12; padding: 15px; background-color: #fffbe6; border-radius: 10px;">

<details open>
<summary><b>Phần Backend</b></summary>

- Java 21
- Maven
- Spring Boot 3.5.7 
  - Spring Data JPA - ORM và database operations
  - Spring JDBC - Database connectivity
  - Spring Security - Authentication & Authorization
  - Spring Web - RESTful APIs
- Lombok 1.18.42
- JWT (jjwt 0.12.6)
- Thymeleaf
- MySQL Connector - Database driver
  
</details>
</div>

<div style="border: 2px solid #3498db; padding: 15px; background-color: #e6f3ff; border-radius: 10px; margin-top: 15px;">

<details open>
<summary><b>Phần Frontend</b></summary>

- HTML
- CSS
- JavaScript

</details>
</div>

<div style="border: 2px solid #3498db; padding: 15px; background-color: #e6f3ff; border-radius: 10px; margin-top: 15px;">

<details open>
<summary><b>Cơ sở dữ liệu</b></summary>

- MySQL 8.0

</details>
</div>

## Downloading Apache Maven : https://maven.apache.org/download.cgi

## Tổng Quan
Ứng dụng web quản lý hệ thống đổi pin cho xe điện, hỗ trợ 3 vai trò:
- Driver - Tài xế xe điện
- Staff - Nhân viên trạm
- Admin - Quản trị viên
### Driver (Tài Xế)
- Đổi pin nhanh chóng
- Tìm trạm gần nhất
- Quản lý phương tiện
- Thanh toán & lịch sử
- Dashboard cá nhân
- Đăng ký gói dịch vụ

### Staff (Nhân Viên)
- Quản lý trạm
- Xác nhận đổi pin
- Quản lý kho pin
- Báo cáo hoạt động
- Xử lý sự cố
- Quản lý giao dịch

### Admin (Quản Trị)
- Quản lý người dùng
- Quản lý trạm
- Quản lý pin
- Báo cáo tổng quan
- Quản lý doanh thu

## Cấu trúc hệ thống
```
Java-WebApp/
├── .gitignore
├── README.md
├── pom.xml                          # File cấu hình Maven
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/                 # Package chính chứa mã nguồn Java
│   │   └── resources/
│   │       ├── application.properties   # File cấu hình ứng dụng
│   │       ├── static/                  # Thư mục chứa các file tĩnh (CSS, JS, images)
│   │       └── templates/               # Thư mục chứa các file Thymeleaf templates (HTML)
│   └── test/
│       └── java/                    # Chứa các test cases
└── target/                          # Thư mục output sau khi build (auto-generated)
```

### Cài đặt cấu hình & chạy

#### Cấu hình Application Properties

File `src/main/resources/application.properties`:
```properties
spring.application.name=BatterySwap
# ===============================
# = DATABASE CONFIGURATION
# ===============================

spring.datasource.url=<Data Source from URL>
spring.datasource.username=<username data>
spring.datasource.password=<password data>
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

# ===============================
# = JPA / HIBERNATE CONFIGURATION
# ===============================
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true

spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect

spring.thymeleaf.prefix=classpath:/templates/
spring.thymeleaf.suffix=.html
spring.thymeleaf.cache=false
```

#### Build Jar Project & Run
```
git clone git@github.com:huynhmainhatminh/Java-WebApp.git
```
File `Java-WebApp`:
```
mvn clean package

java -jar target/BatterySwap-0.0.1-SNAPSHOT.jar
```
#### Website localhost
```
http://localhost:8080/
```






