# log4j2_burp_scan
自用脚本log4j2 被动 burp rce扫描工具 get post cookie 全参数识别，在ceye.io api速率限制下，最大线程扫描每一个参数，记录过滤已检测地址，重复地址

![image](https://user-images.githubusercontent.com/50195525/145595971-b9de921f-112b-4b5b-8da4-70246fe0d7c8.png)

![image](https://user-images.githubusercontent.com/50195525/145596091-aae11539-4566-403c-acb8-4a9b005d930c.png)
![image](https://user-images.githubusercontent.com/50195525/145597555-fe1aac93-9d33-44d4-aff6-997e33e67bf2.png)

token替换为你自己的http://ceye.io/ token 和域名地址
![image](https://user-images.githubusercontent.com/50195525/145596378-610449c5-6693-48e7-bbac-db182cead42b.png)
不要忘了设置这个

套用https://github.com/SkewwG/BurpExtender/ SQL注入检测插件


