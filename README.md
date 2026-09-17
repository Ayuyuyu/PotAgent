# PotAgent 
PotAgent 是一个轻量级的蜜罐模拟程序，但是依然能够起到不错的效果，具备服务模拟，日志记录等功能。（当然也可以增加一定的日志检测能力）
PotAgent 使用golang完成开发。PotAgent在好几年前就已经完成，现在是重写上传。上传的当前版本有参考[honeytrap](https://github.com/honeytrap/honeytrap)，也当然会更加贴合实际的使用场景进行修改。
## WHY低交互
高交互蜜罐具备极好的模拟能力，但是不管是KVM模式还是docker模式创建的蜜罐系统都是极其占用系统资源的，并且其扩展性能并不好。
对于使用过蜜罐系统的人来说，轻量级、高仿真、可配置低交互才是更合适的方向。  
低廉的性能占用，大范围的模拟才能更好的构成完整的感知网络。
## Feature
* **服务模拟**   
- [x] ssh
- [x] telnet
- [x] vnc
- [x] http
- [x] smb
- [x] dns
- [x] https
- [ ] 工控系列PLC
* **多服务配置启动**   
通过配置文件，实现多个不同端口的不同服务内容。
详情见service_conf中的配置文件。
* **日志输出**  
  日志输出格式为json格式，支持文件输出与kafka输出。方便对接扩展
* **大模型接入**
  AI接入更好的模拟输出数据，提高仿真度。 
  - [ ] DeepSeek
  - [ ] QWEN
## 使用  
推荐使用makefile直接编译生成。
直接编译使用：
```
#推荐使用go 1.20以上版本
go build -o PotAgent ./cmd/potagent 
```
**文件目录**  
```
├─services_conf/
│  ├─*.yaml          # 各服务实例配置（http / http_another / https / smb / ssh / telnet / vnc）
│  ├─https/         # HTTPS 自签证书 cert.pem / key.pem（测试用）
│  └─assets/        # 各协议静态资源，由 assets.zip 启动时解压
├─PotAgent          # 主程序
└─pot.yaml          # 程序配置文件（services_dir / outputs）
```
**执行**  
默认读取程序目录的配置文件，也可以进行配置目录进行更改。
```
PotAgent -h
NAME:
   honeypot agent - potAgent flags here

USAGE:
   honeypot agent [global options] command [command options]

DESCRIPTION:
   potAgent for low interact honeypot
    Build Time:
    Build Version:


COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config FILE  Load configuration from FILE (default: "pot.yaml")
   --data DIR     Store data in DIR (default: "~/.potAgent")
   --help, -h     show help
```

**HTTPS**  
http 服务支持可选 TLS，复用同一套请求解析与资源响应逻辑（额外注册了 `https` 协议）。在某个服务 yaml 里加上 `tls` 块即走 HTTPS：

```yaml
protocol: "https"
application: "https-secure"
host: "0.0.0.0"
port: 8443
assets_dir: "./services_conf/assets/http/PhpMyAdmin_4.8.1"
index: "home.html"
tls:
  cert_file: "./services_conf/https/cert.pem"
  key_file: "./services_conf/https/key.pem"
```

未配置 `tls` 的实例仍为明文 HTTP。仓库自带一张自签证书（`services_conf/https/`，测试用），验证方式：

```
curl --cacert services_conf/https/cert.pem https://127.0.0.1:8443/
```

如需正式环境证书，替换 `cert_file`/`key_file` 指向的 CA 签发文件即可，建议不要把私钥提交进仓库。
