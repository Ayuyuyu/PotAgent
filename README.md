# PotAgent 
PotAgent 是一个轻量级的蜜罐模拟程序，但是依然能够起到不错的效果，举报服务模拟，日志记录等功能。（当然也可以增加一定的日志检测能力）
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
- [ ] smb
- [ ] dns
- [ ] https
- [ ] 工控系列PLC
* **多服务配置启动**   
通过配置文件，实现多个不同端口的不同服务内容。例如不同返回的telnet信息，不同的http服务等。  
详情见service_conf中的两个http配置文件。
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
go build -o PotAgent main.go 
```
**文件目录**  
```
├─services_conf  # 服务配置文件与资源文件
├─PotAgent       # 主程序
└─pot.yaml       # 程序配置文件
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
