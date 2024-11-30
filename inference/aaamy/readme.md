# 华中科技大学网络安全程序设计
## 基于OpenSSL的安全聊天系统
一个简单的OpenSSL聊天系统，具有以下功能:

1. 支持Windows或Linux平台
2. 点到点模式
3. 基于OpenSSL的安全套接字通信
4. 客户端服务器双向认证
5. 聊天记录本地加密存储，输入正确口令可查看

## 使用说明
### 环境配置
```bash
# 首先需要配置好基础的Python环境 Python版本需>=3.8
# 接着安装依赖库
pip install -r reqirements.txt
# 然后将wxfchat库拷贝到每一台测试机中
```

### 证书生成
```bash
cd cert
make cert
# make clean可一键清除证书
# 仅支持Linux，windows需更换证书生成方式，或者直接拷贝生成好的证书到certs目录中
```

### 启动服务端
```bash
python user.py
# 程序输出提示
# "Do you want to connect(client), listen(server), check(history) or exit? (c/s/h/q):
# 选择启动服务器模式，并设置端口和密钥
```

### 启动客户端
```bash
python user.py
# 根据提示启动客户端模式，并设置目标IP、端口和密钥
```

### 解密本地消息记录
```bash
python user.py
# 程序将打印history目录下的所有消息记录文件
# 选择其中的一个输入正确密钥查看
```

## 其他
详细见报告