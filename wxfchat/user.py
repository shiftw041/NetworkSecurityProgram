import datetime
import os
import socket
import ssl
import threading
import signal
from time import sleep
from Crypto.Cipher import AES

# 消息解密类
class ChatDecryptor:
    def __init__(self, password):
        # 初始化解密器，密码将被编码为字节串并填充至16字节
        self.passwd = password.encode('utf-8')
        if len(self.passwd) <= 16:
            self.passwd += b'\x00' * (16 - len(self.passwd))
        self.passwd = self.passwd[:16]

    def decrypt_chat_log(self, file_name):
        # 解密聊天记录文件
        try:
            with open(file_name, "rb") as crypt_file:
                en_text = crypt_file.read()
                # 创建AES对象，使用ECB模式
                aes = AES.new(self.passwd, AES.MODE_ECB)
                 # 解密密文
                den_text = aes.decrypt(en_text)
                 # 输出解密后的聊天记录
                print("Chat history is below: ", den_text.decode())
        except FileNotFoundError:
            print("Doc path wrong")
        except Exception as e:
            print(f"Error for decrypto: {e}")

# 消息记录类，用于记录和加密聊天记录
class msg_recorder:
    # 接收密码参数 默认为123456
    def __init__(self, passwd="123456"):
        self.passwd = passwd.encode('utf-8')
        while len(self.passwd) <= 16:
            self.passwd = self.passwd + b'\x00'
        self.passwd = self.passwd[0:16]
        self.buff = ""

    # 记录聊天消息
    def record(self, sender, content):
        msg = "[{}]{} >> {}".format(datetime.datetime.now(), sender, content)
        self.buff = "{}\n{}".format(self.buff, msg)

    def output(self, file):
        aes = AES.new(self.passwd, AES.MODE_ECB)  # 创建一个aes对象
        text = self.buff.encode('utf-8')
        while len(text) % AES.block_size != 0:
            text = text + b'\x00'
        file.write(aes.encrypt(text))

# 客户端类，使用SSL协议向对方发起通信连接
class client_ssl:
    def connect_server(self, ip, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        context.load_verify_locations('cert/ca.crt')# 验证对方证书
        context.load_cert_chain('cert/client.crt','cert/client.key')# 加载客户端证书和私钥，用于自身的身份验证

        # 关闭检查对方的hostname，用于测试环境
        context.check_hostname = False

        # 创建到对方的套接字连接
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname='server.psk') as ssock:
                while True:
                    # 向服务端发送信息
                    send_msg = input("C >> ")
                    if send_msg == "exit()":
                        break
                    ssock.send(send_msg.encode("utf-8"))
                    # 接收服务端返回的信息
                    msg = ssock.recv(1024).decode("utf-8")
                    if len(msg) >= 0:
                        print(f"S >> {msg}")
                    sleep(0.5)
                # 关闭SSL连接
                ssock.close()




recorder = None

# 客户端通信类
class ssl_client:
    def __init__(self, ssl_client, ssl_client_address):
        self.client = ssl_client
        self.addr = ssl_client_address

    def build(self):
        global recorder
        ssl_client = self.client

        while True:
            recv_data = ssl_client.recv(1024)

            if recv_data:
                print("C >>".format(self.addr), recv_data.decode())
                recorder.record("C",recv_data.decode())
                send_msg = input("S >> ".format(self.addr)).encode("utf-8")
                recorder.record("S", send_msg.decode())
                ssl_client.send(send_msg)
            else:
                print("Connetion close, encrypted chat history is generated.".format(self.addr))
                if not os.path.exists("./history"):
                    os.mkdir("./history")
                file = open("./history/{}".format(datetime.datetime.now()),"wb")
                recorder.output(file)
                ssl_client.close()
                break
    
# 服务器类
class server_ssl:

    def __init__(self, port, client_num=100):
        self.port = port
        self.client_num = client_num
    def build_server(self):
        # 创建了SSL上下文对象, 此上下文将用于服务器端的 TLS 通信
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER, )
        # 设置 SSL 上下文的验证模式, 客户端必须提供证书。如果客户端未提供证书或证书无效，SSL 握手将失败
        context.verify_mode = ssl.CERT_REQUIRED

        context.load_cert_chain('cert/server.crt', 'cert/server.key')
        context.load_verify_locations('cert/ca.crt')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('172.17.0.1', self.port))
            sock.listen(self.client_num)
            print("Begin listening")

            with context.wrap_socket(sock, server_side=True, ) as ssock:
                while True:
                    try:
                        client_socket, addr = ssock.accept()
                    except:
                        # print("Connection failed")
                        ssock.close()
                        break

                    client = ssl_client(client_socket, addr)

                    thd = threading.Thread(target=client.build, args=())
                    thd.setDaemon(True)
                    thd.start()
                # ssock.close()

if __name__ == "__main__":
    while True:
        print()
        role = input("Do you want to connect(client), listen(server), check(history) or exit? (c/s/h/q): ").strip().lower()
        if role == 'q':
            print("Exit the program.")
            break
    
        elif role == 'c':
            ip = input("Enter the IP want to connect(default: 172.17.0.1): ").strip() or "172.17.0.1"
            port_input = input("Enter the communication port (default: 1231): ").strip()
            port = int(port_input) if port_input else 1231
            passwd = input("Enter a password to encrypt chat history(default: 123456): ") or "123456"
            # 执行客户端逻辑
            # recorder = msg_recorder(passwd)
            print("")
            client = client_ssl()
            client.connect_server(ip, port)

        elif role == 's':
            # 执行服务器逻辑
            port_input = input("Enter the communication port (default: 1231): ").strip()
            port = int(port_input) if port_input else 1231
            passwd = input("Enter a password to encrypt chat history(default: 123456): ") or "123456"
            recorder = msg_recorder(passwd)
            server = server_ssl(port)
            server.build_server()

        elif role == 'h':
            history_dir = "./history"
            if os.path.exists(history_dir):
                files = os.listdir(history_dir)
                print("Files in history directory:")
                for file in files:
                    print(file)
            else:
                print(f"The directory '{history_dir}' does not exist.")
            crypt_file_name = "./history/" + input("Enter the chat history file to check: ")
            password = input("Enter password: ")
            decryptor = ChatDecryptor(password)
            decryptor.decrypt_chat_log(crypt_file_name)

        else:
            print("Invalid option!!!")
    