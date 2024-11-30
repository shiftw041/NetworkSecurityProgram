import hashlib
import select
import signal
import socket
import ssl
import sys

SERVER_PORT = 7890
SERVER_CERT = 'cert/server.crt'
SERVER_KEY_FILE = 'cert/server.key'
CA_CERT = 'cert/ca.crt'
CERT_PASSWORD = '123456'
USERS_FILE = 'data/users.ini'

conn_list = []  # 连接池
active_users = set()  # 已在线用户
conn_map = {}  # 连接地址-用户映射


def broadcast_data(src_sock: ssl.SSLSocket, data: bytes):
    """数据广播到其它客户端"""
    # global conn_list
    for sock in conn_list:
        if sock != server_socket and sock != src_sock \
                and sock.getpeername() in conn_map:
            try:
                sock.write(data)
            except Exception as e:
                print(e.args)
                sock.close()
                conn_list.remove(sock)


def load_users():
    user_dict = {}
    with open(USERS_FILE, 'r') as file:
        for line in file.readlines():
            user = line.split('$$')
            name = user[0].strip()
            pwd = user[1].strip()
            user_dict[name] = pwd
        return user_dict


def accept():
    """接收来自客户端的TCP连接，并使用OpenSSL进行双向认证和封装"""
    # 返回一个新套接字sockfd,以及另一端套接字绑定的地址addr(hostaddr,post)
    sockfd, _ = server_socket.accept()
    ssl_sock = context.wrap_socket(sockfd, server_side=True)
    conn_list.append(ssl_sock)


def sign_up(sock: ssl.SSLSocket, data: str):
    info = data.split('\n\n')
    username = info[0]
    if username in user_dict:
        sock.write('$FAI$User already exists.'.encode())
    else:
        pwd = hashlib.sha256(info[1].encode()).hexdigest()
        user_dict[username] = pwd
        with open(USERS_FILE, 'a') as file:
            file.write(username + '$$' + pwd + '\n')
        sock.write('$SUC$'.encode())


def sign_in(sock: ssl.SSLSocket, data: str):
    info = data.split('\n\n')
    username = info[0]
    password = info[1].encode()
    if username not in user_dict:
        sock.write('$FAI$User does not exist.'.encode())
    elif hashlib.sha256(password).hexdigest() != user_dict[username]:
        sock.write('$FAI$The password is incorrect.'.encode())
    elif username in active_users:
        sock.write('$FAI$User has logged in.'.encode())
    else:
        active_users.add(username)
        addr = sock.getpeername()
        conn_map[addr] = username
        print("User:'%s'%s is online\n" % (username, addr))
        sock.write('$SUC$'.encode())
        msg = "\n$MSG$'%s' entered the chat room.\n" % username
        broadcast_data(sock, msg.encode())


def sign_out(sock: ssl.SSLSocket):
    if sock.getpeername() in conn_map:
        user = conn_map[sock.getpeername()]
        msg = "$MSG$User:'%s' is offline.\n" % user
        broadcast_data(sock, msg.encode())
        print("User:'%s'(%s) is offline\n" % (user, sock.getpeername()))
        active_users.remove(user)
    sock.close()
    conn_list.remove(sock)


def exit_prog(signum, frame):
    conn_list.remove(server_socket)
    server_socket.close()
    for conn in conn_list:
        conn.write('$END$Server is down.\n'.encode())
        conn.close()
    print('\nChat server is down.')
    sys.exit()


if __name__ == "__main__":
    # 创建默认SSL上下文
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY_FILE,
                            password=CERT_PASSWORD)
    context.load_verify_locations(cafile=CA_CERT)
    user_dict = load_users()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SOL_SOCKET: 套接字级别设置
    # SO_REUSEADDR: 地址复用
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', SERVER_PORT))
    # 监听连接,参数为最大未accept的连接数
    server_socket.listen(2)
    conn_list.append(server_socket)
    print("Chat server started on port " + str(SERVER_PORT))
    signal.signal(signal.SIGINT, exit_prog)

    while True:
        # 多路复用返回可读连接列表
        read_sockets, _, _ = select.select(conn_list, [], [])
        for sock in read_sockets:
            if sock == server_socket:
                accept()
            else:
                # addr, port = conn_map[sock]
                data = sock.read(1024)
                if data:
                    data = data.decode()
                    flag = data[:5]
                    msg = data[5:]
                    if flag == '$SUP$':
                        sign_up(sock, msg)
                    elif flag == '$SIN$':
                        sign_in(sock, msg)
                    else:
                        # 转发消息给其它用户
                        broadcast_data(sock, data.encode())
                else:
                    sign_out(sock)
