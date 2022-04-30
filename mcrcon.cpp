#include <winsock2.h>
#include <windows.h>
#include <cstddef>
#include <winnt.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <ws2tcpip.h>

//定义结构体
struct rconpacket
{
	int size;
	int id;
	int cmd;
	char data[4096];
} rcon_packet;

// 函数声明和变量定义
// 网络相关函数
#define VERSION "0.1.0"
#define IN_NAME "mcrcon-with-cpp"
#define VER_STR IN_NAME " " VERSION " (built: " __DATE__ " " __TIME__ ")"
typedef unsigned char uint8_t;
rconpacket *net_recv_packet(int sd);
void net_init_WSA(void);
void net_close(int sd);
int net_connect(const char *host, const char *port);
int net_send(int sd, const uint8_t *buffer, size_t size);
int net_send_packet(int sd, rconpacket *packet);
int net_clean_incoming(int sd, int size);
// Misc stuff
void usage(void);
int get_line(char *buffer, int len);
int run_terminal_mode(int sock);
int run_commands(int argc, char *argv[]);
// Rcon协议相关函数
rconpacket *packet_build(int id, int cmd, char *s1);
void packet_print(rconpacket *packet);
int rcon_auth(int sock, char *passwd);
int rcon_command(int sock, char *command);
// 静态全局变量定义
static int global_raw_output = 0;
static int global_silent_mode = 0;
static int global_disable_colors = 0;
static int global_connection_alive = 1;
static int global_rsock;
static int global_wait_seconds = 0;
// Windows控制台字体颜色
HANDLE console_handle;

// 函数定义
void exit_proc(void)
{
	if (global_rsock != -1)
	{
		net_close(global_rsock);
	}
}

void sighandler(int sig)
{
	if (sig == SIGINT)
	{
		putchar('\n');
	}
	global_connection_alive = 0;
}

unsigned int mcrcon_parse_seconds(char *str)
{
	char *end;
	long result = strtol(str, &end, 10);
	if (errno != 0)
	{
		fprintf(stderr, "-w 无效数值\n错误%d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (end == str)
	{
		fprintf(stderr, "-w 无效数值（输入不是数字）\n");
		exit(EXIT_FAILURE);
	}
	if (result <= 0 || result > 600)
	{
		fprintf(stderr, "-w 无效数值。\n取值范围为 1 - %d (seconds).\n", 600);
		exit(EXIT_FAILURE);
	}
	return (unsigned int)result;
}

int main(int argc, char *argv[])
{
	int terminal_mode = 0;
	int exit_code = EXIT_SUCCESS;
	opterr = 1;
	int opt;
	char *host = getenv("MCRCON_HOST");
	char *pass = getenv("MCRCON_PASS");
	char *port = getenv("MCRCON_PORT");
	if (!port)
		port = (char *)"25575";
	if (!host)
		host = (char *)"localhost";
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	if (argc < 1 && pass == NULL)
	{
		usage();
	}
	while ((opt = getopt(argc, argv, "vrtcshw:H:p:P:")) != -1)
	{
		switch (opt)
		{
		case 'H':
			host = optarg;
			break;
		case 'P':
			port = optarg;
			break;
		case 'p':
			pass = optarg;
			break;
		case 'c':
			global_disable_colors = 1;
			break;
		case 's':
			global_silent_mode = 1;
			break;
		case 'i':
			break;
		case 't':
			terminal_mode = 1;
			break;
		case 'r':
			global_raw_output = 1;
			break;
		case 'w':
			global_wait_seconds = mcrcon_parse_seconds(optarg);
			break;
		case 'v':
			puts(VER_STR " - https://github.com/half-nothing/mcrcon-with-cpp");
			puts("Refactoring from:\n\thttps://github.com/Tiiffi/mcrcon/issues/");
			exit(EXIT_SUCCESS);
		case 'h':
			usage();
			break;
		case '?':
		default:
			puts("使用'mcrcon -h'获得帮助");
			exit(EXIT_FAILURE);
		}
	}
	if (pass == NULL)
	{
		puts("错误：没有提供密码(-p password)\n使用'mcrcon -h'获得帮助.");
		return 0;
	}
	if (optind == argc && terminal_mode == 0)
	{
		terminal_mode = 1;
	}
	atexit(&exit_proc);
	signal(SIGABRT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGINT, &sighandler);
	net_init_WSA();
	console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (console_handle == INVALID_HANDLE_VALUE)
	{
		console_handle = NULL;
	}
	global_rsock = net_connect(host, port);
	if (rcon_auth(global_rsock, pass))
	{
		if (terminal_mode)
		{
			run_terminal_mode(global_rsock);
		}
		else
		{
			exit_code = run_commands(argc, argv);
		}
	}
	else 
	{
		fprintf(stdout, "身份验证失败\n");
		exit_code = EXIT_FAILURE;
	}
	exit(exit_code);
}

void usage(void)
{
	puts(
		"帮助: " IN_NAME " [OPTIONS] [COMMANDS]\n\n"
		"向Minecraft发送远程命令\n\n"
		"Options:\n"
		"  -H\t\t服务器名称(默认:localhost)\n"
		"  -P\t\tRcon端口(默认: 25575)\n"
		"  -p\t\tRcon密码\n"
		"  -t\t\t终端模式\n"
		"  -s\t\t静默模式\n"
		"  -c\t\t关闭颜色\n"
		"  -r\t\t输出原始数据包\n"
		"  -w\t\t在每个命令之间等待指定的时间(秒)(1 - 600秒)\n"
		"  -h\t\t打印帮助\n"
		"  -v\t\t版本信息\n\n"
		"服务器地址、端口和密码可以通过以下环境变量设置:\n"
		"  MCRCON_HOST\n"
		"  MCRCON_PORT\n"
		"  MCRCON_PASS\n");
	puts(
		"- 如果没有给出命令，mccrcon将以终端模式启动\n"
		"- 命令行选项将覆盖环境变量\n"
		"- 带有空格的Rcon命令必须用引号括起来\n");
	puts("例子:\n\t" IN_NAME " -H my.minecraft.server -p password -w 5 \"say 服务器重启！\" save-all stop\n");
	puts("按“enter”退出。");
	getchar();
	exit(EXIT_SUCCESS);
}

void net_init_WSA(void)
{
	WSADATA wsadata;
	WORD version = MAKEWORD(2, 2);
	int err = WSAStartup(version, &wsadata);
	if (err != 0)
	{
		fprintf(stderr, "WSAStartup失效。错误: %d。\n", err);
		exit(EXIT_FAILURE);
	}
}

void net_close(int sd)
{
	closesocket(sd);
	WSACleanup();
}

int net_connect(const char *host, const char *port)
{
	int sd;
	struct addrinfo hints;
	struct addrinfo *server_info, *p;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	net_init_WSA();
	int ret = getaddrinfo(host, port, &hints, &server_info);
	if (ret != 0)
	{
		fprintf(stderr, "名称解析失败。\n");
		fprintf(stderr, "错误 %d: %s", ret, gai_strerror(ret));
		exit(EXIT_FAILURE);
	}
	for (p = server_info; p != NULL; p = p->ai_next)
	{
		sd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sd == -1)
		{
			continue;
		}
		ret = connect(sd, p->ai_addr, p->ai_addrlen);
		if (ret == -1)
		{
			net_close(sd);
			continue;
		}
		break;
	}
	if (p == NULL)
	{
		fprintf(stderr, "连接失败\n");
		freeaddrinfo(server_info);
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(server_info);
	return sd;
}

int net_send(int sd, const uint8_t *buff, size_t size)
{
	size_t sent = 0;
	size_t left = size;
	while (sent < size)
	{
		int result = send(sd, (const char *)buff + sent, left, 0);
		if (result == -1)
		{
			return -1;
		}
		sent += result;
		left -= sent;
	}
	return 0;
}

int net_send_packet(int sd, rconpacket *packet)
{
	int len;
	int total = 0;
	int bytesleft;
	int ret = -1;
	bytesleft = len = packet->size + sizeof(int);
	while (total < len)
	{
		ret = send(sd, (char *)packet + total, bytesleft, 0);
		if (ret == -1)
		{
			break;
		}
		total += ret;
		bytesleft -= ret;
	}
	return ret == -1 ? -1 : 1;
}

rconpacket *net_recv_packet(int sd)
{
	int psize;
	static rconpacket packet = {0, 0, 0, {0x00}};
	int ret = recv(sd, (char *)&psize, sizeof(int), 0);
	if (ret == 0)
	{
		fprintf(stderr, "连接丢失\n");
		global_connection_alive = 0;
		return NULL;
	}
	if (ret != sizeof(int))
	{
		fprintf(stderr, "错误：无效的包大小(%d)。\n", ret);
		global_connection_alive = 0;
		return NULL;
	}
	if (psize < 10 || psize > 4096)
	{
		fprintf(stderr, "错误：无效的包大小。(%d)包大小应当大于10小于%d.\n", psize, 4096);
		if (psize > 4096 || psize < 0)
			psize = 4096;
		net_clean_incoming(sd, psize);
		return NULL;
	}
	packet.size = psize;
	int received = 0;
	while (received < psize)
	{
		ret = recv(sd, (char *)&packet + sizeof(int) + received, psize - received, 0);
		if (ret == 0)
		{ 
			fprintf(stderr, "连接丢失\n");
			global_connection_alive = 0;
			return NULL;
		}
		received += ret;
	}
	return &packet;
}

int net_clean_incoming(int sd, int size)
{
	char tmp[size];
	int ret = recv(sd, tmp, size, 0);
	if (ret == 0)
	{
		fprintf(stderr, "连接丢失\n");
		global_connection_alive = 0;
	}
	return ret;
}

void print_color(int color)
{
	if (color >= 0x61 && color <= 0x66)
	{
		color -= 0x57;
	}
	else if (color >= 0x30 && color <= 0x39)
	{
		color -= 0x30;
	}
	else if (color == 0x6e)
	{
		color = 16;
	}
	else
	{
		return;
	}
	SetConsoleTextAttribute(console_handle, color);
}

void packet_print(rconpacket *packet)
{
	if (global_raw_output == 1)
	{
		for (int i = 0; packet->data[i] != 0; ++i)
		{
			putchar(packet->data[i]);
		}
		return;
	}
	int i;
	int def_color = 0;
	CONSOLE_SCREEN_BUFFER_INFO console_info;
	if (GetConsoleScreenBufferInfo(console_handle, &console_info) != 0)
	{
		def_color = console_info.wAttributes + 0x30;
	}
	else
	{
		def_color = 0x37;
	}
	if (global_disable_colors == 0)
	{
		for (i = 0; (unsigned char)packet->data[i] != 0; ++i)
		{
			if (packet->data[i] == 0x0A)
			{
				print_color(def_color);
			}
			else if ((unsigned char)packet->data[i] == 0xc2 && (unsigned char)packet->data[i + 1] == 0xa7)
			{
				print_color(packet->data[i += 2]);
				continue;
			}
			putchar(packet->data[i]);
		}
		print_color(def_color); 
	}
	else
	{
		for (i = 0; (unsigned char)packet->data[i] != 0; ++i)
		{
			if ((unsigned char)packet->data[i] == 0xc2 && (unsigned char)packet->data[i + 1] == 0xa7)
			{
				i += 2;
				continue;
			}
			putchar(packet->data[i]);
		}
	}
	if (packet->data[i - 1] != 10 && packet->data[i - 1] != 13)
	{
		putchar('\n');
	}
}

rconpacket *packet_build(int id, int cmd, char *s1)
{
	static rconpacket packet = {0, 0, 0, {0x00}};
	int len = strlen(s1);
	if (len >= 4096)
	{
		fprintf(stderr, "警告：命令过长(%d)。命令的最大长度为: %d.\n", len, 4096 - 1);
		return NULL;
	}
	packet.size = sizeof(int) * 2 + len + 2;
	packet.id = id;
	packet.cmd = cmd;
	strncpy(packet.data, s1, 4096 - 1);
	return &packet;
}

int rcon_auth(int sock, char *passwd)
{
	int ret;
	rconpacket *packet = packet_build(0xBADC0DE, 3, passwd);
	if (packet == NULL)
	{
		return 0;
	}
	ret = net_send_packet(sock, packet);
	if (!ret)
	{
		return 0;
	}
	packet = net_recv_packet(sock);
	if (packet == NULL)
	{
		return 0;
	}
	return packet->id == -1 ? 0 : 1;
}

int rcon_command(int sock, char *command)
{
	rconpacket *packet = packet_build(0xBADC0DE, 2, command);
	if (packet == NULL)
	{
		global_connection_alive = 0;
		return 0;
	}
	net_send_packet(sock, packet);
	packet = net_recv_packet(sock);
	if (packet == NULL)
	{
		return 0;
	}
	if (packet->id != 0xBADC0DE)
	{
		return 0;
	}
	if (!global_silent_mode)
	{
		if (packet->size > 10)
			packet_print(packet);
	}
	return 1;
}

int run_commands(int argc, char *argv[])
{
	int i = optind;
	for (;;)
	{
		if (!rcon_command(global_rsock, argv[i]))
		{
			return EXIT_FAILURE;
		}
		if (++i >= argc)
		{
			return EXIT_SUCCESS;
		}
		if (global_wait_seconds > 0)
		{
			Sleep(global_wait_seconds * 1000);
		}
	}
}

int run_terminal_mode(int sock)
{
	int ret = 0;
	char command[4096] = {0x00};
	puts("登录成功\n输入 'Q' 或按下Ctrl-D/Ctrl-C断开连接");
	while (global_connection_alive)
	{
		putchar('>');
		int len = get_line(command, 4096);
		if (len < 1)
		{
			continue;
		}
		if (strcasecmp(command, "Q") == 0)
		{
			break;
		}
		if (len > 0 && global_connection_alive)
		{
			ret += rcon_command(sock, command);
		}
		if (strcasecmp(command, "stop") == 0)
		{
			break;
		}
	}
	return ret;
}

int get_line(char *buffer, int bsize)
{
	char *ret = fgets(buffer, bsize, stdin);
	if (ret == NULL)
	{
		if (ferror(stdin))
		{
			fprintf(stderr, "错误 %d: %s\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		putchar('\n');
		exit(EXIT_SUCCESS);
	}
	buffer[strcspn(buffer, "\r\n")] = '\0';
	int len = strlen(buffer);
	if (len == bsize - 1)
	{
		int ch;
		while ((ch = getchar()) != '\n' && ch != EOF)
			;
	}
	return len;
}