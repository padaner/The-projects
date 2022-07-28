#include "sm3.h"

static unsigned char message_buffer[64] = { 0 };//存放消息分组
static unsigned int hash[8] = { 0 };//存放哈希值即经过sm3加密的值
static unsigned int T[64] = { 0 };//常量

//十六进制输出
void out_hex()
{
	unsigned int i = 0;
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", hash[i]);
	}
	printf("\n");
}

//循环左移
unsigned int rotate_left(unsigned int a, unsigned int k)
{
	k = k % 32;
	return (a << k) | (a >> (32 - k));
}

//初始化常量
int init_T()
{
	int i = 0;
	for (i = 0; i < 16; i++)
	{
		T[i] = 0x79cc4519;
	}
	for (i = 16; i < 64; i++)
	{
		T[i] = 0x7a879d8a;
	}
	return 1;
}

//布尔函数ff(已定义)
unsigned int ff(int x, int y, int z, int j)
{
	unsigned int ret = 0;
	if (0 <= j && j < 16)
	{
		ret = x ^ y ^ z;
	}
	else if (16 <= j && j < 64)
	{
		ret = (x & y) | (x & z) | (y & z);
	}
	return ret;
}

//布尔函数gg(已定义)
unsigned int gg(int x, int y, int z, int j)
{
	unsigned int ret = 0;
	if (0 <= j && j < 16)
	{
		ret = x ^ y ^ z;
	}
	else if (16 <= j && j < 64)
	{
		ret = (x & y) | ((~x) & z);
	}
	return ret;
}

//用于消息扩展
#define p_0(x) x ^ (rotate_left(x, 9)) ^ (rotate_left(x, 17))
#define p_1(x) x ^ (rotate_left(x, 15)) ^ (rotate_left(x, 23))

//迭代压缩
int cf(unsigned char* arr)
{
	unsigned int W[68];
	unsigned int W_1[64];
	unsigned int j;
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int SS1, SS2, TT1, TT2;

	//消息扩展：
	//将一个512位数据分组划分为16个消息字，并且作为生成的132个消息字的前16个。
	//再用这16个消息字递推生成剩余的116个消息字。
	//在最终得到的132个消息字中，前68个消息字构成数列{W}，
	//后64个消息字构成数列{W_1}
	for (j = 0; j < 16; j++)
	{
		W[j] = arr[j * 4 + 0] << 24 | arr[j * 4 + 1] << 16 | arr[j * 4 + 2] << 8 | arr[j * 4 + 3];
	}
	for (j = 16; j < 68; j++)
	{
		W[j] = p_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6];
	}
	for (j = 0; j < 64; j++)
	{
		W_1[j] = W[j] ^ W[j + 4];
	}

	//讲初值IV放在A、B、C、D、E、F、G、H八个32位变量中
	A = hash[0];
	B = hash[1];
	C = hash[2];
	D = hash[3];
	E = hash[4];
	F = hash[5];
	G = hash[6];
	H = hash[7];

	//压缩函数
	for (j = 0; j < 64; j++)
	{
		SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T[j], j))) & 0xFFFFFFFF, 7);
		SS2 = SS1 ^ (rotate_left(A, 12));
		TT1 = (ff(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
		TT2 = (gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
		D = C;
		C = rotate_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rotate_left(F, 19);
		F = E;
		E = p_0(TT2);

	}

	//得到压缩函数的输出
	hash[0] = (A ^ hash[0]);
	hash[1] = (B ^ hash[1]);
	hash[2] = (C ^ hash[2]);
	hash[3] = (D ^ hash[3]);
	hash[4] = (E ^ hash[4]);
	hash[5] = (F ^ hash[5]);
	hash[6] = (G ^ hash[6]);
	hash[7] = (H ^ hash[7]);
	return 1;
}

//初始iv
void SM3_Init()
{
	init_T();
	hash[0] = 0x7380166f;
	hash[1] = 0x4914b2b9;
	hash[2] = 0x172442d7;
	hash[3] = 0xda8a0600;
	hash[4] = 0xa96f30bc;
	hash[5] = 0x163138aa;
	hash[6] = 0xe38dee4d;
	hash[7] = 0xb0fb0e4e;
}

//消息填充
void block(const char* msg, unsigned int msglen) {
	int i;
	int left = 0;
	unsigned long long total = 0;

	//将消息分组并且迭代压缩
	for (i = 0; i < msglen / 64; i++) {
		memcpy(message_buffer, msg + i * 64, 64);
		cf(message_buffer);
	}

	//计算剩下的字节数。
	//将bit’1’填充至消息末尾，再添加’0’，剩余字节用0补齐。
	total = msglen * 8;//消息长度
	left = msglen % 64;//在分组完之后最后一个有消息的分组消息末尾的位置
	memset(&message_buffer[left], 0, 64 - left);//对分组内消息末尾后的位置设0
	memcpy(message_buffer, msg + i * 64, left);//将经过一系列分组之后最后一段不足64的消息放入分组
	message_buffer[left] = 0x80;//消息末尾后的第一个值赋值0x80，即10000000，实现消息末尾第一个位置填1，之后填0

	//判断剩余字节数是否足够存放代表消息长度的64位比特串。
	//如果足够，则将比特串放入，执行压缩，如果不够，则将剩余部分填0，并将比特串放入下一分组进行压缩。
	if (left <= 55) {
		for (i = 0; i < 8; i++)
			message_buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;//将长度赋值压缩
		cf(message_buffer);
	}
	else {
		cf(message_buffer);
		memset(message_buffer, 0, 64);//在新的分组内操作，先初始设为0
		for (i = 0; i < 8; i++)
			message_buffer[56 + i] = (total >> ((8 - 1 - i) * 8)) & 0xFF;//大端赋值，将长度写入最后一个分组
		cf(message_buffer);
	}

}

//sm3主体
int SM3(const char* msg, unsigned int msglen, unsigned char* out_hash)
{
	SM3_Init();
	block(msg, msglen);
	out_hex();
	return 1;
}

int main(int argc, char* argv[])
{
	unsigned char Hash[32] = { 0 };

	const char* str = "abc";
	//sm3算法加密“abc”之后的结果：66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
	int len;
	len = strlen(str);
	printf("明文：");
	printf("%s\n", str);
	printf("sm3加密结果：\n");
	if (!SM3(str, len, Hash))
		printf("1 false\n");
	return 0;
}

