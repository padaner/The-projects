#pragma once
#ifndef SM3_H
#define SM3_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void out_hex();//将加密结果转换为16进制形式输出
int SM3(const char* msg, unsigned int msglen, unsigned char* out_hash);//sm3加密函数

#endif
