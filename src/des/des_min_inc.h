
#ifndef  __CRYPTO_MIN_INC_H__
#define  __CRYPTO_MIN_INC_H__
 

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

/* 方法说明:用此方法,执行后des 运算,得到密文,或是明文
   参数说明: in   :  加密时,它是原文,解密时,它是密文
          in_len  :  in 长度,
                     当它是原文时: 这个数可以为任意长度,
                     因des 内部,是以64bit为单位运算,
					 如输入9byte,则加密后的长度为16byte,
					 如输入7byte,则加密后的长度为8byte,

                     当它是密文长度时: 这个数必须是原文加密
					 时返回的长度

            out  :   接收密文或是明文的buf 

          out_len:   接收密文或是明文的buf 长度,
			         加密: out_len >= ((原文长度 +7)-(原文长度 +7)%8
					 例: in_len = 9, out_len 必须>=16 ,否则返回 0;
                     解密: out_len >= 密文长度

            key  :   8byte 任意输入串,做为加密与解密的密码,des算法中,
			         加密与解密用的是用一个密码

            enc  :   DES_ENCRYPT  加密, DES_DECRYPT 解密;见宏定义
       返回结果  : int 成功:返回解密或是加密后的大于0的输出长度, 失败 返回 0;
 */
int des_min_do(const unsigned char *in,int in_len, unsigned char *out, int out_len, const unsigned char *key, int enc);

#endif
