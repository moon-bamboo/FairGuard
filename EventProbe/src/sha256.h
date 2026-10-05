/*
 * sha256.h —— 极简 SHA-256（无 CRT 依赖）
 *
 * ============================ 为什么需要它 ============================
 *
 * 检测器的日志要能"自证没被事后改过"。做法是【哈希链】：
 *
 *     chain[0] = 初始值
 *     chain[n] = SHA256( chain[n-1] || 第n次告警的记录 )
 *
 * 每次告警都把当前 chain 值写进日志，局末再写一次最终值。
 * 事后想改中间某一行，就必须把那一行之后的所有 chain 值全部重算，
 * 而重算的结果与原日志对不上 —— 改动立刻暴露。
 *
 * ⚠️ 必须说清的局限（用户已知悉并接受）：
 *   - 只能防"事后修改"，防不住"整份重新生成"（算法公开、无密钥）
 *   - 单人日志【无法自证】；要成为有效证据需要多方交叉核对
 *   - 因此只对【事件头部 +0..+12】做哈希 —— Destination 之后
 *     在不同机器上不一样（那是本地状态），整条哈希无法交叉验证
 *
 * ============================ 实现说明 ============================
 *
 * 标准 FIPS 180-4。因为插件用 -nostdlib 编译（没有 memcpy / memset，
 * 也没有 64 位除法运行时支持），这里：
 *   - 不调用任何库函数，字节搬运自己写循环
 *   - 只用 unsigned / unsigned long long（mingw 下前者 32 位、后者 64 位）
 */

#ifndef EVENTPROBE_SHA256_H
#define EVENTPROBE_SHA256_H

typedef struct {
    unsigned           state[8];
    unsigned long long bitlen;
    unsigned char      buf[64];
    unsigned           buflen;
} Sha256Ctx;

#define SHA256_ROTR(x, n)  ( ((x) >> (n)) | ((x) << (32 - (n))) )

static const unsigned SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline void Sha256_Init(Sha256Ctx* c)
{
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bitlen = 0;
    c->buflen = 0;
}

/* 处理一个 64 字节块 */
static inline void Sha256_Block(Sha256Ctx* c, const unsigned char* p)
{
    unsigned w[64];
    unsigned a, b, cc, d, e, f, g, h;
    unsigned t1, t2;
    int i;

    for (i = 0; i < 16; i++)
    {
        w[i] = ((unsigned)p[i * 4] << 24) | ((unsigned)p[i * 4 + 1] << 16) |
               ((unsigned)p[i * 4 + 2] << 8) | (unsigned)p[i * 4 + 3];
    }
    for (i = 16; i < 64; i++)
    {
        unsigned s0 = SHA256_ROTR(w[i - 15], 7) ^ SHA256_ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned s1 = SHA256_ROTR(w[i - 2], 17) ^ SHA256_ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

    for (i = 0; i < 64; i++)
    {
        unsigned S1 = SHA256_ROTR(e, 6) ^ SHA256_ROTR(e, 11) ^ SHA256_ROTR(e, 25);
        unsigned ch = (e & f) ^ ((~e) & g);
        unsigned S0 = SHA256_ROTR(a, 2) ^ SHA256_ROTR(a, 13) ^ SHA256_ROTR(a, 22);
        unsigned mj = (a & b) ^ (a & cc) ^ (b & cc);

        t1 = h + S1 + ch + SHA256_K[i] + w[i];
        t2 = S0 + mj;

        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static inline void Sha256_Update(Sha256Ctx* c, const void* data, unsigned len)
{
    const unsigned char* p = (const unsigned char*)data;
    unsigned i;

    c->bitlen += (unsigned long long)len * 8;

    for (i = 0; i < len; i++)
    {
        c->buf[c->buflen++] = p[i];
        if (c->buflen == 64)
        {
            Sha256_Block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static inline void Sha256_Final(Sha256Ctx* c, unsigned char* out)
{
    unsigned long long bits = c->bitlen;
    unsigned i;

    /* 补 0x80，然后补 0 到 56 mod 64，最后 8 字节大端长度 */
    c->buf[c->buflen++] = 0x80;

    if (c->buflen > 56)
    {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        Sha256_Block(c, c->buf);
        c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;

    for (i = 0; i < 8; i++)
        c->buf[56 + i] = (unsigned char)(bits >> (56 - i * 8));

    Sha256_Block(c, c->buf);
    c->buflen = 0;

    for (i = 0; i < 8; i++)
    {
        out[i * 4]     = (unsigned char)(c->state[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->state[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->state[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c->state[i]);
    }
}

/* 一次性哈希（内部已经 64 字节块处理，buf 是 64 字节对齐无要求） */
static inline void Sha256(const void* data, unsigned len, unsigned char* out)
{
    Sha256Ctx c;
    Sha256_Init(&c);
    Sha256_Update(&c, data, len);
    Sha256_Final(&c, out);
}

#endif /* EVENTPROBE_SHA256_H */
