#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <cstdint>

// SM4算法常量定义
const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// S盒（8位输入 -> 8位输出）
const uint8_t SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// T-Table预计算结果（4个表，每个表256个32位字）
uint32_t T_Table[4][256];

// 初始化T-Table
void InitTTable() {
    for (int i = 0; i < 256; ++i) {
        uint8_t b = SBOX[i];
        uint32_t y = (b << 24) | (b << 16) | (b << 8) | b;

        // 计算T变换结果
        uint32_t t = y ^ ((y << 2) | (y >> 30)) ^ ((y << 10) | (y >> 22)) ^
            ((y << 18) | (y >> 14)) ^ ((y << 24) | (y >> 8));

        // 填充4个T-Table
        T_Table[0][i] = (t << 24) | (t >> 8);
        T_Table[1][i] = (t << 16) | (t >> 16);
        T_Table[2][i] = (t << 8) | (t >> 24);
        T_Table[3][i] = t;
    }
}

// 循环左移
inline uint32_t Rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 使用T-Table优化的T函数
inline uint32_t T(uint32_t x) {
    return T_Table[0][(x >> 24) & 0xFF] ^
        T_Table[1][(x >> 16) & 0xFF] ^
        T_Table[2][(x >> 8) & 0xFF] ^
        T_Table[3][x & 0xFF];
}

// 轮函数F
inline uint32_t F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    return x0 ^ T(x1 ^ x2 ^ x3 ^ rk);
}

// 用于密钥扩展的T'变换
uint32_t T_prime(uint32_t x) {
    uint8_t b[4];
    b[0] = SBOX[(x >> 24) & 0xFF];
    b[1] = SBOX[(x >> 16) & 0xFF];
    b[2] = SBOX[(x >> 8) & 0xFF];
    b[3] = SBOX[x & 0xFF];
    uint32_t y = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    return y ^ Rotl(y, 13) ^ Rotl(y, 23);
}

// 密钥扩展算法
void ExpandKey(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];
    // 初始化中间密钥
    K[0] = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | key[3] ^ FK[0];
    K[1] = ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | key[7] ^ FK[1];
    K[2] = ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key[10] << 8) | key[11] ^ FK[2];
    K[3] = ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)key[14] << 8) | key[15] ^ FK[3];

    // 生成轮密钥
    for (int i = 0; i < 32; ++i) {
        K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

// SM4加密/解密（轮密钥顺序相反即为解密）
void SM4Crypt(const uint8_t input[16], uint8_t output[16], const uint32_t rk[32]) {
    uint32_t X[36];
    // 初始化4个字
    X[0] = ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) | ((uint32_t)input[2] << 8) | input[3];
    X[1] = ((uint32_t)input[4] << 24) | ((uint32_t)input[5] << 16) | ((uint32_t)input[6] << 8) | input[7];
    X[2] = ((uint32_t)input[8] << 24) | ((uint32_t)input[9] << 16) | ((uint32_t)input[10] << 8) | input[11];
    X[3] = ((uint32_t)input[12] << 24) | ((uint32_t)input[13] << 16) | ((uint32_t)input[14] << 8) | input[15];

    // 32轮迭代
    for (int i = 0; i < 32; ++i) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[i]);
    }

    // 反序变换
    uint32_t Y[4] = { X[35], X[34], X[33], X[32] };
    for (int i = 0; i < 4; ++i) {
        output[i * 4] = (Y[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (Y[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (Y[i] >> 8) & 0xFF;
        output[i * 4 + 3] = Y[i] & 0xFF;
    }
}

int main() {
    // 初始化T-Table
    InitTTable();

    // 示例：加密"Hello, SM4!"（需填充为16字节）
    uint8_t key[16] = { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f' };
    uint8_t plaintext[16] = { 'H', 'e', 'l', 'l', 'o', ',', ' ', 'S', 'M', '4', '!', 0x80, 0, 0, 0, 0 }; // PKCS#7填充
    uint8_t ciphertext[16], decrypted[16];

    // 生成轮密钥
    uint32_t rk[32];
    ExpandKey(key, rk);

    // 加密
    SM4Crypt(plaintext, ciphertext, rk);
    std::cout << "密文: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
    }
    std::cout << std::endl;

    // 解密（轮密钥逆序）
    uint32_t rk_decrypt[32];
    for (int i = 0; i < 32; ++i) {
        rk_decrypt[i] = rk[31 - i];
    }
    SM4Crypt(ciphertext, decrypted, rk_decrypt);
    std::cout << "明文: " << decrypted << std::endl;

    return 0;
}
