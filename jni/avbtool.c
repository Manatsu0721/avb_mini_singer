/*
 * avb_autosign — 静态链接的 AVB 2.0 add_hash_footer 实现
 *
 * 用法: avb_autosign <partition_name> <partition_size> <image_path>
 *
 * 功能等价于:
 *   avbtool.py add_hash_footer \
 *     --partition_name <name> \
 *     --image <path> \
 *     --algorithm SHA256_RSA4096 \
 *     --key <embedded>
 *     --partition_size <size>
 * 
 * 输出直接覆写原镜像文件
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <unistd.h>
#include <openssl/sha.h>

/* ========== 1. 嵌入的私钥 ========== */
extern char _binary_subaru_key_pem_start[];
extern char _binary_subaru_key_pem_end[];

/* ========== 2. AVB 常数 ========== */
#define AVB_FOOTER_MAGIC      "AVBf"
#define AVB_FOOTER_MAGIC_LEN  4
#define AVB_MAGIC             "AVB0"
#define AVB_MAGIC_LEN         4

/* 算法类型 (与 avb_crypto.h 保持一致) */
#define AVB_ALG_TYPE_SHA256_RSA4096  2

/* 算法参数 */
#define HASH_NUM_BYTES       32   /* SHA256 */
#define SIG_NUM_BYTES        512  /* RSA4096 */
#define PUBKEY_NUM_BYTES     1032 /* 8 + 2*4096/8 */

/* AVB 对齐约束 */
#define AVB_ALIGNMENT        64

/* 各结构 reserved 大小 (与 avbtool.py FORMAT_STRING 一致) */
#define FOOTER_RESERVED      28
#define VBMETA_HEADER_RESERVED  80
#define HASH_DESC_RESERVED   60

/* PKCS#1 v1.5 padding for SHA256_RSA4096
 *   0x00 0x01 [458 x 0xff] 0x00 [ASN.1 19 bytes] [digest 32 bytes]
 *   总长 = 512 bytes
 *   ASN.1 = 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
 */
static const uint8_t PKCS1_ASN1_SHA256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

static void build_pkcs1_padding(const uint8_t *digest, uint8_t *out) {
    out[0] = 0x00;
    out[1] = 0x01;
    memset(out + 2, 0xff, 458);
    out[460] = 0x00;
    memcpy(out + 461, PKCS1_ASN1_SHA256, 19);
    memcpy(out + 480, digest, 32);
}

/* ========== 3. AVB 结构体定义 ========== */

/* --- AvbFooter (64 bytes) --- */
typedef struct __attribute__((packed)) {
    uint8_t  magic[AVB_FOOTER_MAGIC_LEN];
    uint32_t version_major;
    uint32_t version_minor;
    uint64_t original_image_size;
    uint64_t vbmeta_offset;
    uint64_t vbmeta_size;
    uint8_t  reserved[FOOTER_RESERVED];
} AvbFooter;

/* --- AvbVBMetaImageHeader (256 bytes) --- */
typedef struct __attribute__((packed)) {
    uint8_t  magic[AVB_MAGIC_LEN];
    uint32_t required_libavb_version_major;
    uint32_t required_libavb_version_minor;
    uint64_t authentication_data_block_size;
    uint64_t auxiliary_data_block_size;
    uint32_t algorithm_type;
    uint64_t hash_offset;
    uint64_t hash_size;
    uint64_t signature_offset;
    uint64_t signature_size;
    uint64_t public_key_offset;
    uint64_t public_key_size;
    uint64_t public_key_metadata_offset;
    uint64_t public_key_metadata_size;
    uint64_t descriptors_offset;
    uint64_t descriptors_size;
    uint64_t rollback_index;
    uint32_t flags;
    uint32_t rollback_index_location;
    char     release_string[48];
    uint8_t  reserved[VBMETA_HEADER_RESERVED];
} AvbVBMetaHeader;

/* --- AvbHashDescriptor (固定部分 132 bytes) --- */
/* 序列化: [tag(8)][nbf(8)][image_size(8)][hash_algo(32)]
 *         [name_len(4)][salt_len(4)][digest_len(4)][flags(4)]
 *         [reserved(60)]
 *         [name][salt][digest][padding(to 8)]
 */
typedef struct __attribute__((packed)) {
    uint64_t tag;
    uint64_t num_bytes_following;
    uint64_t image_size;
    char     hash_algorithm[32];
    uint32_t partition_name_len;
    uint32_t salt_len;
    uint32_t digest_len;
    uint32_t flags;
    uint8_t  reserved[HASH_DESC_RESERVED];
} AvbHashDescriptorFixed;

/* ========== 4. 辅助函数 ========== */

static uint64_t round_up(uint64_t v, uint64_t align) {
    return (v + align - 1) & ~(align - 1);
}

static void print_openssl_error(void) {
    ERR_print_errors_fp(stderr);
}

static EVP_PKEY* load_embedded_key(void) {
    long key_len = _binary_subaru_key_pem_end - _binary_subaru_key_pem_start;
    BIO *bio = BIO_new_mem_buf(_binary_subaru_key_pem_start, key_len);
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

static uint8_t* read_file(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("fopen"); return NULL; }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size < 0) { perror("ftell"); fclose(fp); return NULL; }
    rewind(fp);
    uint8_t *buf = malloc(size);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, size, fp) != (size_t)size) {
        perror("fread"); free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *out_size = (size_t)size;
    return buf;
}

static int write_file_at(FILE *fp, uint64_t offset,
                         const uint8_t *data, size_t size)
{
    if (fseeko(fp, offset, SEEK_SET) != 0) {
        perror("fseeko"); return -1;
    }
    if (fwrite(data, 1, size, fp) != size) {
        perror("fwrite"); return -1;
    }
    return 0;
}

/* 扩展文件到指定大小，用零填充 */
static int extend_file(FILE *fp, uint64_t new_size) {
    if (fseeko(fp, 0, SEEK_END) != 0) return -1;
    uint64_t cur = ftello(fp);
    if (cur >= new_size) return 0;
    /* 一次 write 一个零字节，然后 ftruncate 到目标大小 */
    uint8_t zero = 0;
    if (fwrite(&zero, 1, 1, fp) != 1) return -1;
    fflush(fp);
    if (ftruncate(fileno(fp), new_size) != 0) {
        perror("ftruncate"); return -1;
    }
    return 0;
}

/* ========== 5. AVB RSA 公开密钥编码 ========== */

/*
 * AvbRSAPublicKeyHeader (8 bytes) + modulus (key_bits/8) + rrmodn (key_bits/8)
 * struct __attribute__((packed)) {
 *     uint32_t key_num_bits;
 *     uint32_t n0inv;     // -1/n[0] mod 2^32
 *     uint8_t  modulus[key_num_bits/8];
 *     uint8_t  rrmodn[key_num_bits/8];
 * };
 */
static int encode_avb_pubkey(EVP_PKEY *pkey,
                             uint8_t *out, size_t *out_len)
{
    /* 从 EVP_PKEY 获取 RSA 参数 */
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        fprintf(stderr, "Not an RSA key\n");
        return -1;
    }

    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);

    /* 验证 e == 65537 */
    if (BN_get_word(e) != 65537) {
        fprintf(stderr, "Only exponent 65537 supported\n");
        RSA_free(rsa);
        return -1;
    }

    int key_bits = BN_num_bits(n);
    /* 向上取整到 2 的幂 */
    int key_bits_rounded = 1;
    while (key_bits_rounded < key_bits) key_bits_rounded <<= 1;

    if (key_bits_rounded != 4096) {
        fprintf(stderr, "Key bits=%d, expected 4096\n", key_bits_rounded);
        RSA_free(rsa);
        return -1;
    }

    int key_bytes = key_bits_rounded / 8;

    /* 计算 n0inv = -1/n[0] mod 2^32 (Montgomery inverse of low word)
     * 直接从 bn2bin 提取 modulus 的低 32 位 (大端表示的最后 4 字节) */
    uint8_t n_bin[512];
    int n_bytes = BN_bn2bin(n, n_bin);
    uint32_t n0 = ((uint32_t)n_bin[n_bytes-4] << 24) |
                  ((uint32_t)n_bin[n_bytes-3] << 16) |
                  ((uint32_t)n_bin[n_bytes-2] << 8)  |
                  ((uint32_t)n_bin[n_bytes-1]);
    /* Newton iteration for modular inverse: inv = inv * (2 - n0 * inv) (mod 2^32)
     * n0 is always odd for RSA, so inverse exists */
    uint32_t inv = 1U;
    inv = inv * (2 - n0 * inv);
    inv = inv * (2 - n0 * inv);
    inv = inv * (2 - n0 * inv);
    inv = inv * (2 - n0 * inv);
    inv = inv * (2 - n0 * inv); /* 5 iterations suffice for 32 bits */
    uint32_t n0inv = 0U - inv; /* n0inv = -n0^(-1) mod 2^32 */

    /* 计算 rr = r^2 mod N, 其中 r = 2^key_bits */
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *rr = BN_new();
    BIGNUM *r = BN_new();
    BN_set_bit(r, key_bits_rounded);
    BN_mod_sqr(rr, r, n, bn_ctx);

    /* 提取 modulus 和 rr 为大端字节数组 */
    uint8_t *modulus_buf = malloc(key_bytes);
    uint8_t *rr_buf = malloc(key_bytes);
    if (!modulus_buf || !rr_buf) {
        free(modulus_buf); free(rr_buf);
        BN_free(rr); BN_free(r); BN_CTX_free(bn_ctx);
        RSA_free(rsa);
        return -1;
    }
    memset(modulus_buf, 0, key_bytes);
    memset(rr_buf, 0, key_bytes);
    BN_bn2bin(n, modulus_buf + key_bytes - BN_num_bytes(n));
    BN_bn2bin(rr, rr_buf + key_bytes - BN_num_bytes(rr));

    /* 写入输出: [key_num_bits(4)][n0inv(4)][modulus(key_bytes)][rr(key_bytes)] */
    uint32_t key_num_bits_be = __builtin_bswap32(key_bits_rounded);
    uint32_t n0inv_be = __builtin_bswap32(n0inv);
    memcpy(out, &key_num_bits_be, 4);
    memcpy(out + 4, &n0inv_be, 4);
    memcpy(out + 8, modulus_buf, key_bytes);
    memcpy(out + 8 + key_bytes, rr_buf, key_bytes);
    *out_len = 8 + 2 * key_bytes;

    free(modulus_buf);
    free(rr_buf);
    BN_free(rr);
    BN_free(r);
    BN_CTX_free(bn_ctx);
    RSA_free(rsa);
    return 0;
}

/* ========== 大端序列化辅助 (AVB 磁盘格式为大端) ========== */

static inline void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline void put_u64_be(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

/* 将 AvbVBMetaHeader 序列化为大端字节数组 (256 bytes) */
static void encode_header_be(const AvbVBMetaHeader *hdr, uint8_t *out) {
    int o = 0;
    memcpy(out + o, hdr->magic, 4); o += 4;
    put_u32_be(out + o, hdr->required_libavb_version_major); o += 4;
    put_u32_be(out + o, hdr->required_libavb_version_minor); o += 4;
    put_u64_be(out + o, hdr->authentication_data_block_size); o += 8;
    put_u64_be(out + o, hdr->auxiliary_data_block_size); o += 8;
    put_u32_be(out + o, hdr->algorithm_type); o += 4;
    put_u64_be(out + o, hdr->hash_offset); o += 8;
    put_u64_be(out + o, hdr->hash_size); o += 8;
    put_u64_be(out + o, hdr->signature_offset); o += 8;
    put_u64_be(out + o, hdr->signature_size); o += 8;
    put_u64_be(out + o, hdr->public_key_offset); o += 8;
    put_u64_be(out + o, hdr->public_key_size); o += 8;
    put_u64_be(out + o, hdr->public_key_metadata_offset); o += 8;
    put_u64_be(out + o, hdr->public_key_metadata_size); o += 8;
    put_u64_be(out + o, hdr->descriptors_offset); o += 8;
    put_u64_be(out + o, hdr->descriptors_size); o += 8;
    put_u64_be(out + o, hdr->rollback_index); o += 8;
    put_u32_be(out + o, hdr->flags); o += 4;
    put_u32_be(out + o, hdr->rollback_index_location); o += 4;
    memcpy(out + o, hdr->release_string, 48); o += 48;
    memset(out + o, 0, 80); /* reserved */
}

/* 将 AvbFooter 序列化为大端字节数组 (64 bytes) */
static void encode_footer_be(const AvbFooter *footer, uint8_t *out) {
    int o = 0;
    memcpy(out + o, footer->magic, 4); o += 4;
    put_u32_be(out + o, footer->version_major); o += 4;
    put_u32_be(out + o, footer->version_minor); o += 4;
    put_u64_be(out + o, footer->original_image_size); o += 8;
    put_u64_be(out + o, footer->vbmeta_offset); o += 8;
    put_u64_be(out + o, footer->vbmeta_size); o += 8;
    memset(out + o, 0, FOOTER_RESERVED); /* reserved */
}

/* ========== 6. AVB 签名 ========== */

/*
 * avbtool.py 的签名方式:
 *   digest = SHA256(data_to_sign)
 *   padded_block = PKCS1_padding + digest
 *   signature = RSA_private_encrypt(padded_block, RSA_NO_PADDING)
 *   等价于: openssl rsautl -sign -raw -inkey key.pem
 */
static int avb_sign(EVP_PKEY *pkey,
                    const uint8_t *data_to_sign, size_t data_len,
                    uint8_t *signature, size_t *sig_len)
{
    /* 1. SHA256(data_to_sign) */
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data_to_sign, data_len, digest);

    /* 2. 构建 PKCS#1 v1.5 填充块
     *    布局: [0x00][0x01][458 x 0xff][0x00][19 ASN.1 header][32 digest]
     *    total = 512 bytes
     */
    uint8_t padded[SIG_NUM_BYTES];
    build_pkcs1_padding(digest, padded);

    /* 3. Raw RSA signing (RSA_NO_PADDING) */
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        fprintf(stderr, "Failed to get RSA key\n");
        return -1;
    }

    unsigned char sig_buf[SIG_NUM_BYTES];
    int ret = RSA_private_encrypt(SIG_NUM_BYTES, padded, sig_buf,
                                  rsa, RSA_NO_PADDING);
    RSA_free(rsa);

    if (ret != SIG_NUM_BYTES) {
        fprintf(stderr, "RSA_private_encrypt failed (ret=%d): ", ret);
        print_openssl_error();
        return -1;
    }

    memcpy(signature, sig_buf, SIG_NUM_BYTES);
    *sig_len = SIG_NUM_BYTES;
    return 0;
}

/* ========== 7. Hash Descriptor 编码 ========== */

static size_t encode_hash_descriptor(const char *partition_name,
                                     size_t image_size,
                                     const uint8_t *salt, size_t salt_len,
                                     const uint8_t *digest, size_t digest_len,
                                     uint8_t *out, size_t out_cap)
{
    size_t name_len = strlen(partition_name);
    /* 固定部分 132 bytes (大端序列化) */
    size_t fixed_size = 132;
    size_t var_size = name_len + salt_len + digest_len;
    size_t total = fixed_size + var_size;
    size_t padded_total = round_up(total, 8);
    size_t padding = padded_total - total;

    if (out_cap < padded_total) {
        fprintf(stderr, "Hash descriptor buffer too small\n");
        return 0;
    }

    int o = 0;
    put_u64_be(out + o, 2); o += 8;  /* tag = AVB_DESCRIPTOR_TAG_HASH */
    put_u64_be(out + o, padded_total - 16); o += 8;  /* num_bytes_following */
    put_u64_be(out + o, image_size); o += 8;
    memset(out + o, 0, 32);
    strcpy((char*)out + o, "sha256"); o += 32;
    put_u32_be(out + o, (uint32_t)name_len); o += 4;
    put_u32_be(out + o, (uint32_t)salt_len); o += 4;
    put_u32_be(out + o, (uint32_t)digest_len); o += 4;
    put_u32_be(out + o, 0); o += 4; /* flags = 0 */
    memset(out + o, 0, 60); o += 60; /* reserved */

    /* 变长部分 */
    memcpy(out + o, partition_name, name_len); o += name_len;
    memcpy(out + o, salt, salt_len); o += salt_len;
    memcpy(out + o, digest, digest_len); o += digest_len;
    memset(out + o, 0, padding);

    return padded_total;
}

/* ========== generate_vbmeta: 完整 VBMeta 生成 ========== */

static uint8_t* generate_vbmeta(const char *partition_name,
                                const uint8_t *image_data, size_t image_size,
                                EVP_PKEY *pkey,
                                size_t *out_size)
{
    /* 1. 生成随机盐 */
    uint8_t salt[32];
    {
        FILE *ur = fopen("/dev/urandom", "rb");
        if (!ur) {
            memset(salt, 0, 32);
        } else {
            if (fread(salt, 1, 32, ur) != 32) memset(salt, 0, 32);
            fclose(ur);
        }
    }

    /* 2. 计算图像 digest = SHA256(salt + image_data) */
    uint8_t digest[SHA256_DIGEST_LENGTH];
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, salt, 32);
        SHA256_Update(&ctx, image_data, image_size);
        SHA256_Final(digest, &ctx);
    }

    /* 3. 编码 hash descriptor */
    size_t desc_buf_size = 1024;
    uint8_t *desc_buf = malloc(desc_buf_size);
    if (!desc_buf) return NULL;

    size_t desc_size = encode_hash_descriptor(
        partition_name, image_size,
        salt, 32, digest, SHA256_DIGEST_LENGTH,
        desc_buf, desc_buf_size);

    if (desc_size == 0) {
        free(desc_buf);
        return NULL;
    }

    /* 4. 编码公开密钥 */
    uint8_t pubkey_buf[PUBKEY_NUM_BYTES];
    size_t pubkey_size = 0;
    if (encode_avb_pubkey(pkey, pubkey_buf, &pubkey_size) != 0) {
        free(desc_buf);
        return NULL;
    }

    /* 5. 构建 Auxiliary Data Block
     *    布局: descriptors at offset 0, public key after */
    size_t aux_data_size = desc_size + pubkey_size;
    size_t aux_block_size = round_up(aux_data_size, AVB_ALIGNMENT);
    uint8_t *aux_block = calloc(1, aux_block_size);
    if (!aux_block) { free(desc_buf); return NULL; }
    memcpy(aux_block, desc_buf, desc_size);
    memcpy(aux_block + desc_size, pubkey_buf, pubkey_size);
    free(desc_buf);

    /* 6. 构建 VBMeta Header */
    AvbVBMetaHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, AVB_MAGIC, AVB_MAGIC_LEN);
    hdr.required_libavb_version_major = 1;
    hdr.required_libavb_version_minor = 0;
    hdr.algorithm_type = AVB_ALG_TYPE_SHA256_RSA4096;
    hdr.rollback_index = 0;
    hdr.flags = 0;
    hdr.rollback_index_location = 0;
    strcpy(hdr.release_string, "avb_autosign 1.0");

    /* Aux block offsets */
    hdr.auxiliary_data_block_size = aux_block_size;
    hdr.descriptors_offset = 0;
    hdr.descriptors_size = desc_size;
    hdr.public_key_offset = desc_size;
    hdr.public_key_size = pubkey_size;
    hdr.public_key_metadata_offset = desc_size + pubkey_size;
    hdr.public_key_metadata_size = 0;

    /* Auth block: hash + signature */
    size_t auth_data_size = HASH_NUM_BYTES + SIG_NUM_BYTES;
    size_t auth_block_size = round_up(auth_data_size, AVB_ALIGNMENT);
    hdr.authentication_data_block_size = auth_block_size;
    hdr.hash_offset = 0;
    hdr.hash_size = HASH_NUM_BYTES;
    hdr.signature_offset = HASH_NUM_BYTES;
    hdr.signature_size = SIG_NUM_BYTES;

    /* 7. 序列化 header (大端) */
    uint8_t hdr_blob[256];
    encode_header_be(&hdr, hdr_blob);

    /* 8. 计算 hash = SHA256(header_blob + aux_block) */
    size_t hash_input_size = 256 + aux_block_size;
    uint8_t *hash_input = malloc(hash_input_size);
    if (!hash_input) { free(aux_block); return NULL; }
    memcpy(hash_input, hdr_blob, 256);
    memcpy(hash_input + 256, aux_block, aux_block_size);

    uint8_t auth_hash[SHA256_DIGEST_LENGTH];
    SHA256(hash_input, hash_input_size, auth_hash);

    /* 9. 签名 hash */
    uint8_t signature[SIG_NUM_BYTES];
    size_t sig_len = 0;
    if (avb_sign(pkey, hash_input, hash_input_size,
                 signature, &sig_len) != 0) {
        free(aux_block);
        free(hash_input);
        return NULL;
    }
    free(hash_input);

    /* 10. 构建 Authentication Data Block */
    uint8_t *auth_block = calloc(1, auth_block_size);
    if (!auth_block) { free(aux_block); return NULL; }
    memcpy(auth_block, auth_hash, HASH_NUM_BYTES);
    memcpy(auth_block + HASH_NUM_BYTES, signature, SIG_NUM_BYTES);

    /* 11. 组装 VBMeta Blob: header(256) + auth_block + aux_block */
    size_t total = 256 + auth_block_size + aux_block_size;
    uint8_t *vbmeta = malloc(total);
    if (!vbmeta) { free(auth_block); free(aux_block); return NULL; }
    memcpy(vbmeta, hdr_blob, 256);
    memcpy(vbmeta + 256, auth_block, auth_block_size);
    memcpy(vbmeta + 256 + auth_block_size, aux_block, aux_block_size);

    free(auth_block);
    free(aux_block);

    *out_size = total;
    return vbmeta;
}

/* 最大元数据空间估计（用于空间预检）
 * 我们的实际 vbmeta = 2112 bytes, footer = 64 bytes, 
 * 但为了安全（盐随机变化导致 desc 大小微调）用宽松值 */
#define MAX_METADATA_ESTIMATE 8192

/* ========== 9. 主函数 ========== */

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <partition_name> <partition_size> <image_path>\n"
                        "Example: %s boot 0x200000 boot.img\n"
                        "         %s system 16777216 system.img\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *partition_name = argv[1];
    uint64_t partition_size = strtoull(argv[2], NULL, 0);
    if (partition_size == 0) {
        fprintf(stderr, "Invalid partition size: %s\n", argv[2]);
        return 1;
    }
    const char *image_path = argv[3];
    const uint64_t block_size = 4096;

    if (partition_size % block_size != 0) {
        fprintf(stderr, "Partition size %llu is not a multiple of %llu\n",
                (unsigned long long)partition_size,
                (unsigned long long)block_size);
        return 1;
    }

    /* 初始化 OpenSSL (不加载配置文件——静态链接时会导致崩溃) */
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* 1. 加载私钥 */
    EVP_PKEY *pkey = load_embedded_key();
    if (!pkey) {
        fprintf(stderr, "Failed to load embedded key\n");
        return 1;
    }
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        fprintf(stderr, "Embedded key is not RSA\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    /* 2. 读取镜像文件 */
    size_t file_size;
    uint8_t *image_data = read_file(image_path, &file_size);
    if (!image_data) {
        fprintf(stderr, "Failed to read %s\n", image_path);
        EVP_PKEY_free(pkey);
        return 1;
    }

    /* 3. 检测并剥离旧 AVB footer (实现幂等性, 类似 avbtool.py) */
    uint64_t orig_size = file_size;
    if (file_size >= sizeof(AvbFooter)) {
        /* 读取文件末尾的 footer 区域 */
        uint64_t footer_candidate_off = file_size - sizeof(AvbFooter);
        uint8_t *footer_area = image_data + footer_candidate_off;
        if (memcmp(footer_area, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) == 0) {
            /* 解析旧 footer, 获取 original_image_size */
            /* Footer 大端布局: magic(4) + ver_maj(4) + ver_min(4) + 
             * orig_size(8) + vbmeta_off(8) + vbmeta_sz(8) + reserved(28) */
            uint64_t old_orig_size = 0;
            for (int i = 0; i < 8; i++) {
                old_orig_size = (old_orig_size << 8) | footer_area[12 + i];
            }
            printf("Found existing footer (original_size=%llu), stripping\n",
                   (unsigned long long)old_orig_size);
            orig_size = old_orig_size;
            /* 不需要真的 truncate 文件; 用 orig_size 做后续判断即可 */
        }
    }

    /* 如果没找到旧 footer, 尝试扫描末尾连续 \0 来确定实际数据大小 */
    if (orig_size == file_size && file_size > 0) {
        /* 从文件末尾向前扫描, 找到最后一个非零字节 */
        size_t scan_pos = file_size;
        while (scan_pos > 0) {
            scan_pos--;
            if (image_data[scan_pos] != 0) {
                scan_pos++; /* 指向最后一个非零字节之后 */
                break;
            }
        }
        if (scan_pos < file_size) {
            /* 对齐到 block_size */
            size_t trimmed = round_up(scan_pos, block_size);
            if (trimmed < file_size) {
                printf("Trimmed trailing zeros: %zu -> %zu bytes\n",
                       file_size, trimmed);
                orig_size = trimmed;
            }
        }
    }

    /* 4. 空间预检: 确保镜像能放进分区 */
    if (orig_size > partition_size - MAX_METADATA_ESTIMATE) {
        fprintf(stderr,
                "ERROR: Image size (%llu) exceeds maximum image size (%llu)\n"
                "       for partition size %llu (need %llu bytes for metadata).\n",
                (unsigned long long)orig_size,
                (unsigned long long)(partition_size - MAX_METADATA_ESTIMATE),
                (unsigned long long)partition_size,
                (unsigned long long)MAX_METADATA_ESTIMATE);
        free(image_data);
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("Image: %s (actual=%zu, partition=%llu)\n",
           image_path, orig_size, (unsigned long long)partition_size);

    /* 5. 生成 VBMeta blob (用 orig_size 的数据, 不是 file_size) */
    size_t vbmeta_size;
    uint8_t *vbmeta = generate_vbmeta(partition_name, image_data, orig_size,
                                      pkey, &vbmeta_size);
    if (!vbmeta) {
        fprintf(stderr, "Failed to generate VBMeta blob\n");
        free(image_data);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t vbmeta_padded_size = round_up(vbmeta_size, block_size);
    uint64_t total_metadata = vbmeta_padded_size + sizeof(AvbFooter);
    if (orig_size + total_metadata > partition_size) {
        fprintf(stderr,
                "ERROR: Image + metadata (%llu + %llu = %llu) exceeds "
                "partition size %llu\n",
                (unsigned long long)orig_size,
                (unsigned long long)total_metadata,
                (unsigned long long)(orig_size + total_metadata),
                (unsigned long long)partition_size);
        free(image_data); free(vbmeta); EVP_PKEY_free(pkey);
        return 1;
    }

    printf("VBMeta blob: %zu bytes (padded: %zu)\n", vbmeta_size, vbmeta_padded_size);

    /* 6. 打开镜像文件（写入模式）, 扩展至 partition_size */
    FILE *fp = fopen(image_path, "rb+");
    if (!fp) {
        perror("fopen for write");
        free(image_data); free(vbmeta); EVP_PKEY_free(pkey);
        return 1;
    }

    if (extend_file(fp, partition_size) != 0) {
        fprintf(stderr, "Failed to extend image to partition size\n");
        fclose(fp); free(image_data); free(vbmeta); EVP_PKEY_free(pkey);
        return 1;
    }

    /* 7. 计算 vbmeta 写入位置: 在分区末尾预留 footer 空间之后 */
    uint64_t vbmeta_offset = partition_size - sizeof(AvbFooter) - vbmeta_padded_size;

    /* 确保不覆盖原镜像数据 */
    if (orig_size > vbmeta_offset) {
        vbmeta_offset = round_up(orig_size, block_size);
    }

    printf("Writing vbmeta at offset %llu\n", (unsigned long long)vbmeta_offset);

    /* 写入 vbmeta blob (带 block_size 填充) */
    uint8_t *vbmeta_padded = calloc(1, vbmeta_padded_size);
    if (!vbmeta_padded) {
        fclose(fp); free(image_data); free(vbmeta); EVP_PKEY_free(pkey);
        return 1;
    }
    memcpy(vbmeta_padded, vbmeta, vbmeta_size);

    if (write_file_at(fp, vbmeta_offset, vbmeta_padded, vbmeta_padded_size) != 0) {
        fprintf(stderr, "Failed to write vbmeta blob\n");
        free(vbmeta_padded); fclose(fp); free(image_data); free(vbmeta);
        EVP_PKEY_free(pkey);
        return 1;
    }
    free(vbmeta_padded);

    /* 8. 写入 Footer (大端) */
    AvbFooter footer;
    memset(&footer, 0, sizeof(footer));
    memcpy(footer.magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN);
    footer.version_major = 1;
    footer.version_minor = 0;
    footer.original_image_size = orig_size;
    footer.vbmeta_offset = vbmeta_offset;
    footer.vbmeta_size = vbmeta_size;

    uint8_t footer_blob[sizeof(AvbFooter)];
    encode_footer_be(&footer, footer_blob);

    uint64_t footer_offset = partition_size - sizeof(AvbFooter);
    if (write_file_at(fp, footer_offset, footer_blob, sizeof(footer_blob)) != 0) {
        fprintf(stderr, "Failed to write footer\n");
        fclose(fp); free(image_data); free(vbmeta);
        EVP_PKEY_free(pkey);
        return 1;
    }

    fclose(fp);

    printf("Successfully signed %s (partition=%s, offset=%llu, vbmeta=%zu bytes)\n",
           image_path, partition_name,
           (unsigned long long)vbmeta_offset, vbmeta_size);

    free(image_data);
    free(vbmeta);
    EVP_PKEY_free(pkey);
    return 0;
}
