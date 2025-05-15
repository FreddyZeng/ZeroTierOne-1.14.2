/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#ifndef ZT_C25519_HPP
#define ZT_C25519_HPP

#include <string>    // std::string
#include <vector>    // std::vector<uint8_t>
#include <cstdint>   // uint8_t
#include <cstddef>   // size_t
#include <cstring>   // std::memcpy, std::memcmp

#include "Utils.hpp"


namespace ZeroTier {
#define ZT_C25519_PUBLIC_KEY_LEN 64
#define ZT_C25519_PRIVATE_KEY_LEN 64
#define ZT_C25519_SIGNATURE_LEN 96

// 公钥长度（字节）
static constexpr size_t PUBKEY_LEN = ZT_C25519_PUBLIC_KEY_LEN;  // 就是 64

// 1) 用 std::array 存放 64 字节
using PubKeyBin = std::array<uint8_t, PUBKEY_LEN>;

// 2) 自定义一个哈希器（这里用 FNV-1a）
struct PubKeyHash {
	size_t operator()(ZeroTier::PubKeyBin const &p) const noexcept {
		static const size_t FNV_offset_basis = 14695981039346656037ULL;
		static const size_t FNV_prime        = 1099511628211ULL;
		size_t h = FNV_offset_basis;
		for (auto byte : p) {
			h ^= byte;
			h *= FNV_prime;
		}
		return h;
	}
};

// 将单个十六进制字符映射到 0–15，失败返回 false
static bool ZeroTier_HexCharToValue(char c, uint8_t &out) {
    if ('0' <= c && c <= '9') { out = c - '0'; return true; }
    if ('a' <= c && c <= 'f') { out = c - 'a' + 10; return true; }
    if ('A' <= c && c <= 'F') { out = c - 'A' + 10; return true; }
    return false;
}

// 通用：解析任意偶数长度的 hex 字符串到字节数组
// - hex: 非空且偶数长度，只能包含合法十六进制字符
// - out: 解析后字节，长度 = hex.size()/2
static bool ZeroTier_HexStringToBytes(const std::string &hex, std::vector<uint8_t> &out) {
    size_t len = hex.size();
    if (len == 0 || (len & 1)) {
        return false;  // 长度检查
    }
    out.clear();
    out.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        uint8_t hi, lo;
        if (!ZeroTier_HexCharToValue(hex[i], hi) ||
            !ZeroTier_HexCharToValue(hex[i+1], lo)) {
            return false;  // 非法字符
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// 专用：解析 128 字符 hex 公钥到 PubKeyBin
static bool ZeroTier_ParseHexPubKey(const std::string &hex, ZeroTier::PubKeyBin &pubKeyBin) {
    if (hex.size() != ZT_C25519_PUBLIC_KEY_LEN * 2) return false;
    std::vector<uint8_t> buf;
    if (!ZeroTier_HexStringToBytes(hex, buf)) return false;
    // 直接 memcpy 最清晰
    std::memcpy(pubKeyBin.data(), buf.data(), ZT_C25519_PUBLIC_KEY_LEN);
    return true;
}

// 通用：把任意字节数组转换成 hex 字符串（小写）
// - data: 指向输入字节流
// - len:  数据长度
// 返回：长度 = len*2 的 std::string，每个字节对应两个 hex 字符
static std::string ZeroTier_BytesToHexString(const uint8_t* data, size_t len) {
    static const char* hexDigits = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        // 高 4 位
        s.push_back(hexDigits[b >> 4]);
        // 低 4 位
        s.push_back(hexDigits[b & 0x0F]);
    }
    return s;
}

// 如果你有一个 PubKeyBin（固定长度），可以这样包一层：
static std::string ZeroTier_PubKeyBinToHex(const PubKeyBin& pubKeyBin) {
    return ZeroTier_BytesToHexString(pubKeyBin.data(), ZT_C25519_PUBLIC_KEY_LEN);
}

/**
 * A combined Curve25519 ECDH and Ed25519 signature engine
 */
class C25519
{
public:
	struct Public { uint8_t data[ZT_C25519_PUBLIC_KEY_LEN]; };
	struct Private { uint8_t data[ZT_C25519_PRIVATE_KEY_LEN]; };
	struct Signature { uint8_t data[ZT_C25519_SIGNATURE_LEN]; };
	struct Pair { Public pub; Private priv; };

	/**
	 * Generate a C25519 elliptic curve key pair
	 */
	static inline Pair generate()
	{
		Pair kp;
		Utils::getSecureRandom(kp.priv.data,ZT_C25519_PRIVATE_KEY_LEN);
		_calcPubDH(kp);
		_calcPubED(kp);
		return kp;
	}

	/**
	 * Generate a key pair satisfying a condition
	 *
	 * This begins with a random keypair from a random secret key and then
	 * iteratively increments the random secret until cond(kp) returns true.
	 * This is used to compute key pairs in which the public key, its hash
	 * or some other aspect of it satisfies some condition, such as for a
	 * hashcash criteria.
	 *
	 * @param cond Condition function or function object
	 * @return Key pair where cond(kp) returns true
	 * @tparam F Type of 'cond'
	 */
	template<typename F>
	static inline Pair generateSatisfying(F cond)
	{
		Pair kp;
		void *const priv = (void *)kp.priv.data;
		Utils::getSecureRandom(priv,ZT_C25519_PRIVATE_KEY_LEN);
		_calcPubED(kp); // do Ed25519 key -- bytes 32-63 of pub and priv
		do {
			++(((uint64_t *)priv)[1]);
			--(((uint64_t *)priv)[2]);
			_calcPubDH(kp); // keep regenerating bytes 0-31 until satisfied
		} while (!cond(kp));
		return kp;
	}

	/**
	 * Perform C25519 ECC key agreement
	 *
	 * Actual key bytes are generated from one or more SHA-512 digests of
	 * the raw result of key agreement.
	 *
	 * @param mine My private key
	 * @param their Their public key
	 * @param keybuf Buffer to fill
	 * @param keylen Number of key bytes to generate
	 */
	static void agree(const Private &mine,const Public &their,void *keybuf,unsigned int keylen);
	static inline void agree(const Pair &mine,const Public &their,void *keybuf,unsigned int keylen) { agree(mine.priv,their,keybuf,keylen); }

	/**
	 * Sign a message with a sender's key pair
	 *
	 * This takes the SHA-521 of msg[] and then signs the first 32 bytes of this
	 * digest, returning it and the 64-byte ed25519 signature in signature[].
	 * This results in a signature that verifies both the signer's authenticity
	 * and the integrity of the message.
	 *
	 * This is based on the original ed25519 code from NaCl and the SUPERCOP
	 * cipher benchmark suite, but with the modification that it always
	 * produces a signature of fixed 96-byte length based on the hash of an
	 * arbitrary-length message.
	 *
	 * @param myPrivate My private key
	 * @param myPublic My public key
	 * @param msg Message to sign
	 * @param len Length of message in bytes
	 * @param signature Buffer to fill with signature -- MUST be 96 bytes in length
	 */
	static void sign(const Private &myPrivate,const Public &myPublic,const void *msg,unsigned int len,void *signature);
	static inline void sign(const Pair &mine,const void *msg,unsigned int len,void *signature) { sign(mine.priv,mine.pub,msg,len,signature); }

	/**
	 * Sign a message with a sender's key pair
	 *
	 * @param myPrivate My private key
	 * @param myPublic My public key
	 * @param msg Message to sign
	 * @param len Length of message in bytes
	 * @return Signature
	 */
	static inline Signature sign(const Private &myPrivate,const Public &myPublic,const void *msg,unsigned int len)
	{
		Signature sig;
		sign(myPrivate,myPublic,msg,len,sig.data);
		return sig;
	}
	static inline Signature sign(const Pair &mine,const void *msg,unsigned int len)
	{
		Signature sig;
		sign(mine.priv,mine.pub,msg,len,sig.data);
		return sig;
	}

	/**
	 * Verify a message's signature
	 *
	 * @param their Public key to verify against
	 * @param msg Message to verify signature integrity against
	 * @param len Length of message in bytes
	 * @param signature 96-byte signature
	 * @return True if signature is valid and the message is authentic and unmodified
	 */
	static bool verify(const Public &their,const void *msg,unsigned int len,const void *signature);

	/**
	 * Verify a message's signature
	 *
	 * @param their Public key to verify against
	 * @param msg Message to verify signature integrity against
	 * @param len Length of message in bytes
	 * @param signature 96-byte signature
	 * @return True if signature is valid and the message is authentic and unmodified
	 */
	static inline bool verify(const Public &their,const void *msg,unsigned int len,const Signature &signature)
	{
		return verify(their,msg,len,signature.data);
	}

private:
	// derive first 32 bytes of kp.pub from first 32 bytes of kp.priv
	// this is the ECDH key
	static void _calcPubDH(Pair &kp);

	// derive 2nd 32 bytes of kp.pub from 2nd 32 bytes of kp.priv
	// this is the Ed25519 sign/verify key
	static void _calcPubED(Pair &kp);
};

} // namespace ZeroTier

#endif
