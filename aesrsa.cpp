#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>

#define AES_BLOCK_SIZE 16  // Define AES block size

// Utility function to print bytes in hexadecimal
void printBytes(const std::vector<unsigned char>& bytes) {
    for (unsigned char byte : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << "\n";
}

// Function to generate RSA key pair
std::unique_ptr<RSA, decltype(&::RSA_free)> generateRSAKeyPair(int bits) {
    std::unique_ptr<RSA, decltype(&::RSA_free)> rsa(RSA_new(), ::RSA_free);
    std::unique_ptr<BIGNUM, decltype(&::BN_free)> e(BN_new(), ::BN_free);
    BN_set_word(e.get(), RSA_F4);

    if (RSA_generate_key_ex(rsa.get(), bits, e.get(), nullptr) != 1) {
        throw std::runtime_error("Error generating RSA key pair");
    }

    return rsa;
}

// Function to get public key as string
std::string getPublicKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa);
    char* key = nullptr;
    size_t len = BIO_get_mem_data(bio, &key);
    std::string pubKey(key, len);
    BIO_free(bio);
    return pubKey;
}

// Function to get private key as string
std::string getPrivateKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    char* key = nullptr;
    size_t len = BIO_get_mem_data(bio, &key);
    std::string privKey(key, len);
    BIO_free(bio);
    return privKey;
}

// Function to generate AES key
std::vector<unsigned char> generateAESKey(int bits) {
    std::vector<unsigned char> key(bits / 8);
    if (!RAND_bytes(key.data(), key.size())) {
        throw std::runtime_error("Error generating AES key");
    }
    return key;
}

// Function to encrypt data using AES
std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& plaintext, std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error creating EVP_CIPHER_CTX");

    int len;
    int ciphertext_len;
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);

    if (!RAND_bytes(iv.data(), iv.size())) throw std::runtime_error("Error generating IV");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) throw std::runtime_error("Error in EVP_EncryptInit_ex");

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) throw std::runtime_error("Error in EVP_EncryptUpdate");
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) throw std::runtime_error("Error in EVP_EncryptFinal_ex");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

// Function to decrypt data using AES
std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error creating EVP_CIPHER_CTX");

    int len;
    int plaintext_len;
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) throw std::runtime_error("Error in EVP_DecryptInit_ex");

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) throw std::runtime_error("Error in EVP_DecryptUpdate");
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) throw std::runtime_error("Error in EVP_DecryptFinal_ex");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

// Function to encrypt AES key using RSA
std::vector<unsigned char> rsaEncrypt(RSA* rsa, const std::vector<unsigned char>& plaintext) {
    std::vector<unsigned char> ciphertext(RSA_size(rsa));
    int len = RSA_public_encrypt(plaintext.size(), plaintext.data(), ciphertext.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) throw std::runtime_error("Error encrypting AES key with RSA");
    ciphertext.resize(len);
    return ciphertext;
}

// Function to decrypt AES key using RSA
std::vector<unsigned char> rsaDecrypt(RSA* rsa, const std::vector<unsigned char>& ciphertext) {
    std::vector<unsigned char> plaintext(RSA_size(rsa));
    int len = RSA_private_decrypt(ciphertext.size(), ciphertext.data(), plaintext.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) throw std::runtime_error("Error decrypting AES key with RSA");
    plaintext.resize(len);
    return plaintext;
}

int main() {
    try {
        // Step 1: Generate RSA Key Pair
        auto rsa = generateRSAKeyPair(2048);
        std::string publicKey = getPublicKey(rsa.get());
        std::string privateKey = getPrivateKey(rsa.get());

        std::cout << "Public Key:\n" << publicKey << "\n";
        std::cout << "Private Key:\n" << privateKey << "\n";

        // Step 2: Generate AES Key
        auto aesKey = generateAESKey(256);
        std::cout << "AES Key:\n";
        printBytes(aesKey);

        // Step 3: Encrypt Data with AES
        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        std::string data = "Secret Data";
        std::vector<unsigned char> plaintext(data.begin(), data.end());

        std::cout << "Plaintext before encryption: " << data << "\n";

        auto ciphertext = aesEncrypt(aesKey, plaintext, iv);
        std::cout << "Ciphertext after encryption:\n";
        printBytes(ciphertext);

        std::cout << "IV:\n";
        printBytes(iv);

        // Step 4: Encrypt AES Key with RSA
        auto encAesKey = rsaEncrypt(rsa.get(), aesKey);
        std::cout << "Encrypted AES Key:\n";
        printBytes(encAesKey);

        // Step 5: Decrypt AES Key with RSA
        auto decryptedAesKey = rsaDecrypt(rsa.get(), encAesKey);
        std::cout << "Decrypted AES Key:\n";
        printBytes(decryptedAesKey);

        // Step 6: Decrypt Data with AES
        auto decryptedData = aesDecrypt(decryptedAesKey, ciphertext, iv);
        std::string decryptedString(decryptedData.begin(), decryptedData.end());

        std::cout << "Decryption output: " << decryptedString << "\n";
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
    }

    return 0;
}
