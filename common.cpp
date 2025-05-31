#include "common.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <thread>
#include <vector> // Ensure vector is included for std::vector usage

// Initialize global variable
std::vector<std::vector<uint8_t>> ROTATING_AUTH_KEYS;
LogLevel CURRENT_LOG_LEVEL = LogLevel::INFO;


void initialize_rotating_keys() {
    if (!ROTATING_AUTH_KEYS_HEX.empty() && ROTATING_AUTH_KEYS.empty()) {
        for (const auto& hex_key : ROTATING_AUTH_KEYS_HEX) {
            std::vector<uint8_t> byte_key = hex_to_bytes(hex_key);
            if (byte_key.empty() && !hex_key.empty()) {
                std::cerr << "CRITICAL: Error converting hex key to bytes: " << hex_key << std::endl;
                throw std::runtime_error("Error converting hex key to bytes: " + hex_key);
            }
             if (byte_key.size() != 32 && !hex_key.empty()){
                std::cerr << "CRITICAL: Auth key has incorrect length (" << byte_key.size() << " bytes, expected 32) after hex conversion: " << hex_key << std::endl;
                throw std::runtime_error("Auth key has incorrect length after hex conversion: " + hex_key);
            }
            ROTATING_AUTH_KEYS.push_back(byte_key);
        }
    }
    if (ROTATING_AUTH_KEYS.empty()) {
        std::cerr << "CRITICAL: ROTATING_AUTH_KEYS list cannot be empty or failed to load." << std::endl;
        throw std::runtime_error("ROTATING_AUTH_KEYS list cannot be empty or failed to load.");
    }

    LOG_INFO("--- Verifying Loaded Auth Keys (first 3 and last) ---");
    for (size_t i = 0; i < ROTATING_AUTH_KEYS.size(); ++i) {
        if (i < 3 || i == ROTATING_AUTH_KEYS.size() - 1) {
            if (ROTATING_AUTH_KEYS[i].empty()) {
                LOG_ERROR("Loaded Auth Key at index " + std::to_string(i) + " is EMPTY.");
            } else {
                std::string key_hex_full = bytes_to_hex(ROTATING_AUTH_KEYS[i]);
                std::string start_hex = key_hex_full.substr(0, std::min((size_t)16, key_hex_full.length()));
                std::string end_hex = key_hex_full.length() > 16 ? key_hex_full.substr(key_hex_full.length() - std::min((size_t)16, key_hex_full.length())) : "";

                LOG_INFO("Loaded Auth Key Idx " + std::to_string(i) + " (len " + std::to_string(ROTATING_AUTH_KEYS[i].size()) + "): " +
                         start_hex + "..." + end_hex);
            }
        }
    }
    LOG_INFO("--- End of Auth Key Verification ---");
}

void log_message(LogLevel level, const std::string& msg, const char* file, int line) {
    if (level < CURRENT_LOG_LEVEL) {
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm = *std::localtime(&now_c);

    std::ostringstream oss_time;
    oss_time << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");

    std::string level_str;
    switch (level) {
        case LogLevel::DEBUG:   level_str = "DEBUG";   break;
        case LogLevel::INFO:    level_str = "INFO";    break;
        case LogLevel::WARNING: level_str = "WARNING"; break;
        case LogLevel::ERROR:   level_str = "ERROR";   break;
    }

    const char* base_file = strrchr(file, '/');
    if (base_file) {
        base_file++;
    } else {
        base_file = file;
    }

    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lock(log_mutex);

    std::cout << oss_time.str() << " - " << level_str << " - [" << std::this_thread::get_id() << "] "
              << base_file << ":" << line << " - " << msg << std::endl;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) {
        std::cerr << "ERROR: hex_to_bytes: Input hex string has odd length: " << hex << std::endl;
        return bytes;
    }
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char* end;
        long val = strtol(byteString.c_str(), &end, 16);
        if (*end != '\0' || val < 0 || val > 255) {
            std::cerr << "ERROR: hex_to_bytes: Invalid hex character or value in string: " << byteString << " from " << hex << std::endl;
            bytes.clear(); return bytes;
        }
        bytes.push_back(static_cast<uint8_t>(val));
    }
    return bytes;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

void print_buffer(const std::string& prefix, const unsigned char* buf, size_t len) {
    std::ostringstream oss;
    oss << prefix << " (len " << len << "): ";
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buf[i]);
    }
    LOG_DEBUG(oss.str());
}

std::vector<uint8_t> derive_key_hkdf(const std::vector<uint8_t>& master_key,
                                     const std::vector<uint8_t>& salt,
                                     const std::vector<uint8_t>& info,
                                     size_t length) {
    std::vector<uint8_t> derived_key(length);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        LOG_ERROR("HKDF: EVP_PKEY_CTX_new_id failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        return {};
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        LOG_ERROR("HKDF: EVP_PKEY_derive_init failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        LOG_ERROR("HKDF: EVP_PKEY_CTX_set_hkdf_md failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
        LOG_ERROR("HKDF: EVP_PKEY_CTX_set1_hkdf_salt failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key.data(), master_key.size()) <= 0) {
        LOG_ERROR("HKDF: EVP_PKEY_CTX_set1_hkdf_key failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
        LOG_ERROR("HKDF: EVP_PKEY_CTX_add1_hkdf_info failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    size_t out_len_val = length;
    if (EVP_PKEY_derive(pctx, derived_key.data(), &out_len_val) <= 0) {
        LOG_ERROR("HKDF: EVP_PKEY_derive failed. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    if (out_len_val != length) {
         LOG_ERROR("HKDF: Derived key length mismatch. Expected " + std::to_string(length) + ", got " + std::to_string(out_len_val));
         EVP_PKEY_CTX_free(pctx);
         return {};
    }

    EVP_PKEY_CTX_free(pctx);
    return derived_key;
}

bool encrypt_gcm(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& nonce,
                 const std::vector<uint8_t>& ad,
                 std::vector<uint8_t>& ciphertext_with_tag,
                 const std::string& log_ctx_prefix) {
    if (nonce.size() != NONCE_LEN) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: Nonce length invalid. Expected " + std::to_string(NONCE_LEN) + ", got " + std::to_string(nonce.size()));
        return false;
    }
    if (key.size() != 32) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: Key length invalid. Expected 32 bytes for AES-256, got " + std::to_string(key.size()));
        return false;
    }

    if (CURRENT_LOG_LEVEL <= LogLevel::DEBUG) {
        LOG_DEBUG(log_ctx_prefix + "Encrypt GCM Call Details:");
        LOG_DEBUG(log_ctx_prefix + "  Key (first 8B): " + (key.empty() ? "EMPTY" : bytes_to_hex(std::vector<uint8_t>(key.begin(), key.begin() + std::min((size_t)8, key.size())))));
        LOG_DEBUG(log_ctx_prefix + "  Nonce: " + bytes_to_hex(nonce));
        LOG_DEBUG(log_ctx_prefix + "  AD: " + bytes_to_hex(ad) + " (len: " + std::to_string(ad.size()) + ")");
        LOG_DEBUG(log_ctx_prefix + "  Plaintext len: " + std::to_string(plaintext.size()));
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_CIPHER_CTX_new failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_EncryptInit_ex (cipher) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL)) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data())) {
         LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_EncryptInit_ex (key/IV) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len_out;
    if (!ad.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len_out, ad.data(), ad.size())) {
            LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_EncryptUpdate (AD) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    ciphertext_with_tag.assign(plaintext.size() + GCM_TAG_LEN, 0); // Assign resizes and zero-fills
    unsigned char* ct_ptr = ciphertext_with_tag.data();
    int current_ciphertext_len = 0;

    if (!plaintext.empty()){
        if (1 != EVP_EncryptUpdate(ctx, ct_ptr, &len_out, plaintext.data(), plaintext.size())) {
            LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_EncryptUpdate (plaintext) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        current_ciphertext_len = len_out;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ct_ptr + current_ciphertext_len, &len_out)) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_EncryptFinal_ex failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    current_ciphertext_len += len_out;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, ct_ptr + current_ciphertext_len)) {
        LOG_ERROR(log_ctx_prefix + "Encrypt GCM: EVP_CIPHER_CTX_ctrl (GET_TAG) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_with_tag.resize(current_ciphertext_len + GCM_TAG_LEN);
    if (CURRENT_LOG_LEVEL <= LogLevel::DEBUG) {
        LOG_DEBUG(log_ctx_prefix + "Encrypt GCM success. Output len (Ciphertext + Tag): " + std::to_string(ciphertext_with_tag.size()));
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decrypt_gcm(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& ciphertext_with_tag,
                 const std::vector<uint8_t>& nonce,
                 const std::vector<uint8_t>& ad,
                 std::vector<uint8_t>& plaintext,
                 const std::string& log_ctx_prefix) {
    if (nonce.size() != NONCE_LEN) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: Nonce length invalid. Expected " + std::to_string(NONCE_LEN) + ", got " + std::to_string(nonce.size()));
        return false;
    }
    if (ciphertext_with_tag.size() < GCM_TAG_LEN) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: Ciphertext too short to contain tag (len: " + std::to_string(ciphertext_with_tag.size()) + ", tag_len: " + std::to_string(GCM_TAG_LEN) + ").");
        return false;
    }
     if (key.size() != 32) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: Key length invalid. Expected 32 bytes for AES-256, got " + std::to_string(key.size()));
        return false;
    }

    if (CURRENT_LOG_LEVEL <= LogLevel::DEBUG) {
        LOG_DEBUG(log_ctx_prefix + "Decrypt GCM Call Details:");
        LOG_DEBUG(log_ctx_prefix + "  Key (first 8B): " + (key.empty() ? "EMPTY" : bytes_to_hex(std::vector<uint8_t>(key.begin(), key.begin() + std::min((size_t)8, key.size())))));
        LOG_DEBUG(log_ctx_prefix + "  Nonce: " + bytes_to_hex(nonce));
        LOG_DEBUG(log_ctx_prefix + "  AD: " + bytes_to_hex(ad) + " (len: " + std::to_string(ad.size()) + ")");
        LOG_DEBUG(log_ctx_prefix + "  Ciphertext + Tag len: " + std::to_string(ciphertext_with_tag.size()));
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_CIPHER_CTX_new failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        return false;
    }

    const unsigned char* ciphertext_ptr = ciphertext_with_tag.data();
    size_t ciphertext_len = ciphertext_with_tag.size() - GCM_TAG_LEN;
    const unsigned char* tag_ptr = ciphertext_with_tag.data() + ciphertext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_DecryptInit_ex (cipher) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL)) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data())) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_DecryptInit_ex (key/IV) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len_out;
    if (!ad.empty()) {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len_out, ad.data(), ad.size())) {
            LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_DecryptUpdate (AD) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    plaintext.assign(ciphertext_len, 0); // Assign resizes and zero-fills
    unsigned char* pt_ptr = plaintext.data();
    int current_plaintext_len = 0;

    if (ciphertext_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, pt_ptr, &len_out, ciphertext_ptr, ciphertext_len)) {
            LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_DecryptUpdate (ciphertext) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        current_plaintext_len = len_out;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag_ptr)) {
        LOG_ERROR(log_ctx_prefix + "Decrypt GCM: EVP_CIPHER_CTX_ctrl (SET_TAG) failed. " + std::string(ERR_reason_error_string(ERR_get_error())));
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, pt_ptr + current_plaintext_len, &len_out);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        current_plaintext_len += len_out;
        plaintext.resize(current_plaintext_len);
        if (CURRENT_LOG_LEVEL <= LogLevel::DEBUG) {
             LOG_DEBUG(log_ctx_prefix + "Decrypt GCM success. Plaintext len: " + std::to_string(plaintext.size()));
        }
        return true;
    } else {
        unsigned long err_code = ERR_peek_last_error();
        std::string err_str = "General failure (tag mismatch or other)";
        if (err_code != 0) {
             err_str = ERR_reason_error_string(err_code);
        }
        LOG_WARN(log_ctx_prefix + "Decrypt GCM: Tag verification failed or other decryption error. OpenSSL reason: " + err_str);
        plaintext.clear();
        return false;
    }
}

std::vector<uint8_t> generate_random_bytes(size_t len) {
    std::vector<uint8_t> buf(len);
    if (RAND_bytes(buf.data(), static_cast<int>(len)) != 1) {
        LOG_ERROR("Failed to generate random bytes. OpenSSL error: " + std::string(ERR_reason_error_string(ERR_get_error())));
        return {};
    }
    return buf;
}

uint8_t Counter::increment() {
    value = (value % 255) + 1;
    return value;
}

void Counter::set(uint8_t val) {
    value = val % 255;
    if (value == 0 && val != 0) {
         value = 255;
    } else if (val == 0) {
        value = 0;
    }
}