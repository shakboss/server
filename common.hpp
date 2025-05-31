#ifndef COMMON_HPP
#define COMMON_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <mutex>
#include <condition_variable>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

// --- Configuration ---
const std::string SERVER_IP_STR = "127.0.0.1"; // Change to actual server IP for client
const int SERVER_PORT = 8888;

const std::vector<uint8_t> USERNAME = {'o', 'n', 'e'};
const std::vector<uint8_t> PASSWORD = {'o', 'n', 'e'};

// List of rotating pre-shared keys for initial authentication handshake.
// Client and Server MUST have the same list and order.
const std::vector<std::string> ROTATING_AUTH_KEYS_HEX = {
    "5d7688dfc653e52d4b1c4623b23e119b12bb8d38739cd5717676087fa4239dfb",
    "dfa0a0ce82b0ed7192431ca2d0dab4c61886ce0350426accfbd2e11adc983f57",
    "8789457d7c6e72a8bd35b2112a239521c084b3e243b4f143b1284b2d6bbcd596",
    "dd614b4c422dbb852924d0443ada493f1e71766e7a25bd288e1b55ef2bec0287",
    "41feb40c2499128e5aa8819c08f27177214daf9ee4f9135e0357e9f801281196",
    "908f284dce8424c0ac7c2c7921b3e1fe81bff95b21659aa6146c317fa49692af",
    "87b41e08c73ea3ea6faed9a1c123fa2f5d3bfa8e65984965343050e87eb966ad",
    "a5fd5a0a793c4fb4345e5706cfd4a9d300f3b3cdc88f700036e7acec553e4850",
    "9341a40f6f357ab3d47904deeb77ac2f2753c37ca3cb1e7e02adfc9f92202122",
    "cb81733114baa146647dfff1eb3fc5bfd0d10a534788b300197bacd060615476",
    "3d80642d793a7a146f78b849eaade779a947eb15b014a07d706ecc6d729e9b88",
    "da3f98ba8eda688591d9d46c5291facc94494fad43712700135d72ed7ba316db",
    "7f71841baa397ebf892d21aa9310e32fdf1511dfd632c68816325390775393da",
    "3ca2f472e000bc0372c2b57595917755dc34e23cfb911850fe0bb4ead0b68eb2",
    "823bbcd7fa41c44ad6c0808eec72df7e19b37f79028e7313dbac041a1df9347b",
    "07c84744ca508eec320bee3f6b7458b8078f4133b198e86eef88e7d1284fb57e",
    "4d3e0c314c240fe561915ae7fc7b0ce203a04ca6c08ed1717f0f7b1de561101a",
    "320012a4f59d36129b84361b2195eafa341dfb987e33a62153f102a032c84fb3",
    "03966181ab9331036e3c09b65162ed0d00dd23e385bb385387f0fea00a32d281",
    "fe435a9736468a59075a4e4dfea66fbad300885853b38cca7daf2326183aed07",
    "b77f2861a4bb1f71b1196408c80f9b45213fe531be412499395af13c9f8b8d22",
    "55e57edb8d7a95ddcbbab4a9942d68d57a71b582cf8f211798806524a6ea2df1",
    "aaaa767ee0a93f48b83e87c252b332877d290d85e0cc945c4935fa04603da17e",
    "15682179931ead94c76f15221c5bab4d9061c90b2c667d18d7462a5c9226627b",
    "cc49fe3f32c32a9f106ec8ffd8e9381e8679267db1ca5b1749abcb2b08f349a0",
    "4a9dc6e6e6e83650ea04d648c4e790c7b90b0469b0f647904aeea18915ecb735",
    "06ef7a7afae38852c8eaf24d3ef038db8f3554e55b71b4705fe27310d5f2de66",
    "c4bc35c7c67d66a8698aa83ec8608e07065a69e13c012495f6b5fa57620918ae",
    "7b8ee9988355609079875a8de613ef03fe2e0df14b30751b43d7bc8c5134af1d",
    "ffc85fb60350cc46f8f849357bcdff229d9d9b4bd091152e1cf8f19bef881a74",
    "9d310a84c617882163f9f5fbf4ec6dcfdea03bf22d58113edcce0ff611f68e19",
    "54510087110e938b2e93eb96b4912b79b808916bb3f0ed7c53cb4d483ceb8994",
    "f122b0ae8d19f6104ad7b2b46d7c001c2d659b56fbdf0fcc292eb026e06a6bb2",
    "53e5474263760433278c2fc25851125f708f367a7ff12a3f2378534a13104bbb",
    "df293fa8d93d995321bd638cfea255eed53d95063e69dc2596cc1d7f81d780a3",
    "58adf546eba17cd786d1efd6776b260af9b597afe238c7d849843571e808cc2b",
    "841bffdc29e86f5faea74207aac182711a0c081fbe1467ec8d8e5a9bf09dcfa5",
    "3c745c3ddd2f38b2b7d11d42047526291b30cbe08619083fe6d5c534351cde30",
    "9cf23acdbdde810d5ad5ce90a51a637eee6d1c845427d01f8c4cf6dc919d34c9",
    "19d05bb72221fa6150278dcbfc160691cbd7a6669e99e4575e64a2299e170f30",
    "8a9584aa1c4e1bde7599d686c63b8d518335e33ffd412d69229d7314e2037d57",
    "2788229872ac668bc413be9e3fef52ace8b35e8323ee56b39f28f19a62307a85",
    "92b16f112f04ab253e63f997c4efd7bdfe59e83338c4b0d2e433f702357fcebc",
    "4e962ead3acbad5fa9046bb3cb727adf209fc7ff8148ad3d13db2a14bb0f2c58",
    "0ca3af050ef14fba005b8a5311906ffa685337abb6cb9d6871d1daf3ddbe53c1",
    "0e5917eb918f2b27ceb08b41f966e6f7d4e81e51fd6f3ed90a0cb392661ca6a2",
    "95161f0606385990dc1faee377b4ee2e690893dc2bbda42b9c8502ae14606e2d",
    "50f82c8a9384f2c7ad8f0f6892955fcebf4d94a3b45e300464233defcf9c1069",
    "f29aef9cbd2f31e7afb0103a1a65b74e9ca5f690ca0a973c9f3b5abe48269828",
    "b90a2ca1d1651c6f1703757e1d6448bff0ba726a6cc609c86946ca776a9306e3",
    "b8d36c0e1cfa16bbabc14a8fadb547b51db23c142432d92d0fab3795c681801f",
    "d705f95d075858efc1a82a8e8c3048031766a448356a8509ece0ffc14193615e",
    "a30017ffc7b67ba764b9bdeae890404e58f1b0c859dccb519ffefd8a44ba9819",
    "f67e999964f5edca46e8fbe472ac00e774251a211337325c18af34872951a0ca",
    "d6bd2ea529ae52fc4e6fa9dcb67934a6441aa21f73035d008e47cfaebe14b264",
    "899a5e0d48c0ab6fe48e42e77e19d387251b71aae1cf257d3ba60b909da585df",
    "abbbcbf92101f227ce0c9de4fcecca3f7e402b37b4dd5a50dda554597ff1e940",
    "9e07608e110aa8bdabcb19aecc4ae3b2eab6591468cd894d5a25b62239b9477f",
    "2235e504f6d352a919b31949fb89df9fd3d62051c5f98a142f3435f6c5f4ab5c",
    "a4854ca887111863914791ab2e0a2f2b2c329dc520e41141739ec2e9d535c18b",
    "f3e2453c2aa896b71a57d072c6c8d6384676ba2ec6bec8d6c7a9e415a42ea5e3",
    "427f014cc47d1d862290a1424559db394ef2b2afe8a673b06d12da8ftone09499",
    "942a52ededd122a01e0b50725788927d61ddd3a6409f7b3c0b1e017ecb43e9aa",
    "3a66f7f264870e28a9235a8dfa95c737d452ca8160498a03c6d66962b7a025e5",
    "65b733dd5a569400d63161252b846decbbd724c35155892b1fe4ca6215bb257b",
    "cff0d5e5653fe650f6576ab1f96b70a0b4d0419f86c4afa429550a5e1f103144",
    "762f7b251ea4ec3bb4391a8f302eb130094f4a415887766b67f48646c86a2426",
    "9ba5b2eed9d8c33b4869e094e94380551b0ca5b9b01a6094d00de7bac5361b44",
    "c3d161aa14b393c55d474a2c2c34cfff732a73c1f1188cd57a69aaea94f1ee84",
    "e543f1f92b4ad519c6c241e26e5796350b41c95e7bf46ea8e0a6dea1d0c52d95",
    "799bdec274920b0d668daf0e4a211335404b3def65410337f57f70d97599aa57",
    "f9c96f93838dc44d4e2b0a5007391685860a70d3b984eb63da88650d14bb32c4",
    "0e8a6b0721731a5eee5e983215cf3f13feb279ed426093f168c9a07760619d90",
    "94c12077b4648b96aca4495baf4ffb5dc1f8c680615967a60932e5809a5f8dcb",
    "678f06ce68abed9831d53a8889f3d68c0307a237f137f83b22704a3cd7dbfb0d",
    "d6bb8198cf7b8fedd408364da35ff2581c8a2b0808a42381c6a71ae1b041c395",
    "66910291e06333e68ef7cec0b72821d422a8bc5c623603b2072751720e4a6964",
    "de92cb3e01f0dcddc23d5b8cbe8f67319b0e9b7d242dba427e1d4b29c8679a09",
    "faa704399e4520971dfc7cf62724b65a887dc5e9644a8eb4af0709930a845633",
    "fa714edad58fe69747b4f84a13640165f8c0657e711debd1f1625200e9fba94e",
    "572dc4a7362aa303d0cb41e75d409665e530cfb7d9dc23a82d103b5d227c4029",
    "fd4563c304961629ca5d10356f749b80b63e44dc3730350816363317ac9097e0",
    "53b50a3326da9fe09580381e22b2576f0373ebba380705b29cace9103801089d",
    "75256549b8aa39330386b5f2d9732d237aea10b441f3db58b66faa6b88767f19",
    "9c0cbca15d83f554190a865545b6e4ad6c08662e74e425abece57b6254a28a4a",
};

extern std::vector<std::vector<uint8_t>> ROTATING_AUTH_KEYS;

void initialize_rotating_keys(); // Call this once at the start

// Packet Types
const uint8_t PACKET_TYPE_AUTH_REQ = 0x01;
const uint8_t PACKET_TYPE_AUTH_RESP_OK = 0x02;
const uint8_t PACKET_TYPE_AUTH_RESP_FAIL = 0x03;
const uint8_t PACKET_TYPE_DATA = 0x04;
// const uint8_t PACKET_TYPE_APP_DATA_TO_CLIENT = 0x05; // If needed

// Header: Type (1B) | SenderCounter (1B) | ReceiverCounter (1B) | Nonce (12B)
const size_t TYPE_LEN = 1;
const size_t SENDER_COUNTER_LEN = 1;
const size_t RECEIVER_COUNTER_LEN = 1; // This is an ACK of the other party's sender counter
const size_t NONCE_LEN = 12;
const size_t HEADER_LEN = TYPE_LEN + SENDER_COUNTER_LEN + RECEIVER_COUNTER_LEN + NONCE_LEN;
const size_t GCM_TAG_LEN = 16; // Standard for AES-GCM

const size_t SESSION_NONCE_LEN = 32; // For server-generated nonce during auth

// --- Logging ---
// Simple logger (can be replaced with a more sophisticated one)
enum class LogLevel { DEBUG, INFO, WARNING, ERROR };
extern LogLevel CURRENT_LOG_LEVEL;
void log_message(LogLevel level, const std::string& msg, const char* file, int line);

#define LOG_DEBUG(msg) log_message(LogLevel::DEBUG, msg, __FILE__, __LINE__)
#define LOG_INFO(msg) log_message(LogLevel::INFO, msg, __FILE__, __LINE__)
#define LOG_WARN(msg) log_message(LogLevel::WARNING, msg, __FILE__, __LINE__)
#define LOG_ERROR(msg) log_message(LogLevel::ERROR, msg, __FILE__, __LINE__)

// --- Cryptography Helpers ---
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
void print_buffer(const std::string& prefix, const unsigned char* buf, size_t len);


std::vector<uint8_t> derive_key_hkdf(const std::vector<uint8_t>& master_key,
                                     const std::vector<uint8_t>& salt,
                                     const std::vector<uint8_t>& info,
                                     size_t length = 32);

// CORRECTED DECLARATIONS:
bool encrypt_gcm(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& nonce,
                 const std::vector<uint8_t>& ad,
                 std::vector<uint8_t>& ciphertext_with_tag, // <<< ADDED PARAMETER NAME BACK
                 const std::string& log_ctx_prefix = "");

bool decrypt_gcm(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& ciphertext_with_tag,
                 const std::vector<uint8_t>& nonce,
                 const std::vector<uint8_t>& ad,
                 std::vector<uint8_t>& plaintext,           // <<< ADDED PARAMETER NAME BACK
                 const std::string& log_ctx_prefix = "");
// END CORRECTED DECLARATIONS

std::vector<uint8_t> generate_random_bytes(size_t len);

// --- Counter Management ---
class Counter {
private:
    uint8_t value;
    std::string name;
public:
    Counter(const std::string& counter_name = "Counter") : value(0), name(counter_name) {}
    uint8_t increment();
    uint8_t current() const { return value; }
    void set(uint8_t val);
};


// --- Packet Structure (conceptual, handled by manual packing/unpacking) ---
struct PacketHeader {
    uint8_t type;
    uint8_t sender_counter;
    uint8_t receiver_counter_ack; // Acknowledges the peer's last received sender_counter
    std::vector<uint8_t> nonce; // Should be NONCE_LEN

    PacketHeader() : type(0), sender_counter(0), receiver_counter_ack(0) {}

    std::vector<uint8_t> pack() const {
        std::vector<uint8_t> buffer;
        buffer.push_back(type);
        buffer.push_back(sender_counter);
        buffer.push_back(receiver_counter_ack);
        buffer.insert(buffer.end(), nonce.begin(), nonce.end());
        return buffer;
    }

    bool unpack(const std::vector<uint8_t>& raw_header) {
        if (raw_header.size() < TYPE_LEN + SENDER_COUNTER_LEN + RECEIVER_COUNTER_LEN) {
            return false; // Nonce check separate
        }
        type = raw_header[0];
        sender_counter = raw_header[1];
        receiver_counter_ack = raw_header[2];
        if (raw_header.size() >= HEADER_LEN) {
             nonce.assign(raw_header.begin() + 3, raw_header.begin() + HEADER_LEN);
        } else { // Only AD part present for AD construction
            nonce.clear();
        }
        return true;
    }
     bool unpack_ad_part(const std::vector<uint8_t>& raw_header_ad_part) {
        if (raw_header_ad_part.size() != TYPE_LEN + SENDER_COUNTER_LEN + RECEIVER_COUNTER_LEN) {
            return false;
        }
        type = raw_header_ad_part[0];
        sender_counter = raw_header_ad_part[1];
        receiver_counter_ack = raw_header_ad_part[2];
        nonce.clear(); // No nonce in AD part
        return true;
    }
};

#endif // COMMON_HPP