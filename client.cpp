#include "common.hpp"
#include "tun_utils.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <csignal>
#include <atomic>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <cstring>
#include <algorithm>
#include <cerrno>
#include <system_error>

const std::string CLIENT_TUN_IP = "10.8.0.2/24";
const std::string CLIENT_TUN_IFACE_PREF = "ctun";

std::atomic<bool> authenticated(false);
std::vector<uint8_t> session_key; // Protected by client_state_mutex
Counter client_send_counter("ClientSendCounter"); // Needs protection if multiple threads send DATA
Counter client_recv_counter_expected("ClientRecvExpectedCounter"); // Needs protection if multiple threads process received DATA
Counter client_last_recv_counter_ack("ClientLastRecvAckCounter"); // Needs protection

int client_sock_fd = -1;
sockaddr_in server_addr_sock;
int tun_fd = -1;
std::string tun_iface_name;

std::mutex client_state_mutex; // Protects session_key and counters
std::condition_variable auth_cv;

volatile sig_atomic_t client_running = 1;

void client_signal_handler(int signum) {
    LOG_INFO("Client Signal " + std::to_string(signum) + " received, shutting down...");
    client_running = 0;
    bool old_auth_state = authenticated.exchange(false); // Set to false and get old state
    if (old_auth_state) { // Only notify if it was authenticated to avoid spurious wakeups during init
        auth_cv.notify_all();
    }

    if (client_sock_fd != -1) {
        shutdown(client_sock_fd, SHUT_RDWR);
    }
}

// Pass log_auth_key_idx for specific logging during auth attempts
bool send_packet_to_server(uint8_t packet_type, const std::vector<uint8_t>& payload_data, const std::vector<uint8_t>& key_override = {}, const std::string& log_auth_key_idx = "") {
    std::vector<uint8_t> key_to_use;
    std::string key_type_log;
    std::string log_enc_prefix = "Client Encrypt PType=" + std::to_string(packet_type);

    if (!key_override.empty()) {
        key_to_use = key_override;
        key_type_log = "AuthKeyOverride";
        if(!log_auth_key_idx.empty()) log_enc_prefix += " AuthKeyIdx=" + log_auth_key_idx;

    } else {
        std::lock_guard<std::mutex> lock(client_state_mutex);
        if (authenticated.load() && !session_key.empty()) {
            key_to_use = session_key;
            key_type_log = "SessionKey";
        } else {
            LOG_ERROR(log_enc_prefix + ": No key for sending. Auth: " + (authenticated.load() ? "Yes" : "No") + ", SessKeyEmpty: " + (session_key.empty() ? "Yes":"No"));
            return false;
        }
    }
    log_enc_prefix += " KeyType=" + key_type_log + ": ";

    if (key_to_use.empty()) {
        LOG_ERROR(log_enc_prefix + "Key to use is empty.");
        return false;
    }

    PacketHeader header;
    header.type = packet_type;
    { // Lock for counters if they could be accessed by other threads (e.g. keepalives)
      // For current design (auth in main, data in one thread), this might be overly cautious for auth path.
      // But safer if client_send_counter could be used by other packet types.
        std::lock_guard<std::mutex> lock(client_state_mutex);
        header.sender_counter = client_send_counter.increment();
        header.receiver_counter_ack = client_last_recv_counter_ack.current();
    }
    header.nonce = generate_random_bytes(NONCE_LEN);
    if (header.nonce.empty()) {
        LOG_ERROR(log_enc_prefix + "Failed to generate nonce.");
        return false;
    }

    std::vector<uint8_t> ad_data = {header.type, header.sender_counter, header.receiver_counter_ack};

    std::vector<uint8_t> encrypted_payload_with_tag;
    if (!encrypt_gcm(key_to_use, payload_data, header.nonce, ad_data, encrypted_payload_with_tag, log_enc_prefix)) {
        // LOG_ERROR is done inside encrypt_gcm
        return false;
    }

    std::vector<uint8_t> full_packet_data = header.pack();
    full_packet_data.insert(full_packet_data.end(), encrypted_payload_with_tag.begin(), encrypted_payload_with_tag.end());

    ssize_t sent_bytes = sendto(client_sock_fd, full_packet_data.data(), full_packet_data.size(), 0,
                                (struct sockaddr*)&server_addr_sock, sizeof(server_addr_sock));

    if (sent_bytes < 0) {
        LOG_ERROR("Client SndPkt: Socket error sending to server: " + std::string(strerror(errno)));
        return false;
    }
     if (static_cast<size_t>(sent_bytes) != full_packet_data.size()) {
        LOG_WARN("Client SndPkt: Partial send to server. Sent " + std::to_string(sent_bytes) + "/" + std::to_string(full_packet_data.size()));
    }

    LOG_DEBUG("Client SndPkt: Sent UDP to Server. Type=" + std::to_string(packet_type) +
              ", SC=" + std::to_string(header.sender_counter) +
              ", AckServerSC=" + std::to_string(header.receiver_counter_ack) +
              ", Len=" + std::to_string(full_packet_data.size()) + ", KeyType=" + key_type_log +
              (log_auth_key_idx.empty() ? "" : " AuthKeyIdx=" + log_auth_key_idx));
    return true;
}

bool attempt_authentication() {
    if (ROTATING_AUTH_KEYS.empty()) {
        LOG_ERROR("Client Auth: No rotating auth keys configured.");
        return false;
    }

    size_t current_key_idx = 0;
    int total_key_rotations = 0;
    const int max_rotations_per_attempt = ROTATING_AUTH_KEYS.size() * 2; // Try each key twice in a full cycle

    while (client_running && !authenticated.load() && total_key_rotations < max_rotations_per_attempt ) {
        const auto& auth_key_to_try = ROTATING_AUTH_KEYS[current_key_idx];
        if (auth_key_to_try.empty()) {
            LOG_ERROR("Client Auth: Auth key at index " + std::to_string(current_key_idx) + " is empty! Skipping.");
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small pause
            continue;
        }
        std::string current_key_idx_str = std::to_string(current_key_idx);
        std::string key_hex_start = auth_key_to_try.size() >= 4 ? bytes_to_hex(std::vector<uint8_t>(auth_key_to_try.begin(), auth_key_to_try.begin() + 4)) : "N/A";
        LOG_INFO("Client Auth: Attempting with key index " + current_key_idx_str + " (key hex start: " + key_hex_start + "...)");

        std::vector<uint8_t> auth_req_payload;
        auth_req_payload.push_back(static_cast<uint8_t>(USERNAME.size()));
        auth_req_payload.insert(auth_req_payload.end(), USERNAME.begin(), USERNAME.end());
        auth_req_payload.push_back(static_cast<uint8_t>(PASSWORD.size()));
        auth_req_payload.insert(auth_req_payload.end(), PASSWORD.begin(), PASSWORD.end());

        { // Lock for counter reset related to this auth attempt
            std::lock_guard<std::mutex> lock(client_state_mutex);
            client_send_counter.set(0);
            client_last_recv_counter_ack.set(0);
            client_recv_counter_expected.set(0);
        }

        if (!send_packet_to_server(PACKET_TYPE_AUTH_REQ, auth_req_payload, auth_key_to_try, current_key_idx_str)) {
            LOG_WARN("Client Auth: Failed to send AUTH_REQ with key index " + current_key_idx_str + ".");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
            continue;
        }

        std::vector<uint8_t> recv_buffer(2048);
        sockaddr_in temp_server_addr;
        socklen_t server_addr_len_temp = sizeof(temp_server_addr);
        ssize_t nbytes = recvfrom(client_sock_fd, recv_buffer.data(), recv_buffer.size(), 0,
                                  (struct sockaddr*)&temp_server_addr, &server_addr_len_temp);

        if (!client_running) { LOG_INFO("Client Auth: Shutdown signal while waiting for AUTH_RESP."); break; }

        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_WARN("Client Auth: Timeout waiting for AUTH_RESP (KeyIdx " + current_key_idx_str + "). Server might be unresponsive or key wrong.");
            } else if (errno == EINTR) {
                LOG_INFO("Client Auth: recvfrom interrupted during AUTH_RESP wait.");
            } else {
                LOG_ERROR("Client Auth: recvfrom error for AUTH_RESP (KeyIdx " + current_key_idx_str + "): " + std::string(strerror(errno)));
            }
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
            std::this_thread::sleep_for(std::chrono::milliseconds(500 + (rand() % 500))); // Add jitter
            continue;
        }
        if (nbytes < (ssize_t)HEADER_LEN) {
            LOG_WARN("Client Auth: Received malformed AUTH_RESP (too short, len " + std::to_string(nbytes) + ", KeyIdx " + current_key_idx_str + ").");
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
            continue;
        }

        std::vector<uint8_t> full_received_packet(recv_buffer.begin(), recv_buffer.begin() + nbytes);
        PacketHeader resp_header;
        std::vector<uint8_t> raw_resp_header(full_received_packet.begin(), full_received_packet.begin() + HEADER_LEN);
        if (!resp_header.unpack(raw_resp_header)) {
             LOG_WARN("Client Auth: Failed to unpack AUTH_RESP header (KeyIdx " + current_key_idx_str + ").");
             current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
             total_key_rotations++;
             continue;
        }

        std::vector<uint8_t> encrypted_resp_payload_with_tag(full_received_packet.begin() + HEADER_LEN, full_received_packet.end());
        std::vector<uint8_t> ad_for_decrypt = {resp_header.type, resp_header.sender_counter, resp_header.receiver_counter_ack};
        std::vector<uint8_t> decrypted_resp_payload;
        std::string log_dec_prefix = "Client Decrypt AUTH_RESP PType=" + std::to_string(resp_header.type) + " AuthKeyIdx=" + current_key_idx_str + ": ";

        if (!decrypt_gcm(auth_key_to_try, encrypted_resp_payload_with_tag, resp_header.nonce, ad_for_decrypt, decrypted_resp_payload, log_dec_prefix)) {
            // LOG_WARN done by decrypt_gcm
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
            continue;
        }

        // If decryption succeeded:
        LOG_INFO("Client Auth: Successfully decrypted AUTH_RESP with KeyIdx " + current_key_idx_str + ", ServerSC=" + std::to_string(resp_header.sender_counter));
        { // Lock for counter updates
            std::lock_guard<std::mutex> lock(client_state_mutex);
            client_last_recv_counter_ack.set(resp_header.sender_counter);
        }

        if (resp_header.type == PACKET_TYPE_AUTH_RESP_OK) {
            LOG_INFO("Client Auth: Received AUTH_RESP_OK from server.");
            if (decrypted_resp_payload.size() != SESSION_NONCE_LEN) {
                LOG_ERROR("Client Auth: AUTH_RESP_OK payload (server_nonce) incorrect length. Expected " +
                          std::to_string(SESSION_NONCE_LEN) + ", got " + std::to_string(decrypted_resp_payload.size()));
                current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size(); // Continue trying with other keys
                total_key_rotations++;
                continue;
            }
            std::vector<uint8_t> server_session_nonce = decrypted_resp_payload;

            std::vector<uint8_t> derived_skey = derive_key_hkdf(auth_key_to_try, server_session_nonce, {'v','p','n','_','s','e','s','s','i','o','n','_','k','e','y'});
            if (derived_skey.empty()) {
                LOG_ERROR("Client Auth: Session key derivation failed.");
                current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
                total_key_rotations++;
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(client_state_mutex);
                session_key = derived_skey;
                client_send_counter.set(0); // Reset for data phase
                // Expect server's next data packet SC to be based on AUTH_RESP_OK's SC
                client_recv_counter_expected.set(resp_header.sender_counter);
            }
            LOG_INFO("Client Auth: Session key derived: " + (session_key.empty() ? "ERROR" : bytes_to_hex(session_key).substr(0,16) + "..."));

            authenticated = true;
            auth_cv.notify_all();
            LOG_INFO("Client: AUTHENTICATED successfully with server.");
            return true;

        } else if (resp_header.type == PACKET_TYPE_AUTH_RESP_FAIL) {
            std::string reason(decrypted_resp_payload.begin(), decrypted_resp_payload.end());
            LOG_WARN("Client Auth: Authentication FAILED by server (KeyIdx " + current_key_idx_str + "). Reason: " + reason);
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            LOG_WARN("Client Auth: Received unexpected packet type " + std::to_string(resp_header.type) + " in AUTH_RESP (KeyIdx " + current_key_idx_str + ").");
            current_key_idx = (current_key_idx + 1) % ROTATING_AUTH_KEYS.size();
            total_key_rotations++;
        }
    }

    if (!authenticated.load()) {
        LOG_ERROR("Client Auth: Failed to authenticate after " + std::to_string(total_key_rotations) + " attempts.");
    }
    return authenticated.load();
}

void tun_to_udp_loop_client() {
    LOG_INFO("Client TUN->UDP thread started for " + tun_iface_name);
    std::vector<uint8_t> tun_buffer; tun_buffer.reserve(2048);

    {
        std::unique_lock<std::mutex> lock(client_state_mutex);
        auth_cv.wait(lock, []{ return authenticated.load() || !client_running; });
    }

    if (!authenticated.load() && client_running) {
        LOG_WARN("Client TUN->UDP: Authentication not completed, thread exiting.");
        return;
    }
    if (!client_running) {
         LOG_INFO("Client TUN->UDP: Shutdown signal received, thread exiting.");
        return;
    }
    LOG_INFO("Client TUN->UDP: Authenticated, starting packet forwarding.");

    while (client_running && authenticated.load() && tun_fd != -1) {
        tun_buffer.assign(tun_buffer.capacity(), 0); // Use full capacity for read, zero out first
        ssize_t nread = read(tun_fd, tun_buffer.data(), tun_buffer.capacity()); // Read into current capacity

        if (!client_running || !authenticated.load()) break;

        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // Non-blocking TUN and no data
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }
            LOG_ERROR("Client TUN->UDP: Error reading from TUN " + tun_iface_name + ". Error: " + strerror(errno) + ". Signaling auth loss.");
            authenticated = false; auth_cv.notify_all();
            break;
        }
        if (nread == 0) { // EOF on TUN - highly unusual unless closed
            LOG_WARN("Client TUN->UDP: Read 0 bytes (EOF?) from TUN " + tun_iface_name + ". Signaling auth loss.");
            authenticated = false; auth_cv.notify_all();
            break;
        }

        tun_buffer.resize(nread);
        // LOG_DEBUG("Client TUN->UDP: Read " + std::to_string(nread) + " bytes from TUN. Forwarding.");

        if (!send_packet_to_server(PACKET_TYPE_DATA, tun_buffer)) {
            LOG_WARN("Client TUN->UDP: Failed to send DATA packet to server. Assuming connection lost.");
            authenticated = false; auth_cv.notify_all();
            break;
        }
    }
    LOG_INFO("Client TUN->UDP thread finished. Authenticated: " + std::string(authenticated.load() ? "Yes" : "No"));
}

void udp_to_tun_loop_client() {
    LOG_INFO("Client UDP->TUN thread started.");
    std::vector<uint8_t> recv_buffer(2048);

    {
        std::unique_lock<std::mutex> lock(client_state_mutex);
        auth_cv.wait(lock, []{ return authenticated.load() || !client_running; });
    }

    if (!authenticated.load() && client_running) {
        LOG_WARN("Client UDP->TUN: Authentication not completed, thread exiting.");
        return;
    }
     if (!client_running) {
         LOG_INFO("Client UDP->TUN: Shutdown signal received, thread exiting.");
        return;
    }
    LOG_INFO("Client UDP->TUN: Authenticated, starting packet listening.");

    while (client_running && authenticated.load() && client_sock_fd != -1 && tun_fd != -1) {
        sockaddr_in temp_server_addr;
        socklen_t server_addr_len_temp = sizeof(temp_server_addr);
        ssize_t nbytes = recvfrom(client_sock_fd, recv_buffer.data(), recv_buffer.size(), 0,
                                  (struct sockaddr*)&temp_server_addr, &server_addr_len_temp);

        if (!client_running || !authenticated.load()) break;

        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else if (errno == EINTR) {
                 LOG_INFO("Client UDP->TUN: recvfrom interrupted.");
                 continue;
            }
            LOG_ERROR("Client UDP->TUN: recvfrom error: " + std::string(strerror(errno)) + ". Assuming connection lost.");
            authenticated = false; auth_cv.notify_all();
            break;
        }
        if (nbytes < (ssize_t)HEADER_LEN) {
            LOG_WARN("Client UDP->TUN: Received malformed packet (too short, len " + std::to_string(nbytes) + ").");
            continue;
        }

        std::vector<uint8_t> full_received_packet(recv_buffer.begin(), recv_buffer.begin() + nbytes);
        PacketHeader recv_pkt_header;
        std::vector<uint8_t> raw_recv_header(full_received_packet.begin(), full_received_packet.begin() + HEADER_LEN);
        if (!recv_pkt_header.unpack(raw_recv_header)) {
            LOG_WARN("Client UDP->TUN: Failed to unpack received packet header.");
            continue;
        }

        std::vector<uint8_t> encrypted_payload_with_tag(full_received_packet.begin() + HEADER_LEN, full_received_packet.end());
        std::string log_prefix_base = "Client UDP->TUN from Server: PType=" + std::to_string(recv_pkt_header.type) +
                                 ", ServerSC=" + std::to_string(recv_pkt_header.sender_counter) +
                                 ", ServerAckMySC=" + std::to_string(recv_pkt_header.receiver_counter_ack);

        std::vector<uint8_t> current_skey; // Renamed to avoid confusion
        {
            std::lock_guard<std::mutex> lock(client_state_mutex);
            current_skey = session_key;
        }
        if (current_skey.empty()) {
            LOG_ERROR(log_prefix_base + " - No session key! Auth lost or not complete.");
            authenticated = false; auth_cv.notify_all();
            break;
        }

        if (recv_pkt_header.type == PACKET_TYPE_DATA) {
            std::lock_guard<std::mutex> lock(client_state_mutex); // Protect counter access
            uint8_t expected_sc_val = (client_recv_counter_expected.current() == 0) ? 1 : (client_recv_counter_expected.current() % 255) + 1;
            if (recv_pkt_header.sender_counter != expected_sc_val) {
                 LOG_WARN(log_prefix_base + " - Out of order DATA! Expected SC " + std::to_string(expected_sc_val) +
                         ", got " + std::to_string(recv_pkt_header.sender_counter) +
                         ". Current expected base: " + std::to_string(client_recv_counter_expected.current()) + ". Dropping.");
                continue;
            }
        }

        std::string log_dec_prefix = log_prefix_base + " Decrypt With SessionKey: ";
        std::vector<uint8_t> ad_for_decrypt = {recv_pkt_header.type, recv_pkt_header.sender_counter, recv_pkt_header.receiver_counter_ack};
        std::vector<uint8_t> decrypted_payload;

        if (!decrypt_gcm(current_skey, encrypted_payload_with_tag, recv_pkt_header.nonce, ad_for_decrypt, decrypted_payload, log_dec_prefix)) {
            // LOG_WARN is done by decrypt_gcm
            continue;
        }
        // LOG_DEBUG(log_prefix_base + " - Decrypted payload len " + std::to_string(decrypted_payload.size()));

        { // Lock for counter updates
            std::lock_guard<std::mutex> lock(client_state_mutex);
            client_last_recv_counter_ack.set(recv_pkt_header.sender_counter);
            if (recv_pkt_header.type == PACKET_TYPE_DATA) {
                client_recv_counter_expected.set(recv_pkt_header.sender_counter);
            }
        }

        if (recv_pkt_header.type == PACKET_TYPE_DATA) {
            if (tun_fd != -1) {
                ssize_t written_bytes = tun_write(tun_fd, decrypted_payload);
                if (written_bytes < 0) {
                    LOG_ERROR(log_prefix_base + " - Failed to write " + std::to_string(decrypted_payload.size()) + " bytes to TUN " + tun_iface_name + ". Signaling auth loss.");
                    authenticated = false; auth_cv.notify_all();
                    break;
                }/* else {
                    LOG_DEBUG(log_prefix_base + " - Wrote " + std::to_string(written_bytes) + " bytes to TUN " + tun_iface_name);
                }*/
            }
        } else {
            LOG_WARN(log_prefix_base + " - Received unexpected non-DATA packet type " + std::to_string(recv_pkt_header.type) + " after auth. Ignoring payload.");
        }
    }
    LOG_INFO("Client UDP->TUN thread finished. Authenticated: " + std::string(authenticated.load() ? "Yes" : "No"));
}

int main(int argc, char *argv[]) {
    std::string server_host_str = SERVER_IP_STR;
    int server_port_num = SERVER_PORT;
    std::string arg_log_level = "INFO";

    if (argc > 1) server_host_str = argv[1];
    if (argc > 2) {
        try {
            server_port_num = std::stoi(argv[2]);
        } catch (const std::exception& e) {
            std::cerr << "Invalid port number: " << argv[2] << ". Using default " << SERVER_PORT << std::endl;
        }
    }
    if (argc > 3) {
         arg_log_level = argv[3];
         std::transform(arg_log_level.begin(), arg_log_level.end(), arg_log_level.begin(),
                        [](unsigned char c){ return std::toupper(c); });
    }

    if (arg_log_level == "DEBUG") CURRENT_LOG_LEVEL = LogLevel::DEBUG;
    else if (arg_log_level == "INFO") CURRENT_LOG_LEVEL = LogLevel::INFO;
    else if (arg_log_level == "WARNING") CURRENT_LOG_LEVEL = LogLevel::WARNING;
    else if (arg_log_level == "ERROR") CURRENT_LOG_LEVEL = LogLevel::ERROR;
    LOG_INFO("Log level set to " + arg_log_level);
    srand(static_cast<unsigned int>(time(0))); // For random jitter in auth retries

    try {
        initialize_rotating_keys(); // This now includes verification logging
    } catch (const std::runtime_error& e) {
        LOG_ERROR("FATAL: Failed to initialize/verify rotating keys: " + std::string(e.what()));
        return 1;
    }
    LOG_INFO("Client initialized with " + std::to_string(ROTATING_AUTH_KEYS.size()) + " rotating Auth Keys.");


    signal(SIGINT, client_signal_handler);
    signal(SIGTERM, client_signal_handler);

    // TUN Setup must happen before socket ops if it influences routing or IP binding (not in this simple case)
    tun_iface_name = CLIENT_TUN_IFACE_PREF;
    tun_fd = tun_alloc(tun_iface_name);
    if (tun_fd < 0) {
        LOG_ERROR("Client Main: Failed to allocate TUN interface. Exiting.");
        return 1;
    }
    if (!configure_tun_iface(tun_iface_name, CLIENT_TUN_IP)) {
        LOG_ERROR("Client Main: Failed to configure TUN interface " + tun_iface_name + ". Exiting.");
        if (tun_fd != -1) close(tun_fd);
        return 1;
    }
    LOG_INFO("Client Main: TUN interface " + tun_iface_name + " ready on " + CLIENT_TUN_IP);

    // Socket Setup
    client_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_sock_fd < 0) {
        LOG_ERROR("Client Main: Failed to create socket: " + std::string(strerror(errno)));
        if (tun_fd != -1) close(tun_fd);
        return 1;
    }

    memset(&server_addr_sock, 0, sizeof(server_addr_sock));
    server_addr_sock.sin_family = AF_INET;
    server_addr_sock.sin_port = htons(static_cast<uint16_t>(server_port_num));

    struct hostent *he;
    he = gethostbyname(server_host_str.c_str()); // Note: gethostbyname is deprecated, consider getaddrinfo
    if (he == NULL) {
        #ifdef __GNU_LIBRARY__
        LOG_ERROR("Client Main: gethostbyname failed for " + server_host_str + ": " + hstrerror(h_errno));
        #else
        LOG_ERROR("Client Main: gethostbyname failed for " + server_host_str + ". h_errno: " + std::to_string(h_errno));
        #endif
        if (client_sock_fd != -1) close(client_sock_fd);
        if (tun_fd != -1) close(tun_fd);
        return 1;
    }
    memcpy(&server_addr_sock.sin_addr, he->h_addr_list[0], static_cast<size_t>(he->h_length));
    char server_ip_resolved_cstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server_addr_sock.sin_addr), server_ip_resolved_cstr, INET_ADDRSTRLEN);
    LOG_INFO("Client Main: Server target '" + server_host_str + "' resolved to " + std::string(server_ip_resolved_cstr) + ":" + std::to_string(server_port_num));

    struct timeval tv_sock_timeout;
    tv_sock_timeout.tv_sec = 5;
    tv_sock_timeout.tv_usec = 0;
    if (setsockopt(client_sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_sock_timeout, sizeof tv_sock_timeout) < 0) {
        LOG_WARN("Client Main: Failed to set socket SO_RCVTIMEO: " + std::string(strerror(errno)) + ". recvfrom may block longer.");
    }

    // Main authentication and communication loop
    while(client_running) {
        if (!authenticated.load()) { // Only attempt auth if not already authenticated
            if (!attempt_authentication()) { // This function handles its own retries internally for a cycle
                if (!client_running) { LOG_INFO("Client Main: Shutdown during auth attempt cycle."); break; }
                LOG_ERROR("Client Main: Authentication attempt cycle failed. Retrying entire cycle in 10 seconds...");
                for(int i=0; i<10 && client_running; ++i) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                if (!client_running) { LOG_INFO("Client Main: Shutdown during 10s retry pause."); break; }
                continue; // Retry the whole attempt_authentication()
            }
        }

        // If authenticated, start/ensure worker threads are running
        LOG_INFO("Client Main: Authentication successful (or already was). Ensuring worker threads...");
        std::thread tun_reader_thread(tun_to_udp_loop_client);
        std::thread udp_reader_thread(udp_to_tun_loop_client);

        // Monitor loop while authenticated
        while(client_running && authenticated.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        LOG_INFO("Client Main: Auth lost or shutdown signal. Joining worker threads...");
        if (tun_reader_thread.joinable()) tun_reader_thread.join();
        LOG_INFO("Client Main: TUN reader thread joined.");
        if (udp_reader_thread.joinable()) udp_reader_thread.join();
        LOG_INFO("Client Main: UDP reader thread joined.");

        if (!client_running) { LOG_INFO("Client Main: Shutdown signal caused exit from worker monitoring."); break; }

        // If we are here and client_running is true, it means authenticated became false (e.g. connection lost)
        LOG_INFO("Client Main: Worker threads joined due to auth loss. Will attempt re-authentication.");
        // authenticated is already false. Clear session key for safety before next auth attempt.
        {
            std::lock_guard<std::mutex> lock(client_state_mutex);
            session_key.clear();
        }
    }

    LOG_INFO("Client Main: Shutting down external resources.");
    if (client_sock_fd != -1) {
        close(client_sock_fd);
        client_sock_fd = -1;
    }
    if (tun_fd != -1) {
        close(tun_fd);
        tun_fd = -1;
    }

    LOG_INFO("Client Main: Shutdown complete.");
    return 0;
}
