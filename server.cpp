#include "common.hpp"
#include "tun_utils.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable> // Not strictly used in this version, but good for complex state
#include <map>
#include <chrono>
#include <csignal>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cstring>
#include <algorithm>
#include <cerrno>
#include <fcntl.h> // For fcntl if making TUN non-blocking

const std::string SERVER_TUN_IP = "10.8.0.1/24";
const std::string SERVER_TUN_IFACE_PREF = "stun";

struct ClientSession {
    sockaddr_in client_addr_sock_struct;
    std::string client_addr_str_key;

    Counter send_counter;
    Counter recv_counter_expected;
    Counter last_recv_counter_ack;

    std::vector<uint8_t> session_key;
    bool authenticated;
    std::vector<uint8_t> server_session_nonce; // Server's nonce for this session's key derivation
    std::chrono::steady_clock::time_point last_active_time;
    std::string last_auth_key_idx_used_by_server; // Store which server AuthKey successfully auth'd this client

    ClientSession(const sockaddr_in& addr_sock, const std::string& addr_key) :
        client_addr_sock_struct(addr_sock), client_addr_str_key(addr_key),
        send_counter("SrvSend-" + addr_key),
        recv_counter_expected("SrvRecvExp-" + addr_key),
        last_recv_counter_ack("SrvLastRecvAck-" + addr_key),
        authenticated(false), last_auth_key_idx_used_by_server("N/A") {
        last_active_time = std::chrono::steady_clock::now();
        LOG_INFO("Session: New potential session for " + client_addr_str_key);
    }

    void update_last_active() {
        last_active_time = std::chrono::steady_clock::now();
    }

    void reset_for_reauth() {
        LOG_INFO("Session: Resetting auth state for " + client_addr_str_key);
        authenticated = false;
        session_key.clear();
        server_session_nonce.clear();
        // Counters might be reset upon successful re-auth, or handled by their specific logic.
        // For this model, recv_counter_expected gets set on first packet of a sequence.
        // send_counter gets reset for auth responses.
    }
};

std::map<std::string, ClientSession> client_sessions;
std::mutex sessions_mutex;
int current_server_auth_key_idx = 0;
std::mutex auth_key_idx_mutex; // Protects current_server_auth_key_idx

int server_sock_fd = -1;
int global_tun_fd = -1;
std::string global_tun_iface_name;

volatile sig_atomic_t running = 1; // Global flag to signal shutdown

void signal_handler(int signum) {
    LOG_INFO("Signal Handler: Received signal " + std::to_string(signum) + ". Initiating server shutdown.");
    running = 0;
    if (server_sock_fd != -1) {
        // Attempt to unblock recvfrom in the main loop.
        // Closing from another thread is generally discouraged for complex apps,
        // but shutdown() is safer for unblocking. A pipe or signalfd is more robust.
        if (shutdown(server_sock_fd, SHUT_RDWR) == -1 && errno != ENOTCONN) {
            // ENOTCONN means it wasn't connected, which is fine for UDP.
            // LOG_WARN("Signal Handler: shutdown(server_sock_fd) failed: " + std::string(strerror(errno)));
        }
    }
    // The main loop and TUN loop will detect 'running = 0' and exit, then close FDs.
}

// Gets the server's current rotating key, to be used by a client for a *new* auth attempt.
std::vector<uint8_t> get_server_current_rotating_auth_key(int& out_idx_val) {
    std::lock_guard<std::mutex> lock(auth_key_idx_mutex);
    if (ROTATING_AUTH_KEYS.empty()) {
         LOG_ERROR("AUTH KEY: CRITICAL - get_server_current_rotating_auth_key called with empty key list!");
         throw std::runtime_error("Rotating auth keys are not initialized or empty.");
    }
    out_idx_val = current_server_auth_key_idx;
    return ROTATING_AUTH_KEYS[current_server_auth_key_idx];
}

// Rotates the server's key index, typically *after* a successful authentication with the *previous* current key.
void rotate_server_auth_key_idx() {
    std::lock_guard<std::mutex> lock(auth_key_idx_mutex);
    if (ROTATING_AUTH_KEYS.empty()) {
        LOG_WARN("AUTH KEY: Cannot rotate server auth key index, list is empty.");
        return;
    }
    int old_key_index = current_server_auth_key_idx;
    current_server_auth_key_idx = (current_server_auth_key_idx + 1) % ROTATING_AUTH_KEYS.size();

    std::string new_key_hex_full = bytes_to_hex(ROTATING_AUTH_KEYS[current_server_auth_key_idx]);
    std::string new_key_hex_end = new_key_hex_full.length() >= 8 ? new_key_hex_full.substr(new_key_hex_full.length() - 8) : "N/A";
    LOG_INFO("AUTH KEY: Server rotated its current auth key index (for NEXT new auth) from " + std::to_string(old_key_index) +
             " to " + std::to_string(current_server_auth_key_idx) +
             " (new key ends with: ..." + new_key_hex_end + ")");
}

// server_auth_key_idx_used_for_resp is the index of the server's rotating key that was used for the successful AUTH_REQ
// or the one the server *would* have used if an AUTH_FAIL is sent before a successful decryption.
bool send_packet_to_client(ClientSession& session, uint8_t packet_type, const std::vector<uint8_t>& payload_data,
                           bool use_session_key, const std::string& server_auth_key_idx_used_for_resp = "") {
    std::vector<uint8_t> key_to_use_for_send;
    std::string key_type_log_detail;
    std::string log_enc_prefix = "SrvSend PType=" + std::to_string(packet_type) + " to " + session.client_addr_str_key;

    if (use_session_key && session.authenticated && !session.session_key.empty()) {
        key_to_use_for_send = session.session_key;
        key_type_log_detail = "SessionKey";
    } else { // Typically for AUTH_RESP_OK or AUTH_RESP_FAIL
        // For AUTH_RESP, we should encrypt with the *same* server rotating key that the client just used/attempted.
        // If server_auth_key_idx_used_for_resp is provided (it's the index of the key server just successfully used for AUTH_REQ), use that specific key.
        // Otherwise, (e.g. for a proactive AUTH_FAIL due to malformed packet before decryption attempt), use server's current.
        int key_idx_to_use_val;
        if (!server_auth_key_idx_used_for_resp.empty() && server_auth_key_idx_used_for_resp != "N/A") {
            try {
                key_idx_to_use_val = std::stoi(server_auth_key_idx_used_for_resp);
                if (key_idx_to_use_val < 0 || static_cast<size_t>(key_idx_to_use_val) >= ROTATING_AUTH_KEYS.size()) {
                    LOG_ERROR(log_enc_prefix + ": Invalid server_auth_key_idx_used_for_resp: " + server_auth_key_idx_used_for_resp + ". Falling back to current.");
                    key_idx_to_use_val = current_server_auth_key_idx; // Fallback to current if bad index provided
                }
            } catch (const std::exception& e) {
                LOG_ERROR(log_enc_prefix + ": Failed to parse server_auth_key_idx_used_for_resp '" + server_auth_key_idx_used_for_resp + "': " + e.what() + ". Falling back to current.");
                key_idx_to_use_val = current_server_auth_key_idx; // Fallback
            }
        } else { // Default to server's current rotating key if no specific index given
            std::lock_guard<std::mutex> lock(auth_key_idx_mutex);
            key_idx_to_use_val = current_server_auth_key_idx;
        }

        if (ROTATING_AUTH_KEYS.empty() || static_cast<size_t>(key_idx_to_use_val) >= ROTATING_AUTH_KEYS.size()){
            LOG_ERROR(log_enc_prefix + "Cannot send auth resp: No rotating keys or invalid index " + std::to_string(key_idx_to_use_val));
            return false;
        }
        key_to_use_for_send = ROTATING_AUTH_KEYS[key_idx_to_use_val];
        key_type_log_detail = "AuthKey (SrvIdx " + std::to_string(key_idx_to_use_val) + ")";
    }
    log_enc_prefix += " With " + key_type_log_detail + ": ";

    if (key_to_use_for_send.empty()) {
        LOG_ERROR(log_enc_prefix + "No key resolved for sending.");
        return false;
    }

    PacketHeader header;
    header.type = packet_type;
    header.sender_counter = session.send_counter.increment();
    header.receiver_counter_ack = session.last_recv_counter_ack.current();
    header.nonce = generate_random_bytes(NONCE_LEN);
    if (header.nonce.empty()) {
        LOG_ERROR(log_enc_prefix + "Failed to generate nonce.");
        return false;
    }

    std::vector<uint8_t> ad_data = {header.type, header.sender_counter, header.receiver_counter_ack};
    std::vector<uint8_t> encrypted_payload_with_tag;

    if (!encrypt_gcm(key_to_use_for_send, payload_data, header.nonce, ad_data, encrypted_payload_with_tag, log_enc_prefix)) {
        return false; // Error logged by encrypt_gcm
    }

    std::vector<uint8_t> full_packet_data = header.pack();
    full_packet_data.insert(full_packet_data.end(), encrypted_payload_with_tag.begin(), encrypted_payload_with_tag.end());

    ssize_t sent_bytes = sendto(server_sock_fd, full_packet_data.data(), full_packet_data.size(), 0,
                                (struct sockaddr*)&session.client_addr_sock_struct, sizeof(session.client_addr_sock_struct));

    if (sent_bytes < 0) {
        LOG_ERROR("SrvSend: Socket error sending to " + session.client_addr_str_key + ": " + strerror(errno));
        return false;
    }
    if (static_cast<size_t>(sent_bytes) != full_packet_data.size()) {
        LOG_WARN("SrvSend: Partial send to " + session.client_addr_str_key + ". Sent " + std::to_string(sent_bytes) + "/" + std::to_string(full_packet_data.size()));
    }

    LOG_DEBUG("SrvSend: Sent UDP. Target=" + session.client_addr_str_key + ", Type=" + std::to_string(packet_type) +
              ", SC=" + std::to_string(header.sender_counter) +
              ", AckClientSC=" + std::to_string(header.receiver_counter_ack) +
              ", Len=" + std::to_string(full_packet_data.size()) + ", Using " + key_type_log_detail);
    return true;
}

void send_auth_fail_response(ClientSession& session, const std::string& reason, const std::string& server_auth_key_idx_tried) {
    std::vector<uint8_t> reason_bytes(reason.begin(), reason.end());
    session.send_counter.set(0);
    LOG_WARN("SrvAuthFail: To " + session.client_addr_str_key + ". Reason: " + reason + ". Server tried decrypting with AuthKey SrvIdx " + server_auth_key_idx_tried);
    send_packet_to_client(session, PACKET_TYPE_AUTH_RESP_FAIL, reason_bytes, false, server_auth_key_idx_tried);
}

void handle_received_packet(const std::vector<uint8_t>& data, const sockaddr_in& client_addr_sock_from_recv, const std::string& client_addr_key_str) {
    ClientSession* session_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = client_sessions.find(client_addr_key_str);
        if (it == client_sessions.end()) {
             auto emplaced_pair = client_sessions.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(client_addr_key_str),
                std::forward_as_tuple(client_addr_sock_from_recv, client_addr_key_str)
            );
            session_ptr = &emplaced_pair.first->second;
        } else {
            session_ptr = &it->second;
            // it->second.client_addr_sock_struct = client_addr_sock_from_recv; // Update if client IP/port could change mid-session
        }
    }
    if (!session_ptr) {
        LOG_ERROR("SrvRcvPkt CRITICAL: Failed to get/create session for " + client_addr_key_str);
        return;
    }
    ClientSession& session = *session_ptr;
    session.update_last_active();

    if (data.size() < HEADER_LEN) {
        LOG_WARN("SrvRcvPkt from " + client_addr_key_str + ": Malformed (too short, len " + std::to_string(data.size()) + "). Dropping.");
        return;
    }

    PacketHeader received_header;
    std::vector<uint8_t> raw_header_data(data.begin(), data.begin() + HEADER_LEN);
    if (!received_header.unpack(raw_header_data)) {
        LOG_WARN("SrvRcvPkt from " + client_addr_key_str + ": Failed to unpack header. Dropping.");
        return;
    }

    std::vector<uint8_t> encrypted_payload_with_tag(data.begin() + HEADER_LEN, data.end());
    std::string log_prefix_base = "SrvRcvPkt from " + client_addr_key_str + " (CurSessAuth: " +
                             (session.authenticated ? "Yes" : "No") + "): PType=" + std::to_string(received_header.type) +
                             ", ClientSC=" + std::to_string(received_header.sender_counter) +
                             ", ClientAckMySC=" + std::to_string(received_header.receiver_counter_ack);

    std::vector<uint8_t> key_for_decryption;
    std::string key_type_for_log_detail;
    std::string server_auth_idx_used_for_auth_req_str = "N/A"; // For logging/AuthFail response if AUTH_REQ fails

    if (received_header.type == PACKET_TYPE_AUTH_REQ) {
        int srv_auth_idx_val;
        key_for_decryption = get_server_current_rotating_auth_key(srv_auth_idx_val);
        server_auth_idx_used_for_auth_req_str = std::to_string(srv_auth_idx_val);
        key_type_for_log_detail = "AuthKey (SrvIdx " + server_auth_idx_used_for_auth_req_str + ")";

        if (session.authenticated) {
            LOG_WARN(log_prefix_base + " - Client sent AUTH_REQ on an already authenticated session. Resetting this session for re-authentication.");
            session.reset_for_reauth(); // Clear old session state
        }
    } else if (session.authenticated && !session.session_key.empty()) { // For DATA packets
        key_for_decryption = session.session_key;
        key_type_for_log_detail = "SessionKey (derived via SrvAuthKeyIdx " + session.last_auth_key_idx_used_by_server + ")";
    } else { // Non-AUTH_REQ on unauthenticated session
        LOG_WARN(log_prefix_base + " - Non-AUTH_REQ packet type=" + std::to_string(received_header.type) +
                 " received on unauthenticated session or session key is missing. Dropping.");
        return;
    }

    if (key_for_decryption.empty()) {
        LOG_ERROR(log_prefix_base + " - No key available for decryption (using " + key_type_for_log_detail + "). Dropping.");
        return;
    }
    std::string log_dec_prefix = log_prefix_base + " DecryptWith " + key_type_for_log_detail + ": ";

    std::vector<uint8_t> decrypted_payload;
    std::vector<uint8_t> ad_for_decrypt = {received_header.type, received_header.sender_counter, received_header.receiver_counter_ack};

    if (!decrypt_gcm(key_for_decryption, encrypted_payload_with_tag, received_header.nonce, ad_for_decrypt, decrypted_payload, log_dec_prefix)) {
        // Error logged by decrypt_gcm
        if (received_header.type == PACKET_TYPE_AUTH_REQ) {
            LOG_WARN(log_prefix_base + " - AUTH_REQ decryption failed (key or content mismatch). Client needs to retry or align key.");
        } else { // Data packet decryption failure with session key
            LOG_ERROR(log_prefix_base + " - DATA packet decryption failed with " + key_type_for_log_detail + ". Session might be compromised or desynced. Resetting auth.");
            session.reset_for_reauth(); // Force re-auth for this client
        }
        return;
    }

    LOG_DEBUG(log_prefix_base + " - Decrypted OK. PayloadLen=" + std::to_string(decrypted_payload.size()) + ", WithKey=" + key_type_for_log_detail);

    session.last_recv_counter_ack.set(received_header.sender_counter);
    if (received_header.type == PACKET_TYPE_DATA && session.authenticated) {
        uint8_t expected_data_sc = (session.recv_counter_expected.current() == 0) ? 1 : (session.recv_counter_expected.current() % 255) + 1;
        if (received_header.sender_counter != expected_data_sc) {
            LOG_WARN(log_prefix_base + " - DATA Out-of-Order! Expected ClientSC=" + std::to_string(expected_data_sc) +
                     ", Got=" + std::to_string(received_header.sender_counter) + ". BaseExpected=" + std::to_string(session.recv_counter_expected.current()) + ". Dropping.");
            return;
        }
        session.recv_counter_expected.set(received_header.sender_counter);
    } else if (received_header.type == PACKET_TYPE_AUTH_REQ) {
        if (received_header.sender_counter != 1) { // First packet of AUTH_REQ sequence from client must be SC=1
            LOG_WARN(log_prefix_base + " - AUTH_REQ received with ClientSC=" + std::to_string(received_header.sender_counter) + " (expected 1). Processing, but might indicate client counter issue.");
            // Proceeding, but client's counter logic should ensure SC=1 for AUTH_REQ.
        }
        session.recv_counter_expected.set(received_header.sender_counter); // This will be 1 (or what client sent)
    }


    if (received_header.type == PACKET_TYPE_AUTH_REQ) {
        // server_auth_idx_used_for_auth_req_str is already set
        LOG_INFO(log_prefix_base + " - Processing AUTH_REQ payload (decrypted with SrvAuthKeyIdx " + server_auth_idx_used_for_auth_req_str + ").");
        try {
            size_t current_offset = 0;
            if (decrypted_payload.empty()) throw std::runtime_error("Empty auth payload post-decryption");

            uint8_t username_len = decrypted_payload.at(current_offset); current_offset++;
            if (current_offset + username_len > decrypted_payload.size()) throw std::runtime_error("Username OOB");
            std::vector<uint8_t> username(decrypted_payload.begin() + current_offset, decrypted_payload.begin() + current_offset + username_len);
            current_offset += username_len;

            if (current_offset >= decrypted_payload.size()) throw std::runtime_error("Password len missing");
            uint8_t password_len = decrypted_payload.at(current_offset); current_offset++;
            if (current_offset + password_len > decrypted_payload.size()) throw std::runtime_error("Password OOB");
            std::vector<uint8_t> password(decrypted_payload.begin() + current_offset, decrypted_payload.begin() + current_offset + password_len);
            current_offset += password_len;

            if (current_offset != decrypted_payload.size()) {
                 LOG_ERROR(log_prefix_base + " - Malformed AUTH_REQ: length mismatch. ExpectedParsed=" +
                           std::to_string(current_offset) + ", ActualPayload=" + std::to_string(decrypted_payload.size()));
                send_auth_fail_response(session, "Malformed Auth Req (Length)", server_auth_idx_used_for_auth_req_str);
                return;
            }
            // LOG_DEBUG(log_prefix_base + " - Auth attempt: User='" + std::string(username.begin(), username.end()) + "'");

            if (username == USERNAME && password == PASSWORD) {
                LOG_INFO(log_prefix_base + " - Credentials VALID.");
                session.server_session_nonce = generate_random_bytes(SESSION_NONCE_LEN);
                if (session.server_session_nonce.empty()) {
                    LOG_ERROR(log_prefix_base + " - Failed to generate server session nonce.");
                    send_auth_fail_response(session, "Server Internal Error (NonceGen)", server_auth_idx_used_for_auth_req_str);
                    return;
                }

                // Key used for AUTH_REQ decryption (key_for_decryption) IS the current server rotating key.
                session.session_key = derive_key_hkdf(key_for_decryption, session.server_session_nonce, {'v','p','n','_','s','e','s','s','i','o','n','_','k','e','y'});
                if (session.session_key.empty()) {
                    LOG_ERROR(log_prefix_base + " - Session key derivation failed.");
                    send_auth_fail_response(session, "Server Key Derivation Error", server_auth_idx_used_for_auth_req_str);
                    return;
                }
                session.last_auth_key_idx_used_by_server = server_auth_idx_used_for_auth_req_str; // Store which key worked
                LOG_INFO(log_prefix_base + " - Session key derived using SrvAuthKeyIdx=" + session.last_auth_key_idx_used_by_server +
                         ". SK ends: ..." + (session.session_key.size() > 8 ? bytes_to_hex(session.session_key).substr(bytes_to_hex(session.session_key).length()-8) : "N/A"));

                session.send_counter.set(0); // Server's SC for AUTH_RESP_OK will be 1

                // Send AUTH_RESP_OK encrypted with the same AuthKey used for AUTH_REQ decryption
                if (send_packet_to_client(session, PACKET_TYPE_AUTH_RESP_OK, session.server_session_nonce, false, server_auth_idx_used_for_auth_req_str)) {
                    session.authenticated = true;
                    session.recv_counter_expected.set(0); // Next DATA from client must start with SC=1
                    LOG_INFO(log_prefix_base + " - Client " + client_addr_key_str + " AUTHENTICATED (SrvAuthKeyIdx " + server_auth_idx_used_for_auth_req_str + ").");
                    rotate_server_auth_key_idx(); // Server now rotates its key for the *next entirely new* client authentication.
                } else {
                    LOG_ERROR(log_prefix_base + " - Failed to send AUTH_RESP_OK.");
                    session.reset_for_reauth(); // If send fails, treat as failed auth overall for this attempt.
                }
            } else {
                LOG_WARN(log_prefix_base + " - Client " + client_addr_key_str + " Auth FAILED (Bad Credentials).");
                send_auth_fail_response(session, "Auth Failed (Credentials)", server_auth_idx_used_for_auth_req_str);
            }
        } catch (const std::out_of_range& oor) {
            LOG_ERROR(log_prefix_base + " - Malformed AUTH_REQ (OOR parsing payload): " + oor.what());
            send_auth_fail_response(session, "Malformed Auth Req (OOR)", server_auth_idx_used_for_auth_req_str);
        } catch (const std::runtime_error& re) {
            LOG_ERROR(log_prefix_base + " - Malformed AUTH_REQ (Runtime error parsing): " + re.what());
            send_auth_fail_response(session, "Malformed Auth Req (RE)", server_auth_idx_used_for_auth_req_str);
        } catch (const std::exception& e) {
            LOG_ERROR(log_prefix_base + " - Unexpected error processing AUTH_REQ payload: " + std::string(e.what()));
            send_auth_fail_response(session, "Server Error During Auth Processing", server_auth_idx_used_for_auth_req_str);
        }

    } else if (received_header.type == PACKET_TYPE_DATA) {
        if (session.authenticated) {
            if (global_tun_fd != -1) {
                ssize_t written_bytes = tun_write(global_tun_fd, decrypted_payload);
                if (written_bytes < 0) {
                    LOG_ERROR(log_prefix_base + " - Failed to write " + std::to_string(decrypted_payload.size()) + "B to TUN.");
                }
            } else {
                LOG_WARN(log_prefix_base + " - Global TUN FD not ready. Cannot write " + std::to_string(decrypted_payload.size()) + "B to TUN.");
            }
        } else {
            LOG_WARN(log_prefix_base + " - Internal Error: DATA packet processed but session not marked authenticated. Dropping.");
        }
    } else if (received_header.type == PACKET_TYPE_AUTH_RESP_OK || received_header.type == PACKET_TYPE_AUTH_RESP_FAIL) {
        LOG_WARN(log_prefix_base + " - Server received an Auth Response PType from client. Unexpected. Ignoring.");
    } else {
        LOG_WARN(log_prefix_base + " - Unknown packet type after decryption: " + std::to_string(received_header.type) + ". Ignoring payload.");
    }
}

void tun_to_udp_loop() {
    LOG_INFO("Server TUN->UDP: Thread started for TUN " + global_tun_iface_name);
    std::vector<uint8_t> tun_buffer;
    tun_buffer.reserve(2048);

    while (running && global_tun_fd != -1) {
        tun_buffer.assign(tun_buffer.capacity(), 0);
        ssize_t nread = read(global_tun_fd, tun_buffer.data(), tun_buffer.capacity());

        if (!running) { LOG_INFO("Server TUN->UDP: Shutdown signal. Exiting loop."); break;}

        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                 std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Shorter sleep for non-blocking
                 continue;
            }
            LOG_ERROR("Server TUN->UDP: Error reading from TUN " + global_tun_iface_name + ". Error: " + strerror(errno) + ". Thread exiting.");
            running = 0; // Critical TUN failure, signal main to stop.
            break;
        }
        if (nread == 0) { // EOF on TUN, or TUN closed.
            LOG_WARN("Server TUN->UDP: Read 0 bytes (EOF?) from TUN " + global_tun_iface_name + ". Assuming TUN closed. Thread exiting.");
            running = 0;
            break;
        }

        tun_buffer.resize(nread);
        // LOG_DEBUG("Server TUN->UDP: Read " + std::to_string(nread) + "B from TUN.");

        ClientSession* target_session_ptr = nullptr;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            for (auto& pair : client_sessions) {
                if (pair.second.authenticated) { // Simplistic: pick first authenticated.
                    target_session_ptr = &pair.second;
                    break;
                }
            }
        }

        if (target_session_ptr) {
            // LOG_DEBUG("Server TUN->UDP: Forwarding " + std::to_string(tun_buffer.size()) + "B from TUN to " + target_session_ptr->client_addr_str_key);
            if(!send_packet_to_client(*target_session_ptr, PACKET_TYPE_DATA, tun_buffer, true)){
                LOG_WARN("Server TUN->UDP: Failed to send DATA packet to " + target_session_ptr->client_addr_str_key + ". Client session might be problematic.");
                // Optionally, mark this client session as unauthenticated or remove it if send fails repeatedly
            }
        } else {
            // LOG_DEBUG("Server TUN->UDP: No authenticated client. Dropping " + std::to_string(tun_buffer.size()) + "B from TUN.");
        }
    }
    LOG_INFO("Server TUN->UDP: Thread finished.");
}

int main(int argc, char *argv[]) {
    std::string arg_log_level = "INFO";
    if (argc > 1) {
        arg_log_level = argv[1];
        std::transform(arg_log_level.begin(), arg_log_level.end(), arg_log_level.begin(),
                       [](unsigned char c){ return std::toupper(c); });
    }
    if (arg_log_level == "DEBUG") CURRENT_LOG_LEVEL = LogLevel::DEBUG;
    else if (arg_log_level == "INFO") CURRENT_LOG_LEVEL = LogLevel::INFO;
    else if (arg_log_level == "WARNING") CURRENT_LOG_LEVEL = LogLevel::WARNING;
    else if (arg_log_level == "ERROR") CURRENT_LOG_LEVEL = LogLevel::ERROR;
    else { LOG_WARN("Main: Unknown log level '" + arg_log_level + "'. Defaulting to INFO."); CURRENT_LOG_LEVEL = LogLevel::INFO; }
    LOG_INFO("Main: Log level set to " + arg_log_level);

    try {
        initialize_rotating_keys();
    } catch (const std::runtime_error& e) {
        LOG_ERROR("Main CRITICAL: Failed to initialize/verify rotating keys: " + std::string(e.what()));
        return 1;
    }
    int initial_auth_key_idx_val;
    get_server_current_rotating_auth_key(initial_auth_key_idx_val); // To log current index correctly after init
    LOG_INFO("Main: Server initialized with " + std::to_string(ROTATING_AUTH_KEYS.size()) +
             " Auth Keys. Current index (for new auth): " + std::to_string(initial_auth_key_idx_val));

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    global_tun_iface_name = SERVER_TUN_IFACE_PREF;
    global_tun_fd = tun_alloc(global_tun_iface_name);
    if (global_tun_fd < 0) {
        LOG_ERROR("Main: Failed to allocate TUN interface. Exiting.");
        return 1;
    }
    // Set TUN to non-blocking for more responsive TUN reader loop
    // int tun_flags = fcntl(global_tun_fd, F_GETFL, 0);
    // if (tun_flags != -1 && fcntl(global_tun_fd, F_SETFL, tun_flags | O_NONBLOCK) != -1) {
    //     LOG_INFO("Main: Set TUN " + global_tun_iface_name + " to non-blocking.");
    // } else {
    //     LOG_WARN("Main: Could not set TUN fd to non-blocking: " + std::string(strerror(errno)) + ". Read may block longer.");
    // }

    if (!configure_tun_iface(global_tun_iface_name, SERVER_TUN_IP)) {
        LOG_ERROR("Main: Failed to configure TUN interface " + global_tun_iface_name + ". Exiting.");
        if (global_tun_fd !=-1) { close(global_tun_fd); global_tun_fd = -1;}
        return 1;
    }
    LOG_INFO("Main: TUN interface " + global_tun_iface_name + " ready on " + SERVER_TUN_IP);

    server_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock_fd < 0) {
        LOG_ERROR("Main: Failed to create UDP socket: " + std::string(strerror(errno)));
        if (global_tun_fd !=-1) { close(global_tun_fd); global_tun_fd = -1; }
        return 1;
    }

    sockaddr_in server_addr_bind_struct;
    memset(&server_addr_bind_struct, 0, sizeof(server_addr_bind_struct));
    server_addr_bind_struct.sin_family = AF_INET;
    server_addr_bind_struct.sin_port = htons(SERVER_PORT);
    server_addr_bind_struct.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock_fd, (struct sockaddr*)&server_addr_bind_struct, sizeof(server_addr_bind_struct)) < 0) {
        LOG_ERROR("Main: Failed to bind UDP socket to 0.0.0.0:" + std::to_string(SERVER_PORT) + ": " + std::string(strerror(errno)));
        if(server_sock_fd !=-1) {close(server_sock_fd); server_sock_fd = -1;}
        if (global_tun_fd !=-1) {close(global_tun_fd); global_tun_fd = -1;}
        return 1;
    }
    LOG_INFO("Main: UDP Server listening on 0.0.0.0:" + std::to_string(SERVER_PORT));

    struct timeval tv_sock_timeout_main;
    tv_sock_timeout_main.tv_sec = 1;
    tv_sock_timeout_main.tv_usec = 0;
    if (setsockopt(server_sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_sock_timeout_main, sizeof tv_sock_timeout_main) < 0) {
        LOG_WARN("Main: Failed to set UDP socket SO_RCVTIMEO: " + std::string(strerror(errno)) + ". recvfrom may block longer than 1s.");
    }

    std::thread tun_reader_thread_obj(tun_to_udp_loop);

    std::vector<uint8_t> recv_buffer_main_loop(2048);
    sockaddr_in client_addr_sock_struct_recv_loop;
    socklen_t client_addr_len_loop = sizeof(client_addr_sock_struct_recv_loop);

    LOG_INFO("Main: Entering UDP receive loop.");
    while (running) {
        ssize_t nbytes = recvfrom(server_sock_fd, recv_buffer_main_loop.data(), recv_buffer_main_loop.size(), 0,
                                  (struct sockaddr*)&client_addr_sock_struct_recv_loop, &client_addr_len_loop);

        if (!running) { LOG_INFO("Main: Shutdown signal detected in UDP recv loop."); break; }

        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // LOG_DEBUG("Main: UDP Socket timeout.");
                // TODO: Periodic session cleanup based on last_active_time
            } else if (errno == EINTR) {
                 LOG_INFO("Main: UDP recvfrom interrupted by signal. Continuing.");
            } else if (errno == EBADF && !running) { // Socket closed by signal handler
                 LOG_INFO("Main: UDP recvfrom reported EBADF, socket likely closed for shutdown.");
            }
            else {
                 LOG_ERROR("Main: UDP recvfrom error: " + std::string(strerror(errno)) + " (errno: " + std::to_string(errno) + ")");
                 if (errno == EBADF) { running = 0; } // If socket is bad, can't continue.
            }
            continue;
        }

        if (nbytes == 0) {
            LOG_WARN("Main: UDP Received 0 bytes (unexpected). Ignoring.");
            continue;
        }

        char client_ip_cstr_resolved[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr_sock_struct_recv_loop.sin_addr), client_ip_cstr_resolved, INET_ADDRSTRLEN);
        std::string client_ip_str_from_recv(client_ip_cstr_resolved);
        int client_port_from_recv = ntohs(client_addr_sock_struct_recv_loop.sin_port);
        std::string client_map_key_str = client_ip_str_from_recv + ":" + std::to_string(client_port_from_recv);

        // LOG_DEBUG("Main: UDP Received " + std::to_string(nbytes) + "B from " + client_map_key_str);

        std::vector<uint8_t> received_data_for_pkt_handler(recv_buffer_main_loop.begin(), recv_buffer_main_loop.begin() + nbytes);
        handle_received_packet(received_data_for_pkt_handler, client_addr_sock_struct_recv_loop, client_map_key_str);
    }

    LOG_INFO("Main: UDP loop finished. Waiting for TUN reader thread to join...");
    // running is already 0 or will be set.
    // Closing global_tun_fd *before* join can help unblock read() if tun_to_udp_loop is stuck there.
    if (global_tun_fd != -1) {
        LOG_INFO("Main: Closing global TUN FD (" + std::to_string(global_tun_fd) + ") to ensure TUN reader thread can exit.");
        if (close(global_tun_fd) == -1) {
            LOG_ERROR("Main: Error closing global_tun_fd: " + std::string(strerror(errno)));
        }
        global_tun_fd = -1; // Mark as closed
    }
    if (tun_reader_thread_obj.joinable()) {
        tun_reader_thread_obj.join();
        LOG_INFO("Main: TUN reader thread joined.");
    } else {
        LOG_WARN("Main: TUN reader thread was not joinable.");
    }

    LOG_INFO("Main: Shutting down remaining server resources.");
    if (server_sock_fd != -1) {
        if (close(server_sock_fd) == -1) {
            LOG_ERROR("Main: Error closing server_sock_fd: " + std::string(strerror(errno)));
        }
        server_sock_fd = -1;
    }

    { // Clear sessions map
        std::lock_guard<std::mutex> lock(sessions_mutex);
        LOG_INFO("Main: Clearing " + std::to_string(client_sessions.size()) + " client sessions.");
        client_sessions.clear();
    }

    LOG_INFO("Main: Server shutdown sequence complete.");
    return 0;
}