#ifndef TUN_UTILS_HPP
#define TUN_UTILS_HPP

#include <string>
#include <vector>

// TUN/TAP constants (Linux specific)
#define TUN_DEV "/dev/net/tun"

// Function to allocate TUN interface
// Returns fd of the TUN interface, or -1 on error.
// if_name will be populated with the actual interface name (e.g., "tun0")
int tun_alloc(std::string& if_name_out);

// Function to configure the TUN interface (IP, up, etc.)
// Uses system calls to `ip` command for simplicity.
bool configure_tun_iface(const std::string& if_name, const std::string& ip_addr_with_prefix);

// Function to read from TUN interface
// Returns number of bytes read, or -1 on error, 0 on EOF (should not happen for TUN)
ssize_t tun_read(int tun_fd, std::vector<uint8_t>& buffer);

// Function to write to TUN interface
// Returns number of bytes written, or -1 on error
ssize_t tun_write(int tun_fd, const std::vector<uint8_t>& data);

#endif // TUN_UTILS_HPP