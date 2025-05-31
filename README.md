# server
project
sudo apt update
sudo apt install -y g++ make libssl-dev 
make
sudo sysctl -w net.ipv4.ip_forward=1
# And make it persistent in /etc/sysctl.conf
Create a service file:
Open a new file for your service unit using a text editor (like nano or vim):
sudo nano /etc/systemd/system/vpn_server.service
[Unit]
Description=My Custom VPN Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root  # Or a dedicated non-root user if you adjust permissions/capabilities
Group=root # Or a dedicated group
WorkingDirectory=/root/vpn_server # CHANGE THIS to the actual path of your server files
ExecStart=/root/vpn_server/server INFO # CHANGE THIS to the actual path and desired log level
Restart=on-failure
RestartSec=5s
StandardOutput=journal # Logs to systemd journal
StandardError=journal  # Logs to systemd journalsudo systemctl enable vpn_server.service

[Install]
WantedBy=multi-user.target
sudo systemctl daemon-reload
sudo systemctl enable vpn_server.service
sudo systemctl start vpn_server.service
sudo systemctl status vpn_server.service

sudo journalctl -u vpn_server.service
# To follow logs in real-time:
sudo journalctl -f -u vpn_server.service

sudo systemctl stop vpn_server.service
sudo systemctl restart vpn_server.service

