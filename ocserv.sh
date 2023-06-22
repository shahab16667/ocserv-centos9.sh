#!/bin/bash

# Check whether the root user
if [[ $(id -u) != "0" ]]; then
    printf "\e[42m\e[31mError: You must be root to run this install script.\e[0m\n"
    exit 1
fi

# Check whether CentOS 9 or RHEL 9 is detected
if [[ $(grep "release 9." /etc/redhat-release 2>/dev/null | wc -l) -eq 0 ]]; then
    printf "\e[42m\e[31mError: Your OS is NOT CentOS 9 or RHEL 9.\e[0m\n"
    printf "\e[42m\e[31mThis install script is ONLY for CentOS 9 and RHEL 9.\e[0m\n"
    exit 1
fi

basepath=$(dirname $0)
cd ${basepath}

function ConfigEnvironmentVariable {
    # Variable settings
    # Single IP maximum number of connections, the default is 2
    maxsameclients=4
    # The maximum number of connections, the default is 16
    maxclients=1024
    # Server certificate and key file, placed in the same directory with the script, the key file permissions should be 600 or 400
    servercert=${1-server-cert.pem}
    serverkey=${2-server-key.pem}
    # VPN Intranet IP segment
    vpnnetwork="172.16.24.0/24"
    # DNS
    dns1="8.8.8.8"
    dns2="8.8.4.4"
    # Configuration directory
    confdir="/etc/ocserv"

    # Obtain the network card interface name
    systemctl start NetworkManager.service
    ethlist=$(nmcli --nocheck d | grep -v -E "(^(DEVICE|lo)|unavailable|^[^e])" | awk '{print $1}')
    eth=$(printf "${ethlist}\n" | head -n 1)
    if [[ $(printf "${ethlist}\n" | wc -l) -gt 1 ]]; then
        echo ======================================
        echo "Network Interface list:"
        printf "\e[33m${ethlist}\e[0m\n"
        echo ======================================
        echo "Which network interface you want to listen for ocserv?"
        printf "Default network interface is \e[33m${eth}\e[0m, let it blank to use this network interface: "
        read ethtmp
        if [[ -n "${ethtmp}" ]]; then
            eth=${ethtmp}
        fi
    fi

    # Port, the default is 443
    port=443
    echo -e "\nPlease input the port ocserv listen to."
    printf "Default port is \e[33m${port}\e[0m, let it blank to use this port: "
    read porttmp
    if [[ -n "${porttmp}" ]]; then
        port=${porttmp}
    fi

    # User name, default is user
    username=user
    echo -e "\nPlease input ocserv user name."
    printf "Default user name is \e[33m${username}\e[0m, let it blank to use this user name: "
    read usernametmp
    if [[ -n "${usernametmp}" ]]; then
        username=${usernametmp}
    fi

    # Password, default is password
    password=password
    echo -e "\nPlease input ocserv user password."
    printf "Default password is \e[33m${password}\e[0m, let it blank to use this password: "
    read passwordtmp
    if [[ -n "${passwordtmp}" ]]; then
        password=${passwordtmp}
    fi

    # Check the network interface
    ipaddr=$(ip addr show dev ${eth} | grep "inet " | awk '{print $2}' | cut -d '/' -f 1)
    if [[ -z "${ipaddr}" ]]; then
        printf "\e[42m\e[31mError: Could not get the IP address of the network interface \`${eth}\`.\e[0m\n"
        exit 1
    fi

    # Display the configuration
    echo ======================================
    echo "ocserv Configuration:"
    echo -e "Server IP: \e[33m${ipaddr}\e[0m"
    echo -e "Network Interface: \e[33m${eth}\e[0m"
    echo -e "Port: \e[33m${port}\e[0m"
    echo -e "Username: \e[33m${username}\e[0m"
    echo -e "Password: \e[33m${password}\e[0m"
    echo -e "VPN IP Segment: \e[33m${vpnnetwork}\e[0m"
    echo -e "DNS: \e[33m${dns1} ${dns2}\e[0m"
    echo -e "Server Certificate: \e[33m${servercert}\e[0m"
    echo -e "Server Key: \e[33m${serverkey}\e[0m"
    echo ======================================
    printf "Press any key to start installation or press Ctrl+C to cancel."
    local tmp
    read -n 1 -s tmp
}

function InstallPackages {
    echo -e "\nInstalling ocserv and other required packages..."
    yum install -y epel-release
    yum install -y ocserv net-tools openssl gnutls-utils bind-utils
}

function GenerateSelfSignedCert {
    if [[ -f "${confdir}/${servercert}" && -f "${confdir}/${serverkey}" ]]; then
        echo -e "\nFound existing server certificate and key."
        return
    fi

    echo -e "\nGenerating self-signed server certificate and key..."
    certtool --generate-privkey --outfile "${serverkey}"
    echo -n "cn = \"" > cert.cfg
    read -p "Please enter the domain or IP address of your server: " servername
    echo "${servername}\"" >> cert.cfg
    echo "organization = \"OpenConnect VPN\"" >> cert.cfg
    echo "serial = 1" >> cert.cfg
    echo "expiration_days = 3650" >> cert.cfg
    echo "ca" > ca.info
    echo "cert_signing_key" >> ca.info
    certtool --generate-self-signed --load-privkey "${serverkey}" --template cert.cfg --outfile "${servercert}"
    rm -f cert.cfg ca.info
    mv "${servercert}" "${serverkey}" "${confdir}/"
    chmod 600 "${confdir}/${serverkey}"
}

function ConfigureOcserv {
    echo -e "\nConfiguring ocserv..."

    # Backup the original configuration file
    cp "${confdir}/ocserv.conf" "${confdir}/ocserv.conf.orig"

    # Set the ocserv.conf
    cat > "${confdir}/ocserv.conf" <<EOF
# ocserv.conf - Configuration file for OpenConnect SSL VPN server

# Run as daemon (default: no)
run-as-daemon = true

# Maximum number of simultaneous connections
max-clients = ${maxclients}

# Maximum number of clients that can connect from the same IP address (default: 2)
max-same-clients = ${maxsameclients}

# Server network settings
tcp-port = ${port}
udp-port = ${port}
listen-host = ${ipaddr}
default-domain = example.com
ipv4-network = ${vpnnetwork}
dns = ${dns1}
dns = ${dns2}

# Certificate and key files
server-cert = ${confdir}/${servercert}
server-key = ${confdir}/${serverkey}

# User authentication
auth = "plain[/etc/ocserv/ocpasswd]"

# Routing settings
route = default

# Output verbosity (0-9)
verbose = 0

# Logging settings
syslog = true
syslog-facility = daemon

# MTU size
mtu = 1400

# Setuid settings
setuid = nobody
setgid = nobody

# Ciphers
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-ARCFOUR-128"

# Disallow insecure SSL/TLS renegotiation
disallow-renegotiation = true
EOF

    # Configure ocserv password file
    echo "${username}:"$(openssl passwd -1 -salt "$(openssl rand -hex 4)" "${password}") > "${confdir}/ocpasswd"

    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-ocserv.conf
    sysctl -p /etc/sysctl.d/99-ocserv.conf

    # Configure firewall rules
    firewall-cmd --permanent --add-service={http,https} 2>/dev/null
    firewall-cmd --permanent --add-port=${port}/tcp 2>/dev/null
    firewall-cmd --permanent --add-port=${port}/udp 2>/dev/null
    firewall-cmd --reload 2>/dev/null
}

function StartOcserv {
    echo -e "\nStarting ocserv..."

    systemctl enable ocserv
    systemctl start ocserv

    sleep 2
    systemctl status ocserv --no-pager

    echo -e "\nOpenConnect VPN server has been started."
    echo -e "You can now connect to your VPN using the following settings:"
    echo -e "Server IP: \e[33m${ipaddr}\e[0m"
    echo -e "Port: \e[33m${port}\e[0m"
    echo -e "Username: \e[33m${username}\e[0m"
    echo -e "Password: \e[33m${password}\e[0m"
    echo -e "VPN IP Segment: \e[33m${vpnnetwork}\e[0m"
    echo -e "DNS: \e[33m${dns1} ${dns2}\e[0m"
}

function InstallCompleteMessage {
    echo -e "\nInstallation and configuration completed!"
    echo "Enjoy using OpenConnect VPN!"
}

# Main script execution
ConfigEnvironmentVariable
InstallPackages
GenerateSelfSignedCert
ConfigureOcserv
StartOcserv
InstallCompleteMessage
