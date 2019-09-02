#! /bin/bash

# Creates an OpenVPN Server. Tested on:
# Ubuntu 16.04 and Ubuntu 18.04
# Debian 8, Debian 9, and Debian 10
# Arch
# Manjaro 18.0.4
# SUSE 15
# openSUSE
# FreeBSD

# Check that the script is being run with root privileges
if [ "$EUID" -ne 0 ]; then
	echo "Please run with root privileges"
	exit 1
fi

# Set the setup directory
setupDirectory=~/openvpn-ca

# Check the OS version
checkOperatingSystem(){
	if [ -f /etc/os-release ]; then
		# Modern versions of Debian, Ubuntu, CentOS, RHEL, and openSUSE all use /etc/os-release
		. /etc/os-release
		if grep -q "ID_LIKE" /etc/os-release; then
			OS=$ID_LIKE
		else
			OS=$ID
		fi
	else
		# Fallback for BSD
		OS=$(uname -s)
	fi
	OS = $(echo $OS | cut -d ' ' -f)
}

# Install OpenVPN and EasyRSA for Debian and Debian-like operating systems
installOpenVpnAndEasyRsaDebian(){

	# Update package list to pick up new repository's package information
	apt update

	# Install openvpn
	apt install -y openvpn easy-rsa

	# Create the setup directory
	make-cadir $setupDirectory

	# Change to the setup directory
	cd $setupDirectory
}

# Install OpenVPN and EasyRSA for Fedora and Fedora-like operating systems
installOpenVpnAndEasyFedora(){

	# CentOS requires the Extra Packages for Enterprise Linux repository for the openvpn and easy-rsa packages
	if [ "$ID" = "centos" ]; then
		yum install -y epel-release
	fi

	# Update package list to pick up new repository's package information
	yum check-update

	# Install openvpn
	yum install -y openvpn easy-rsa

	# Create the setup directory
	make-cadir $setupDirectory

	# Change to the setup directory
	cd $setupDirectory
}

# Install OpenVPN and EasyRSA for SUSE and openSUSE operating systems
installOpenVpnAndEasyRsaSuse(){

	# Update package list to pick up new repository's package information
	zypper refresh

	# Install openvpn
	zypper install -y openvpn easy-rsa

	# Create the setup directory
	make-cadir $setupDirectory

	# Change to the setup directory
	cd $setupDirectory
}

# Install OpenVPN and EasyRSA for Arch and Arch-like operating systems
installOpenVpnAndEasyRsaArch(){

	# Update package list to pick up new repository's package information
	pacman -Sy

	# Install openvpn
	pacman -S --noconfirm openvpn easy-rsa

	# Create the setup directory
	make-cadir $setupDirectory

	# Change to the setup directory
	cd $setupDirectory
}

# Install OpenVPN and EasyRSA for FreeBSD
installOpenVpnAndEasyEsaBsd(){

	# Update package list to pick up new repository's package informatiion
	pkg update

	# Install openvpn
	pkg install -y openvpn easy-rsa

	# Create the setup directory
	make-cadir $setupDirectory

	# Change to the setup directory
	cd $setupDirectory
}

# Configure the EasyRSA Variables and Build the Certificate Authority
configureEasyRsaAndBuildTheCa(){

	# Create a link for Ubuntu 18
	ln -s $setupDirectory/openssl-1.0.0.cnf $setupDirectory/openssl.cnf

	# Change values
	sed -i 's/export KEY_COUNTRY="US"/export KEY_COUNTRY="US"/g' $setupDirectory/vars
	sed -i 's/export KEY_PROVINCE="CA"/export KEY_PROVINCE="CA"/g' $setupDirectory/vars
	sed -i 's/export KEY_CITY="SanFrancisco"/export KEY_CITY="City"/g' $setupDirectory/vars
	sed -i 's/export KEY_ORG="Fort-Funston"/export KEY_ORG="Organization"/g' $setupDirectory/vars
	sed -i 's/export KEY_EMAIL="me@myhost.mydomain"/export KEY_EMAIL="me@myhost.mydomain"/g' $setupDirectory/vars
	sed -i 's/export KEY_OU="MyOrganizationalUnit"/export KEY_OU="OrganizationalUnit"/g' $setupDirectory/vars
	sed -i 's/export KEY_NAME="EasyRSA"/export KEY_NAME="server"/g' $setupDirectory/vars

	# Load changes
	source vars

	# Clean the environment
	./clean-all

	# Build the CA certificate
	yes "" | ./build-ca
}

# Create the Server Certificate, Key, and Encryption Files
createServerCertificateKeyAndEncryptionFiles(){

	# Generate the server certificate and key pair
	(echo -en "\n\n\n\n\n\n\n\n\n\n"; sleep 1; echo -en "y\n"; sleep 1; echo -en "y\n") | ./build-key-server server

	# Generate the Diffie-Hellman parameters
	./build-dh

	# Generate an HMAC signature to strengthen the server's TLS integrity verification capabilities
	openvpn --genkey --secret $setupDirectory/keys/ta.key
}

# Generate a Client Certificate and Key Pair
generateClientCertificateAndKeyPair(){

	# Load changes
	source vars

	# Generate the client certificate and key pair
	(echo -en "\n\n\n\n\n\n\n\n\n\n"; sleep 1; echo -en "y\n"; sleep 1; echo -en "y\n") | ./build-key client1

	# Change to the keys folder
	cd $setupDirectory/keys

	# Copy the files
	cp ca.crt server.crt server.key ta.key dh2048.pem /etc/openvpn/
}

# Configure the OpenVPN Service
configureTheOpenVpnService(){

	# Extract the config files
	gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > /etc/openvpn/server.conf

	# Update the server configuration
	sed -i "s/tls-auth ta.key 0 # This file is secret/tls-auth ta.key 0 # This file is secret\nkey-direction 0/g" /etc/openvpn/server.conf
	sed -i "s/;tls-auth ta.key 0/tls-auth ta.key 0/g" /etc/openvpn/server.conf
	sed -i "s/;cipher AES-128-CBC/cipher AES-256-CBC/g" /etc/openvpn/server.conf
	sed -i "s/cipher AES-256-CBC/cipher AES-256-CBC\nauth SHA256/g" /etc/openvpn/server.conf

	# Update the server configuration
	sed -i "s/;user nobody/user nobody/g" /etc/openvpn/server.conf
	sed -i "s/;group nogroup/group nogroup/g" /etc/openvpn/server.conf

	# Push DNS Changes to Redirect All Traffic Through the VPN
	sed -i 's/;push "redirect-gateway def1 bypass-dhcp"/push "redirect-gateway def1 bypass-dhcp"/g' /etc/openvpn/server.conf
	sed -i 's/;push "dhcp-option DNS 208.67.222.222"/push "dhcp-option DNS 208.67.222.222"/g' /etc/openvpn/server.conf
	sed -i 's/;push "dhcp-option DNS 208.67.220.220"/push "dhcp-option DNS 208.67.220.220"/g' /etc/openvpn/server.conf
}

# Adjust the Server Networking Configuration
adjustTheServerNetworkingConfiguration(){

	# Allow IP forwarding
	sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" /etc/sysctl.conf

	# Read the file and adjust the value for the current session
	sysctl -p
}

# Start and Enable the OpenVPN Service on Linux
startAndEnableTheOpenVpnServiceLinux(){

	# Config file has the word server in it so use that in the command /etc/openvpn/server.conf
	systemctl start openvpn@server

	# Check that the service has started with: "systemctl status openvpn@server"
	# Check OpenVPN tun0 interface with: "ip addr show tun0"

	# Enable on boot
	systemctl enable openvpn@server
}

# Start and Enable the OpenVPN Service on FreeBSD
startAndEnableTheOpenVpnServiceBsd(){
	# Start openvpn service
	service start openvpn

	# Enable openvpn to start on boot as a tun device
	sysrc openvpn_enable="YES"
	sysrc openvpn_if="tun"
}

# Create the Client Configuration Infrastructure
createDirectoryStructureToStoreFiles(){

	# Create a directory structure within your home directory to store the files
	mkdir -p $setupDirectory/client-configs/files

	# Copy an example client configuration into the directory to use as a base configuration
	cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf $setupDirectory/client-configs/base.conf

	# Get the server's IP address
	ip=$(hostname -I | cut -d " " -f 1)

	# Set the server's IP in the config file
	sed -i "s/remote my-server-1 1194/remote $ip 1194/g" $setupDirectory/client-configs/base.conf

	# Uncomment user and group directives
	sed -i "s/;user nobody/user nobody/g" $setupDirectory/client-configs/base.conf
	sed -i "s/;group nogroup/group nogroup/g" $setupDirectory/client-configs/base.conf

	# Comment out these directives since the certs and keys will be added within the file itself
	sed -i "s/ca ca.crt/#ca ca.crt/g" $setupDirectory/client-configs/base.conf
	sed -i "s/cert client.crt/#cert client.crt/g" $setupDirectory/client-configs/base.conf
	sed -i "s/key client.key/#key client.key/g" $setupDirectory/client-configs/base.conf

	# Mirror the cipher and auth settings that were set in the /etc/openvpn/server.conf file
	sed -i "s/;remote my-server-2 1194/;remote my-server-2 1194\n\ncipher AES-256-CBC\nauth SHA256\n\nkey-direction 1\n\n# script-security 2\n# up \/etc\/openvpn\/update-resolv-conf\n# down \/etc\/openvpn\/update-resolv-conf/g" $setupDirectory/client-configs/base.conf

	# Create a configuration generation script
	echo "#! /bin/bash" > $setupDirectory/client-configs/make_config.sh
	echo "# First argument: Client identifier" >> $setupDirectory/client-configs/make_config.sh
	echo "KEY_DIR=$setupDirectory/keys" >> $setupDirectory/client-configs/make_config.sh
	echo "OUTPUT_DIR=$setupDirectory/client-configs/files" >> $setupDirectory/client-configs/make_config.sh
	echo "BASE_CONFIG=$setupDirectory/client-configs/base.conf" >> $setupDirectory/client-configs/make_config.sh
	echo "cat \${BASE_CONFIG} \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "<(echo -e '<ca>') \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "\${KEY_DIR}/ca.crt \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "<(echo -e '</ca>\n<cert>') \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "\${KEY_DIR}/\${1}.crt \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "<(echo -e '</cert>\n<key>') \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "\${KEY_DIR}/\${1}.key \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "<(echo -e '</key>\n<tls-auth>') \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "\${KEY_DIR}/ta.key \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "<(echo -e '</tls-auth>') \\" >> $setupDirectory/client-configs/make_config.sh
	echo     "> \${OUTPUT_DIR}/\${1}.ovpn" >> $setupDirectory/client-configs/make_config.sh

	# Lock down permissions and make "make_config.sh" executable
	chmod -R 700 $setupDirectory/client-configs
}

# Generate the Client Configuration
generateClientConfigurationFile(){

	# Change to the client-configs directory
	cd $setupDirectory/client-configs

	# Make the client configuration file
	$setupDirectory/client-configs/make_config.sh client1

	# Move the client configuration file
	mv $setupDirectory/client-configs/files/client1.ovpn ~/client1.ovpn
}

# Enable UFW
enableUfw(){

	# Update the UFW configuration
	sed -i "s/#   ufw-before-forward/#   ufw-before-forward\n\n# START OPENVPN RULES\n# NAT table rules\n*nat\n:POSTROUTING ACCEPT [0:0] \n# Allow traffic from OpenVPN client to eth0\n-A POSTROUTING -s 10.8.0.0\/8 -o eth0 -j MASQUERADE\nCOMMIT\n# END OPENVPN RULES/g" /etc/ufw/before.rules

	# Allow forwarded packets by default
	sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw

	# Allow 1194 and 22
	ufw allow 1194/udp
	ufw allow 22/tcp

	# Disable and re-enable UFW to load the changes
	ufw disable

	# Enable ufw
	yes "y" | ufw enable
}

# Enable Iptables to Forward Traffic
enableIptables(){

	# Allow the tcp connection on the openvpn port
	iptables -A INPUT -i eth0 -m state --state NEW -p udp --dport 1194 -j ACCEPT

	# Allow TUN interface connections to the OpenVPN server
	iptables -A INPUT -i tun+ -j ACCEPT

	# Allow TUN interface connections to be forwarded through other interfaces
	iptables -A FORWARD -i tun+ -j ACCEPT
	iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

	# NAT the VPN client traffic to the Internet
	iptables -t nat -A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE

	# Set the iptables OUTPUT value to ACCEPT
	iptables -A OUTPUT -o tun+ -j ACCEPT
}

if [ "OS" = "debian" ]; then
	installOpenVpnAndEasyRsaDebian
elif [ "OS" = "fedora" ]; then
	installOpenVpnAndEasyFedora
elif [ "OS" = "suse" ]; then
	installOpenVpnAndEasyRsaSuse
elif [ "OS" = "arch" ]; then
	installOpenVpnAndEasyRsaArch
else
	echo "Unsupported or unrecognized operating system. You're on your own!"
	exit 1

configureEasyRsaAndBuildTheCa
createServerCertificateKeyAndEncryptionFiles
generateClientCertificateAndKeyPair
configureTheOpenVpnService
adjustTheServerNetworkingConfiguration
startAndEnableTheOpenVpnService
createDirectoryStructureToStoreFiles
generateClientConfigurationFile

# Loop if the user does not enter anything
while true; do

	# Ask the user for the choice
	read -p "Do you want to enable ufw or iptables to route traffic? (ufw/iptables) " choice

	# Check if the user entered ufw
	if [ "$choice" == "ufw" ]; then

		# Enable UFW
		enableUfw

		# Stop looping
		break

	# Check if the user entered iptables
	elif [ "$choice" == "iptables" ]; then

		# Enable iptables
		enableIptables

		# Stop looping
		break
	fi
done