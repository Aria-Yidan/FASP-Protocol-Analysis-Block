iptables -A FORWARD -o eth0 -i eth1 -s 192.168.163.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sysctl -p
modprobe nf_reject_ipv4

