declare -a examples=(
	"assignments"
	"cidr"
	"config_options"
	"conntrack_with_timeout_assignments"
    "conntrack_with_timeout"
    "conntrack"
	"functions"
	"gateway_with_forward_chain"
	"gateway_with_send_time_exceeded"
	"iface_ip6"
	"iface_with_limits"
    "iface_without_network_configuration"
	"iface"
	"lb_assignment_functionality_2"
    "lb_assignment_functionality"
    "lb_with_tls_termination"
    "lb_with_uplink"
    "lb"
	"log"
	"nacl_one_liner"
	"nacl"
	"nat_and_gateway"
	"syslog"
	"timers"
    "vlan_routing"
    "vlan_with_mac"
    "vlan"
)

for i in "${examples[@]}"
do
	cat examples/$i.nacl | ./NaCl.py goldenfiles/$i.cpp
done
