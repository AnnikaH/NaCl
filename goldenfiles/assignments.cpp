#include <iostream>
#include <net/inet4>
#include <net/ip4/cidr.hpp>
#include <plugins/nacl.hpp>
#include <net/router.hpp>
#include <net/vlan>

using namespace net;

std::unique_ptr<Router<IP4>> nacl_router_obj;
std::shared_ptr<Conntrack> nacl_ct_obj;

namespace custom_made_classes_from_nacl {

class Another_Filter : public nacl::Filter {
public:
	Filter_verdict operator()(IP4::IP_packet& pckt, Inet<IP4>& stack, Conntrack::Entry_ptr ct_entry) {
		if (not ct_entry) {
return Filter_verdict::DROP;
}
return Filter_verdict::ACCEPT;

	}
};

class Eth0_Filter : public nacl::Filter {
public:
	Filter_verdict operator()(IP4::IP_packet& pckt, Inet<IP4>& stack, Conntrack::Entry_ptr ct_entry) {
		if (not ct_entry) {
return Filter_verdict::DROP;
}
return Filter_verdict::DROP;

	}
};

} //< namespace custom_made_classes_from_nacl

void register_plugin_nacl() {
	INFO("NaCl", "Registering NaCl plugin");

	auto& eth1 = Inet4::stack<1>();
	Inet4::ifconfig<1>(10.0, [&eth1] (bool timedout) {
		if (timedout) {
			INFO("NaCl plugin interface eth1", "DHCP request timed out. Nothing to do.");
			return;
		}
		INFO("NaCl plugin interface eth1", "IP address updated: %s", eth1.ip_addr().str().c_str());
	});
	auto& eth0 = Inet4::stack<0>();
	eth0.network_config(IP4::addr{10,0,0,45}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1}, IP4::addr{8,8,8,8});

	// For each iface:
	auto& eth0_nic = eth0.nic();
	auto& eth0_manager = VLAN_manager::get(0);
	// For each vlan connected to this iface:
	Super_stack::inet().create<IP4>(eth0_manager.add(eth0_nic, 13), 0, 13).network_config(IP4::addr{20,20,20,10}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1});

	custom_made_classes_from_nacl::Another_Filter another_filter;
	custom_made_classes_from_nacl::Eth0_Filter eth0_filter;

	eth1.ip_obj().input_chain().chain.push_back(another_filter);

	eth0.ip_obj().prerouting_chain().chain.push_back(eth0_filter);

	// Router

	INFO("NaCl", "Setup routing");
	Router<IP4>::Routing_table routing_table {
		{ IP4::addr{10,0,0,0}, IP4::addr{255,255,255,0}, 0, eth0, 100 },
		{ IP4::addr{10,20,30,0}, IP4::addr{255,255,255,0}, 0, eth1, 50 }
	};
	nacl_router_obj = std::make_unique<Router<IP4>>(routing_table);
	// Set ip forwarding on every iface mentioned in routing_table
	eth0.set_forward_delg(nacl_router_obj->forward_delg());
	eth1.set_forward_delg(nacl_router_obj->forward_delg());

	// Ct

	nacl_ct_obj = std::make_shared<Conntrack>();
	
	nacl_ct_obj->reserve(10000);

	INFO("NaCl", "Enabling Conntrack on eth0");
	eth0.enable_conntrack(nacl_ct_obj);

	INFO("NaCl", "Enabling Conntrack on eth1");
	eth1.enable_conntrack(nacl_ct_obj);
}