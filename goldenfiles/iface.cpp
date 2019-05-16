// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2017-2018 IncludeOS AS, Oslo, Norway
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Autogenerated by NaCl

#include <iostream>
#include <net/interfaces>
#include <net/ip4/cidr.hpp>
#include <net/nat/napt.hpp>
#include <net/vlan_manager.hpp>
#include <syslogd>

using namespace net;

namespace nacl {
  class Filter {
  public:
	virtual Filter_verdict<IP4> operator()(IP4::IP_packet_ptr pckt, Inet& stack, Conntrack::Entry_ptr ct_entry) = 0;
	virtual ~Filter() {}
  };
}

std::shared_ptr<Conntrack> nacl_ct_obj;
std::unique_ptr<nat::NAPT> nacl_natty_obj;

namespace custom_made_classes_from_nacl {

class My_Filter : public nacl::Filter {
public:
	Filter_verdict<IP4> operator()(IP4::IP_packet_ptr pckt, Inet& stack, Conntrack::Entry_ptr ct_entry) {
		if (not ct_entry) {
return {nullptr, Filter_verdict_type::DROP};
}
return {std::move(pckt), Filter_verdict_type::ACCEPT};

	}
};

} //< namespace custom_made_classes_from_nacl

void register_plugin_nacl() {
	INFO("NaCl", "Registering NaCl plugin");

	// vlan my_other_vlan
	Interfaces::create(VLAN_manager::get(1).add(Interfaces::get_nic(1), 20), 1, 20);
	auto& my_other_vlan = Interfaces::get(1, 20);
	my_other_vlan.network_config(IP4::addr{10,20,10,10}, IP4::addr{255,255,255,0}, 0);
	// vlan my_vlan0
	Interfaces::create(VLAN_manager::get(0).add(Interfaces::get_nic(0), 10), 0, 10);
	auto& my_vlan0 = Interfaces::get(0, 10);
	my_vlan0.network_config(IP4::addr{10,10,10,10}, IP4::addr{255,255,255,0}, 0);
	// vlan my_vlan1
	Interfaces::create(VLAN_manager::get(1).add(Interfaces::get_nic(1), 10), 1, 10);
	auto& my_vlan1 = Interfaces::get(1, 10);
	my_vlan1.network_config(IP4::addr{10,10,10,10}, IP4::addr{255,255,255,0}, 0);
	auto& eth1 = Interfaces::get(1);
	eth1.negotiate_dhcp(10.0, [&eth1] (bool timedout) {
		if (timedout) {
			INFO("NaCl plugin interface eth1", "DHCP timeout (%s) - falling back to static configuration", eth1.ifname().c_str());
			eth1.network_config(IP4::addr{10,0,0,50}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1}, IP4::addr{8,8,8,8});
		}
	});
	auto& eth0 = Interfaces::get(0);
	eth0.network_config(IP4::addr{10,0,0,45}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1}, IP4::addr{8,8,8,8});

	custom_made_classes_from_nacl::My_Filter my_filter;

	eth1.ip_obj().prerouting_chain().chain.push_back(my_filter);

	eth1.ip_obj().output_chain().chain.push_back(my_filter);

	eth1.ip_obj().postrouting_chain().chain.push_back(my_filter);

	eth1.ip_obj().input_chain().chain.push_back(my_filter);

	eth0.ip_obj().prerouting_chain().chain.push_back(my_filter);

	eth0.ip_obj().input_chain().chain.push_back(my_filter);

	eth0.ip_obj().output_chain().chain.push_back(my_filter);

	eth0.ip_obj().postrouting_chain().chain.push_back(my_filter);

	// Ct

	nacl_ct_obj = std::make_shared<Conntrack>();

	INFO("NaCl", "Enabling Conntrack on eth1");
	eth1.enable_conntrack(nacl_ct_obj);

	INFO("NaCl", "Enabling Conntrack on eth0");
	eth0.enable_conntrack(nacl_ct_obj);

	// NAT

	nacl_natty_obj = std::make_unique<nat::NAPT>(nacl_ct_obj);

	auto masq = [](IP4::IP_packet_ptr pckt, Inet& stack, Conntrack::Entry_ptr entry)->auto {
		nacl_natty_obj->masquerade(*pckt, stack, entry);
		return Filter_verdict<IP4>{std::move(pckt), Filter_verdict_type::ACCEPT};
	};
	auto demasq = [](IP4::IP_packet_ptr pckt, Inet& stack, Conntrack::Entry_ptr entry)->auto {
		nacl_natty_obj->demasquerade(*pckt, stack, entry);
		return Filter_verdict<IP4>{std::move(pckt), Filter_verdict_type::ACCEPT};
	};

	INFO("NaCl", "Enable MASQUERADE on eth1");
	eth1.ip_obj().prerouting_chain().chain.push_back(demasq);
	eth1.ip_obj().postrouting_chain().chain.push_back(masq);

	INFO("NaCl", "Enable MASQUERADE on eth0");
	eth0.ip_obj().prerouting_chain().chain.push_back(demasq);
	eth0.ip_obj().postrouting_chain().chain.push_back(masq);
}
