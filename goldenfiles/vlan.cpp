// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2017 IncludeOS AS, Oslo, Norway
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
#include <net/inet4>
#include <net/ip4/cidr.hpp>
#include <plugins/nacl.hpp>
#include <net/vlan>
#include <syslogd>

using namespace net;

void register_plugin_nacl() {
	INFO("NaCl", "Registering NaCl plugin");

	auto& eth4 = Inet4::stack<4>();
	eth4.network_config(IP4::addr{10,200,100,100}, IP4::addr{255,255,255,0}, IP4::addr{100,200,100,1});
	auto& eth3 = Inet4::stack<3>();
	eth3.network_config(IP4::addr{10,100,100,100}, IP4::addr{255,255,255,0}, IP4::addr{100,100,100,1});
	auto& eth2 = Inet4::stack<2>();
	eth2.network_config(IP4::addr{10,10,10,50}, IP4::addr{255,255,255,0}, IP4::addr{10,10,10,1});
	auto& eth1 = Inet4::stack<1>();
	eth1.network_config(IP4::addr{10,0,10,45}, IP4::addr{255,255,255,0}, IP4::addr{10,0,10,1});
	auto& eth0 = Inet4::stack<0>();
	eth0.network_config(IP4::addr{10,0,0,30}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1});

	// For each iface:
	auto& eth4_nic = eth4.nic();
	auto& eth4_manager = VLAN_manager::get(4);
	// For each vlan connected to this iface:
	Super_stack::inet().create<IP4>(eth4_manager.add(eth4_nic, 62), 4, 62).network_config(IP4::addr{10,200,100,2}, IP4::addr{255,255,255,0}, IP4::addr{100,200,100,1});
	Super_stack::inet().create<IP4>(eth4_manager.add(eth4_nic, 63), 4, 63).network_config(IP4::addr{10,200,100,3}, IP4::addr{255,255,255,0}, IP4::addr{100,200,100,1});

	// For each iface:
	auto& eth3_nic = eth3.nic();
	auto& eth3_manager = VLAN_manager::get(3);
	// For each vlan connected to this iface:
	Super_stack::inet().create<IP4>(eth3_manager.add(eth3_nic, 22), 3, 22).network_config(IP4::addr{10,100,0,10}, IP4::addr{255,255,255,0}, IP4::addr{100,100,100,1});
	Super_stack::inet().create<IP4>(eth3_manager.add(eth3_nic, 23), 3, 23).network_config(IP4::addr{10,100,0,20}, IP4::addr{255,255,255,0}, IP4::addr{100,100,100,1});

	// For each iface:
	auto& eth2_nic = eth2.nic();
	auto& eth2_manager = VLAN_manager::get(2);
	// For each vlan connected to this iface:
	Super_stack::inet().create<IP4>(eth2_manager.add(eth2_nic, 22), 2, 22).network_config(IP4::addr{10,100,0,10}, IP4::addr{255,255,255,0}, IP4::addr{10,10,10,1});
	Super_stack::inet().create<IP4>(eth2_manager.add(eth2_nic, 23), 2, 23).network_config(IP4::addr{10,100,0,20}, IP4::addr{255,255,255,0}, IP4::addr{10,10,10,1});

	// For each iface:
	auto& eth1_nic = eth1.nic();
	auto& eth1_manager = VLAN_manager::get(1);
	// For each vlan connected to this iface:
	Super_stack::inet().create<IP4>(eth1_manager.add(eth1_nic, 13), 1, 13).network_config(IP4::addr{10,50,0,20}, IP4::addr{255,255,255,0}, IP4::addr{10,0,10,1});
	Super_stack::inet().create<IP4>(eth1_manager.add(eth1_nic, 24), 1, 24).network_config(IP4::addr{10,60,0,20}, IP4::addr{255,255,255,0}, IP4::addr{10,0,10,1});

	// For each iface:
	auto& eth0_nic = eth0.nic();
	auto& eth0_manager = VLAN_manager::get(0);
	// For each vlan connected to this iface:
	Super_stack::inet().create<IP4>(eth0_manager.add(eth0_nic, 5), 0, 5).network_config(IP4::addr{10,50,0,10}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1});
	Super_stack::inet().create<IP4>(eth0_manager.add(eth0_nic, 2), 0, 2).network_config(IP4::addr{10,60,0,10}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1});

}