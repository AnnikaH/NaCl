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
#include <net/inet>
#include <net/super_stack.hpp>
#include <net/ip4/cidr.hpp>
#include <syslogd>
#include <timers>
#include <uplink/uplink.hpp>
#include <ctime>
#include <profile>
#include <os>

using namespace std::chrono;

// ---- Timer Timestamp ----

static std::string now() {
	auto  tnow = time(0);
	auto* curtime = localtime(&tnow);

	char buff[48];
	int len = strftime(buff, sizeof(buff), "%c", curtime);
	return std::string(buff, len);
}

//< Timer Timestamp

// ---- Timer CPU ----

template <int N, typename T>
struct rolling_avg {
	std::deque<T> values;

	void push(T value) {
		if (values.size() >= N) values.pop_front();
		values.push_back(value);
	}
	double avg() const {
		double ps = 0.0;
		if (values.empty()) return ps;
		for (auto v : values) ps += v;
		return ps / values.size();
	}
};

void print_cpu_usage() {
	// CPU-usage statistics
	static uint64_t last_total = 0, last_asleep = 0;
	uint64_t tdiff = StackSampler::samples_total() - last_total;
	last_total = StackSampler::samples_total();
	uint64_t adiff = StackSampler::samples_asleep() - last_asleep;
	last_asleep = StackSampler::samples_asleep();

	if (tdiff > 0) {
		double asleep = adiff / (double) tdiff;
		static rolling_avg<5, double> asleep_avg;
		asleep_avg.push(asleep);

		/*
		printf("CPU usage: %.2f%%  Idle: %.2f%%  Active: %ld Existing: %ld Free: %ld\n",
			(1.0 - asleep) * 100.0, asleep * 100.0,
			Timers::active(), Timers::existing(), Timers::free());
		*/

		INFO("NaCl Timer CPU", "Usage: %.2f%% Idle: %.2f%%", (1.0 - asleep) * 100.0, asleep * 100.0);
	} else {
		INFO("NaCl Timer CPU", "CPU usage unavailable due to lack of samples");
	}
}

//< Timer CPU

// ---- Timer Timers ----

void print_timers_data() {
	INFO("NaCl Timer Timers", "Active: %ld Existing: %ld Free: %ld", Timers::active(), Timers::existing(), Timers::free());
}

//< Timer Timers

// ---- Timer Memory ----

static void print_mem_usage() {
	using namespace util;
	auto mem_max = OS::memory_end();
	auto total_memuse = OS::total_memuse();
	auto heap_alloc = OS::heap_usage();

	INFO("NaCl Timer Memory", "Total memory: %s, in use %0.1f%% (%s heap allocated)",
		Byte_r(mem_max).to_string().c_str(),
		(double(total_memuse) / mem_max) * 100, Byte_r(heap_alloc).to_string().c_str());
}

//< Timer Memory

using namespace net;

namespace nacl {
  class Filter {
  public:
    virtual Filter_verdict<IP4> operator()(IP4::IP_packet_ptr pckt, Inet& stack, Conntrack::Entry_ptr ct_entry) = 0;
    virtual ~Filter() {}
  };
}

void register_plugin_nacl() {
	INFO("NaCl", "Registering NaCl plugin");

	auto& eth0 = Super_stack::get(0);
	eth0.network_config(IP4::addr{10,0,0,45}, IP4::addr{255,255,255,0}, IP4::addr{10,0,0,1});


	StackSampler::begin();
	auto& uplink = uplink::get();

	Timers::periodic(1s, 25s, [](auto) {
		INFO("NaCl Timer Timestamp", "%s", now().c_str());
		INFO("NaCl Timer Stack Sampling", "");
		StackSampler::print(5);
	});

	Timers::periodic(1s, 45s, [](auto) {
		print_mem_usage();
		print_cpu_usage();
	});

	Timers::periodic(1s, 120s, [&uplink](auto) {
		INFO("NaCl Timer Stats", "Sending statistics over uplink");
		uplink.send_stats();
		print_timers_data();
	});
}
