# This file is a part of the IncludeOS unikernel - www.includeos.org
#
# Copyright 2017-2018 IncludeOS AS, Oslo, Norway
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
# To avoid: <...>/NaCl/type_processors/iface.py:1: RuntimeWarning: Parent module '<...>/NaCl/type_processors' not found while handling absolute import

from NaCl import exit_NaCl, Typed, BASE_TYPE_TYPED_INIT, BASE_TYPE_FUNCTION
from shared import *
# TYPE_IFACE, TYPE_NAT, TEMPLATE_KEY_IFACE_PUSHES, TEMPLATE_KEY_ENABLE_CT_IFACES, TEMPLATE_KEY_HAS_NATS,
# TRUE, FALSE

# -------------------- CONSTANTS Iface --------------------

# Moved to shared.py: TYPE_IFACE = "iface"

# Iface top members

IFACE_KEY_INDEX 	= "index"
IFACE_KEY_IP4 		= "ip4"
# IFACE_KEY_IP6 = "ip6"

PREDEFINED_IFACE_KEYS = [
	IFACE_KEY_INDEX,
	IFACE_KEY_IP4,
	# IFACE_KEY_IP6
]

# Iface keys (ip4)

IFACE_KEY_ADDRESS 		= "address"
IFACE_KEY_NETMASK 		= "netmask"
IFACE_KEY_GATEWAY		= "gateway"
IFACE_KEY_DNS 			= "dns"
IFACE_KEY_VLAN 			= "vlan"
IFACE_KEY_MASQUERADE 	= "masquerade"
IFACE_KEY_CONFIG 		= "config"

IFACE_KEY_PREROUTING 	= "prerouting"
IFACE_KEY_INPUT 		= "input"
IFACE_KEY_OUTPUT 		= "output"
IFACE_KEY_POSTROUTING 	= "postrouting"

CHAIN_NAMES = [
	IFACE_KEY_PREROUTING,
	IFACE_KEY_INPUT,
	IFACE_KEY_OUTPUT,
	IFACE_KEY_POSTROUTING
]

PREDEFINED_IFACE_IP4_KEYS = [
	IFACE_KEY_ADDRESS,
	IFACE_KEY_NETMASK,
	IFACE_KEY_GATEWAY,
	IFACE_KEY_DNS,
	IFACE_KEY_VLAN,
	IFACE_KEY_MASQUERADE,
	IFACE_KEY_CONFIG
]
PREDEFINED_IFACE_IP4_KEYS.extend(CHAIN_NAMES)

DHCP_CONFIG 			= "dhcp"
DHCP_FALLBACK_CONFIG 	= "dhcp-with-fallback"
STATIC_CONFIG 			= "static"

PREDEFINED_CONFIG_TYPES = [
	DHCP_CONFIG,
	DHCP_FALLBACK_CONFIG,
	STATIC_CONFIG
]

# -------------------- CONSTANTS Vlan --------------------

TYPE_VLAN 	= "vlan"

# Vlan keys

VLAN_KEY_ADDRESS 	= IFACE_KEY_ADDRESS
VLAN_KEY_NETMASK 	= IFACE_KEY_NETMASK
VLAN_KEY_GATEWAY 	= IFACE_KEY_GATEWAY
VLAN_KEY_DNS 		= IFACE_KEY_DNS
VLAN_KEY_INDEX 		= IFACE_KEY_INDEX

PREDEFINED_VLAN_KEYS = [
	VLAN_KEY_ADDRESS,
	VLAN_KEY_NETMASK,
	VLAN_KEY_GATEWAY,
	VLAN_KEY_INDEX
]

# -------------------- TEMPLATE KEYS (pystache) --------------------

# Template keys Vlan

TEMPLATE_KEY_VLANS = "vlans"

# Template keys Iface

TEMPLATE_KEY_IFACES 					= "ifaces"
TEMPLATE_KEY_IFACES_WITH_VLANS			= "ifaces_with_vlans"
# Moved to shared.py: TEMPLATE_KEY_IFACE_PUSHES = "pushes_iface"
TEMPLATE_KEY_AUTO_NATTING_IFACES 		= "auto_natting_ifaces"
TEMPLATE_KEY_MASQUERADES 				= "masquerades"

# Moved to shared.py: TEMPLATE_KEY_ENABLE_CT_IFACES = "enable_ct_ifaces"

TEMPLATE_KEY_HAS_AUTO_NATTING_IFACES 	= "has_auto_natting_ifaces"
TEMPLATE_KEY_HAS_VLANS 					= "has_vlans"
TEMPLATE_KEY_HAS_MASQUERADES 			= "has_masquerades"

TEMPLATE_KEY_IP4 = "ip4"
# TEMPLATE_KEY_IP6 = "ip6"

TEMPLATE_KEY_CONFIG_IS_DHCP 			= "config_is_dhcp"
TEMPLATE_KEY_CONFIG_IS_DHCP_FALLBACK 	= "config_is_dhcp_fallback"
TEMPLATE_KEY_CONFIG_IS_STATIC 			= "config_is_static"

TEMPLATE_KEY_INDEX 		= "index"
TEMPLATE_KEY_ADDRESS 	= "address"
TEMPLATE_KEY_NETMASK 	= "netmask"
TEMPLATE_KEY_GATEWAY 	= "gateway"
TEMPLATE_KEY_DNS 		= "dns"

TEMPLATE_KEY_IFACE_INDEX = "iface_index"

# -------------------- CLASSES --------------------

# ---- class Vlan ----

class Vlan(Typed):
	def __init__(self, nacl_state, idx, name, ctx, base_type, type_t):
		super(Vlan, self).__init__(nacl_state, idx, name, ctx, base_type, type_t)

		# Vlan keys/members:
		# address
		# netmask
		# gateway
		# index

	# New:
	# Overriding
	def validate_dictionary_key(self, key, parent_key, level, value_ctx):
		class_name = self.get_class_name()

		# TODO: Necessary?
		key = key.lower()

		if level == 1:
			if key not in PREDEFINED_VLAN_KEYS:
				exit_NaCl(value_ctx, "Invalid " + class_name + " member " + key)
		else:
			exit_NaCl(value_ctx, "Invalid " + class_name + " member " + key)

	# New:
	# Overriding
	def resolve_dictionary_value(self, dictionary, key, value_ctx):
		# Creating/setting the self.members dictionary

		# Keys have already been validated
		# This method should make sure that the transpilation of the values
		# is correct (based on the key) and then add that value to self.members:
		# dictionary[key] = resolved_value

		# Goal:
		# Add found value to the dictionary (self.members), or if it is not necessary to add the value to self.members, just process the value
		# dictionary[key] = self.nacl_state.transpile_value(value)

		# If special handling / cases (the value should not be transpiled normally), add an if-option here:

		# TODO: Necessary?
		key_lower = key.lower()

		# Validate values
		if value_ctx.obj() is not None or value_ctx.list_t() is not None:
			exit_NaCl(value_ctx, "The Vlan member " + key + " can not be an object or a list")

		# Add found value
		dictionary[key_lower] = self.nacl_state.transpile_value(value_ctx)

	# Called by the Iface that this Vlan is added to
	def check_mandatory_members(self):
		vlan_index = self.members.get(VLAN_KEY_INDEX)
		vlan_address = self.members.get(VLAN_KEY_ADDRESS)
		vlan_netmask = self.members.get(VLAN_KEY_NETMASK)

		if vlan_index is None or vlan_address is None or vlan_netmask is None:
			exit_NaCl(self.ctx, "The members index, address and netmask must be set for every Vlan")

	# Main processing method
	def process(self):
		if self.res is None:
			# Then process

			# New:
			self.process_ctx()
			self.process_assignments()

			''' Old (handle_as_untyped = False):
			self.process_ctx()
			self.process_assignments()
			self.validate_members()
			self.process_members()
			'''

			self.res = self.members

		return self.res

# < class Vlan

# ---- class Iface ----

class Iface(Typed):
	def __init__(self, nacl_state, idx, name, ctx, base_type, type_t):
		super(Iface, self).__init__(nacl_state, idx, name, ctx, base_type, type_t)

		self.chains = {}	# To handle setting of a chain multiple times in the same Iface
		                	# Should not be handled as the ctx objects in self.members

		# Iface keys/members:
		# - ip4
		# 	- address
		# 	- netmask
		# 	- gateway
		# 	- dns
		# 	- config
		# 	- prerouting
		# 	- input
		# 	- output
		# 	- postrouting
		# 	- vlan (?)
		# 	- masquerade (?)
		# - index
		# - ip6 (later)
		# 	- address
		# 	- gateway
		# 	- dns
		# 	- config (?)
		# 	- prerouting
		# 	- input
		# 	- output
		# 	- postrouting
		# 	- vlan (?)
		# 	- masquerade (?)

	# New:
	# Overriding
	def validate_dictionary_key(self, key, parent_key, level, value_ctx):
		class_name = self.get_class_name()

		# TODO: Necessary?
		key = key.lower()

		if level == 1:
			if key not in PREDEFINED_IFACE_KEYS:
				exit_NaCl(value_ctx, "Invalid " + class_name + " member " + key)
			return

		if parent_key == "":
			exit_NaCl(value_ctx, "Internal error: Parent key of " + key + " has not been given")

		if level == 2:
			if parent_key == IFACE_KEY_IP4 and key not in PREDEFINED_IFACE_IP4_KEYS:
				exit_NaCl(value_ctx, "Invalid " + class_name + " member " + key + " in " + self.name + "." + parent_key)
		else:
			exit_NaCl(value_ctx, "Invalid " + class_name + " member " + key)

	# New:
	# Overriding
	def resolve_dictionary_value(self, dictionary, key, value_ctx):
		# Creating/setting the self.members dictionary

		# Keys have already been validated
		# This method should make sure that the transpilation of the values
		# is correct (based on the key) and then add that value to self.members:
		# dictionary[key] = resolved_value

		# Goal:
		# Add found value to the dictionary (self.members), or if it is not necessary to add the value to self.members, just process the value
		# dictionary[key] = self.nacl_state.transpile_value(value)

		# If special handling / cases (the value should not be transpiled normally), add an if-option here:

		# TODO: Necessary?
		key = key.lower()

		if key in CHAIN_NAMES:
			# prerouting, input, output, postrouting
			return self.process_and_add_push(key, value_ctx)

		if key == IFACE_KEY_MASQUERADE:
			masq_val = self.nacl_state.transpile_value(value_ctx)
			if not isinstance(masq_val, basestring) or (masq_val.lower() != TRUE and masq_val.lower() != FALSE):
				exit_NaCl(member, "Invalid masquerade value. Must be set to true or false")
			if masq_val == TRUE:
				self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_MASQUERADES, {
					TEMPLATE_KEY_IFACE: self.name
				})
			return

		found_element_value = value_ctx.getText()
		if key == IFACE_KEY_CONFIG:
			found_element_value = found_element_value.lower()
			# The config value is just resolved to a string ("dhcp", "dhcp-with-fallback" or "static")
			# Error if ip4.config is set but it has not been resolved to a string or the config value is not a valid config value
			if found_element_value not in PREDEFINED_CONFIG_TYPES:
				exit_NaCl(value_ctx, "Invalid config type. Valid values are " + ", ".join(PREDEFINED_CONFIG_TYPES))
		elif key == IFACE_KEY_VLAN:
			# Just add the value_ctx - this will be processed later
			found_element_value = value_ctx
		else:
			# Default handling / case
			# IFACE_KEY_INDEX
			# IFACE_KEY_ADDRESS
			# IFACE_KEY_NETMASK
			# IFACE_KEY_GATEWAY
			# IFACE_KEY_DNS
			found_element_value = self.nacl_state.transpile_value(value_ctx)
		# Add found value
		dictionary[key] = found_element_value

	# A push is when a function (Filter or Nat) is added to a chain in the NaCl file,
	# f.ex. 'prerouting: my_filter'
	def process_and_add_push(self, chain, value_ctx):
		if self.chains.get(chain) is not None:
			exit_NaCl(value_ctx, "Iface chain " + chain + " has already been set")

		functions = []
		if value_ctx.list_t() is not None:
			# More than one function pushed onto chain
			for list_value in value_ctx.list_t().value_list().value():
				if list_value.value_name() is None:
					exit_NaCl(list_value, "This is not supported: " + value_ctx.getText())
				functions.append(list_value.value_name())
		elif value_ctx.value_name() is not None:
			# Only one function pushed onto chain
			functions = [ value_ctx.value_name() ]
		else:
			exit_NaCl(value_ctx, "This is not supported: " + value_ctx.getText())

		self.chains[chain] = chain # Mark as set
		# Register the push in the pystache data
		self.add_push(chain, functions)

	# Called by process_and_add_push
	# A push is when a function (Filter or Nat) is added to a chain in the NaCl file,
	# f.ex. 'prerouting: my_filter'
	# Register a push in the pystache data
	def add_push(self, chain, functions):
		# chain: string with name of chain
		# functions: list containing value_name ctxs, where each name corresponds to the name of a NaCl function

		add_auto_natting = False
		function_names = []
		num_functions = len(functions)
		for i, function in enumerate(functions):
			name = function.getText()
			element = self.nacl_state.elements.get(name)
			if element is None or element.base_type != BASE_TYPE_FUNCTION:
				exit_NaCl(function, "No function with the name " + name + " exists")

			# If a Nat function is pushed onto an Iface's chain,
			# push the snat_translate lambda in cpp_template.mustache
			# onto the same Iface's postrouting chain
			# and push the dnat_translate lambda in cpp_template.mustache
			# onto the same Iface's prerouting chain
			if element.type_t.lower() == TYPE_NAT:
				add_auto_natting = True

			function_names.append({TEMPLATE_KEY_FUNCTION_NAME: name, TEMPLATE_KEY_COMMA: (i < (num_functions - 1))})

		if add_auto_natting:
			self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_AUTO_NATTING_IFACES, {
				TEMPLATE_KEY_IFACE: self.name
			})

		self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_IFACE_PUSHES, {
			TEMPLATE_KEY_NAME:				self.name,
			TEMPLATE_KEY_CHAIN: 			chain,
			TEMPLATE_KEY_FUNCTION_NAMES: 	function_names
		})

	# New:
	def process_and_add_vlans(self):
		# Called once per Iface AFTER the Iface itself has been processed (self.members has been created and the values resolved)

		vlans = []

		ip4 = self.members.get(IFACE_KEY_IP4)
		vlan_ctx = ip4.get(IFACE_KEY_VLAN)

		if vlan_ctx is not None:
			if vlan_ctx.obj() is not None and any(pair.key().getText().lower() in PREDEFINED_VLAN_KEYS for pair in vlan_ctx.obj().key_value_list().key_value_pair()):
				# Then handle this as a vlan object in itself, not an obj of vlans
				vlan_element = Vlan(self.nacl_state, 0, "", vlan_ctx, BASE_TYPE_TYPED_INIT, TYPE_VLAN)
				vlans.append(vlan_element)
			elif vlan_ctx.obj() is not None:
				# If this is a dictionary/map/obj of vlans
				# Add each Vlan in obj to the vlans list
				# Each element in the obj needs to be a valid Vlan
				for pair in vlan_ctx.obj().key_value_list().key_value_pair():
					# Key: Name of Vlan
					# Value: Actual Vlan object/value (containing address, netmask, gateway, index)
					vlan_element = Vlan(self.nacl_state, 0, pair.key().getText(), pair.value(), BASE_TYPE_TYPED_INIT, TYPE_VLAN)
					vlans.append(vlan_element)
			elif vlan_ctx.list_t() is not None:
				# Add each Vlan in list_t to the vlans list
				# Each element in the list_t needs to be a valid Vlan
				for _, v in enumerate(vlan_ctx.list_t().value_list().value()):
					vlan_element = None

					if v.value_name() is not None:
						vlan_name = v.value_name().getText()
						vlan_element = self.nacl_state.elements.get(vlan_name)
						if not self.is_vlan(vlan_element):
							exit_NaCl(v.value_name(), "Undefined Vlan " + vlan_name)
					elif v.obj() is not None:
						vlan_element = Vlan(self.nacl_state, 0, "", v, BASE_TYPE_TYPED_INIT, TYPE_VLAN)
					else:
						exit_NaCl(v, "A Vlan list must either contain Vlan objects (key value pairs) or names of Vlans")

					vlans.append(vlan_element)
			elif vlan_ctx.value_name() is not None:
				vlan_name = vlan_ctx.value_name().getText()
				vlan_element = self.nacl_state.elements.get(vlan_name)
				if not self.is_vlan(vlan_element):
					exit_NaCl(vlan_ctx.value_name(), "Undefined Vlan " + vlan_name)
				vlans.append(vlan_element)
			else:
				exit_NaCl(vlan_ctx, "An Iface's vlan needs to be a list of Vlans")

		if len(vlans) > 0:
			# Process and add vlans found
			self.add_vlans(vlans)

	# Called by process_and_add_vlans
	def is_vlan(self, element):
		if element is None or not hasattr(element, 'type_t') or element.type_t.lower() != TYPE_VLAN:
			return False
		return True

	# Called by process_and_add_vlans
	def add_vlans(self, vlans):
		# Called once per Iface AFTER the Iface itself has been processed (self.members has been created and the values resolved)

		pystache_vlans = []
		for vlan in vlans:
			vlan.process() # Make sure the Vlan has been processed

			gateway = vlan.members.get(VLAN_KEY_GATEWAY)
			if gateway is None:
				# Use the same gateway as this Iface (could be None)
				ip4 = self.members.get(IFACE_KEY_IP4)
				gateway = ip4.get(IFACE_KEY_GATEWAY)

			vlan.check_mandatory_members() # exits on error

			pystache_vlans.append({
				TEMPLATE_KEY_INDEX: 	vlan.members.get(VLAN_KEY_INDEX),
				TEMPLATE_KEY_ADDRESS: 	vlan.members.get(VLAN_KEY_ADDRESS),
				TEMPLATE_KEY_NETMASK: 	vlan.members.get(VLAN_KEY_NETMASK),
				TEMPLATE_KEY_GATEWAY: 	gateway
			})

		self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_IFACES_WITH_VLANS, {
			TEMPLATE_KEY_IFACE: 		self.name,
			TEMPLATE_KEY_IFACE_INDEX: 	self.members.get(IFACE_KEY_INDEX),
			TEMPLATE_KEY_VLANS: 		pystache_vlans
		})

	# Validate and append iface object to pystache ifaces list
	def add_iface(self):
		# This method should also validate the Iface object, f.ex. that every mandatory field is set

		# -- index --

		# index is a mandatory field
		index = self.members.get(IFACE_KEY_INDEX)
		if index is None:
			exit_NaCl(self.ctx, "Iface member " + IFACE_KEY_INDEX + " has not been set")
		else:
			# Check that an Iface with this Iface's index has not already been defined
			for key, el in self.nacl_state.elements.iteritems():
				if isinstance(el, Iface) and key != self.name:
					# If this element is an Iface and it is not the Iface that we are adding now,
					# give an error if the indeces match
					el_idx = el.members.get(IFACE_KEY_INDEX)
					if el_idx is not None and el_idx == index:
						exit_NaCl(self.ctx, "Another Iface has been defined with index " + el_idx)

		# -- ip4 --

		ip4_config_is_static = False
		ip4_config_is_dhcp = False
		ip4_config_is_dhcp_fallback = False

		ip4 = self.members.get(IFACE_KEY_IP4)
		# For now ip4 is mandatory
		if ip4 is not None:
			# Error if ip4 is not a dictionary (contains key value pairs)
			if not isinstance(ip4, dict):
				exit_NaCl(self.ctx, "Invalid value of Iface member " + IFACE_KEY_IP4 + \
					". It needs to be an object containing " + ", ".join(PREDEFINED_IFACE_IP4_KEYS))

			# Validate ip4's config member
			# config value has previously been resolved to a string (lower case) (in resolve_dictionary_value)
			config = ip4.get(IFACE_KEY_CONFIG)
			if (config is None or config != DHCP_CONFIG) and (ip4.get(IFACE_KEY_ADDRESS) is None or ip4.get(IFACE_KEY_NETMASK) is None):
				exit_NaCl(self.ctx, "The members " + IFACE_KEY_ADDRESS + " and " + IFACE_KEY_NETMASK + " must be set for every Iface if" + \
					" the Iface configuration hasn't been set to " + DHCP_CONFIG)
			elif config is not None and config == DHCP_CONFIG and \
				(ip4.get(IFACE_KEY_ADDRESS) is not None or \
				ip4.get(IFACE_KEY_NETMASK) is not None or \
				ip4.get(IFACE_KEY_GATEWAY) is not None):
				exit_NaCl(self.ctx, "An Iface with config set to " + DHCP_CONFIG + " can not specify " + IFACE_KEY_ADDRESS + \
					", " + IFACE_KEY_NETMASK + " or " + IFACE_KEY_GATEWAY)

			if config is None or config == STATIC_CONFIG:
				ip4_config_is_static = True
			elif config == DHCP_CONFIG:
				ip4_config_is_dhcp = True
			else: # config == DHCP_FALLBACK_CONFIG
				ip4_config_is_dhcp_fallback = True
		else:
			exit_NaCl(self.ctx, "Iface member " + IFACE_KEY_IP4 + " has not been set")

		# TODO: Does this have to be a list containing an object or can it just be an object?
		pystache_ip4 = [{
			TEMPLATE_KEY_ADDRESS: 	ip4.get(IFACE_KEY_ADDRESS),
			TEMPLATE_KEY_NETMASK:	ip4.get(IFACE_KEY_NETMASK),
			TEMPLATE_KEY_GATEWAY: 	ip4.get(IFACE_KEY_GATEWAY),
			TEMPLATE_KEY_DNS: 		ip4.get(IFACE_KEY_DNS),

			TEMPLATE_KEY_CONFIG_IS_STATIC: 			ip4_config_is_static,
			TEMPLATE_KEY_CONFIG_IS_DHCP: 			ip4_config_is_dhcp,
			TEMPLATE_KEY_CONFIG_IS_DHCP_FALLBACK: 	ip4_config_is_dhcp_fallback
		}]

		# -- add the Iface --

		# Create object containing key value pairs with the data we have collected
		# Append this object to the ifaces list
		# Is to be sent to pystache renderer in handle_input function
		self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_IFACES, {
			TEMPLATE_KEY_NAME: 		self.name,
			TEMPLATE_KEY_TITLE: 	self.name.title(),
			TEMPLATE_KEY_INDEX: 	self.members.get(IFACE_KEY_INDEX),

			TEMPLATE_KEY_IP4: 		pystache_ip4

			# TEMPLATE_KEY_IP6: 	pystache_ip6
		})

	def enable_ct(self):
		# Add this Iface's name to enable_ct_ifaces pystache list if it is not in the list already
		if not self.nacl_state.exists_in_pystache_list(TEMPLATE_KEY_ENABLE_CT_IFACES, TEMPLATE_KEY_IFACE, self.name):
			for chain in CHAIN_NAMES:
				if self.chains.get(chain) is not None:
					self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_ENABLE_CT_IFACES, {
						TEMPLATE_KEY_IFACE: self.name
					})
					return # Only one entry in enable_ct_ifaces list for each Iface

	# New:
	# This method is overridden because an Iface can be created with only one value: 'Iface eth0 dhcp'
	# The default is that self.ctx is an obj() (object), but in an Iface it can also be a value_name() (dhcp)
	# Overriding
	def process_ctx(self):
		value_ctx = self.ctx.value() if hasattr(self.ctx, 'value') else self.ctx

		if value_ctx.value_name() is not None:
			# configuration type (dhcp, dhcp-with-fallback, static)
			config = value_ctx.value_name().getText().lower()
			if config in PREDEFINED_CONFIG_TYPES:
				# Old: self.members[IFACE_KEY_CONFIG] = value_ctx
				# TODO: Test:
				self.members[IFACE_KEY_IP4] = {
					IFACE_KEY_CONFIG: config
				}
			else:
				exit_NaCl(value_ctx, "Invalid Iface value " + value_ctx.value_name().getText())
		elif value_ctx.obj() is not None:
			# default
			self.process_obj(self.members, value_ctx.obj())
		else:
			exit_NaCl(value_ctx, "An Iface has to contain key value pairs, or be set to a configuration type (" + \
				", ".join(PREDEFINED_CONFIG_TYPES) + ")")

	# Main processing method
	def process(self):
		if self.res is None:
			# Then process

			# New:
			self.process_ctx()
			self.process_assignments()
			self.process_and_add_vlans() # Must be called after the Iface itself has been processed and the values resolved
			self.add_iface()
			self.enable_ct()

			# Old (handle_as_untyped = False):
			'''
			self.process_ctx()
			self.process_assignments()
			self.validate_members()
			self.process_members()
			self.add_iface()
			self.enable_ct()
			'''

			self.res = self.members

		return self.res

	# Called from handle_input (NaCl.py) right before rendering, after the NaCl file has been processed
	# Register the last data here that can not be registered before this (set has-values f.ex.)
	@staticmethod
	def final_registration(nacl_state):
		if not nacl_state.pystache_list_is_empty(TEMPLATE_KEY_AUTO_NATTING_IFACES):
			nacl_state.register_pystache_data_object(TEMPLATE_KEY_HAS_AUTO_NATTING_IFACES, True)

		if not nacl_state.pystache_list_is_empty(TEMPLATE_KEY_IFACES_WITH_VLANS):
			nacl_state.register_pystache_data_object(TEMPLATE_KEY_HAS_VLANS, True)

		if not nacl_state.pystache_list_is_empty(TEMPLATE_KEY_MASQUERADES):
			nacl_state.register_pystache_data_object(TEMPLATE_KEY_HAS_MASQUERADES, True)
			nacl_state.register_pystache_data_object(TEMPLATE_KEY_HAS_NATS, True)

# < class Iface

# -------------------- INIT --------------------

# Dictionary of lists in NaCl_state
# pystache_data{}
# pystache_data[TEMPLATE_KEY] = []

def create_iface_pystache_lists(nacl_state):
	nacl_state.create_pystache_data_lists([ \
		TEMPLATE_KEY_IFACES, \
		TEMPLATE_KEY_AUTO_NATTING_IFACES, \
		TEMPLATE_KEY_IFACE_PUSHES, \
		TEMPLATE_KEY_IFACES_WITH_VLANS, \
		TEMPLATE_KEY_MASQUERADES, \
		TEMPLATE_KEY_ENABLE_CT_IFACES
		# TEMPLATE_KEY_HAS_MASQUERADES, \
		# TEMPLATE_KEY_HAS_AUTO_NATTING_IFACES, \
		# TEMPLATE_KEY_HAS_VLANS \
		# These three are added in the final_registration method
	])

# def create_vlan_pystache_lists(nacl_state):
#	nacl_state.create_pystache_data_lists(...)

def init(nacl_state):
	# print "Init iface: Iface and Vlan"

	nacl_state.add_type_processor(TYPE_IFACE, Iface)
	nacl_state.add_type_processor(TYPE_VLAN, Vlan)

	create_iface_pystache_lists(nacl_state)
	# create_vlan_pystache_lists(nacl_state) # No lists to create
