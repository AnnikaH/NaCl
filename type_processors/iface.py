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

from NaCl import exit_NaCl, exit_NaCl_internal_error, Typed, BASE_TYPE_TYPED_INIT, BASE_TYPE_FUNCTION
from shared import *
# TYPE_IFACE, TYPE_NAT, TEMPLATE_KEY_IFACE_PUSHES, TEMPLATE_KEY_ENABLE_CT_IFACES, TEMPLATE_KEY_HAS_NATS,
# TRUE, FALSE

# -------------------- CONSTANTS Iface --------------------

# Moved to shared.py: TYPE_IFACE = "iface"

# Iface top members

IFACE_KEY_INDEX             = "index"
IFACE_KEY_IP4               = "ip4"
IFACE_KEY_IP6               = "ip6"
IFACE_KEY_SEND_QUEUE_LIMIT  = "send_queue_limit"
IFACE_KEY_BUFFER_LIMIT      = "buffer_limit"
# IFACE_KEY_VLAN            = "vlan"    # Moved to shared.py

PREDEFINED_IFACE_KEYS = [
    IFACE_KEY_INDEX,
    IFACE_KEY_IP4,
    IFACE_KEY_IP6,
    IFACE_KEY_VLAN,
    IFACE_KEY_SEND_QUEUE_LIMIT,
    IFACE_KEY_BUFFER_LIMIT
]

# Iface keys (ip4)

IFACE_KEY_ADDRESS       = "address"
IFACE_KEY_NETMASK       = "netmask"
IFACE_KEY_GATEWAY       = "gateway"
IFACE_KEY_DNS           = "dns"
IFACE_KEY_MASQUERADE    = "masquerade"
IFACE_KEY_CONFIG        = "config"

IFACE_KEY_PREROUTING    = "prerouting"
IFACE_KEY_INPUT         = "input"
IFACE_KEY_OUTPUT        = "output"
IFACE_KEY_POSTROUTING   = "postrouting"

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
    IFACE_KEY_MASQUERADE,
    IFACE_KEY_CONFIG
]
PREDEFINED_IFACE_IP4_KEYS.extend(CHAIN_NAMES)

# Iface keys (ip6)

IFACE_KEY_PREFIX = "prefix"

PREDEFINED_IFACE_IP6_KEYS = [
    IFACE_KEY_ADDRESS,
    IFACE_KEY_PREFIX,
    IFACE_KEY_GATEWAY,
    # IFACE_KEY_DNS
    # IFACE_KEY_MASQUERADE
    IFACE_KEY_CONFIG
]
# TODO:
# PREDEFINED_IFACE_IP6_KEYS.extend(CHAIN_NAMES)

# config values

AUTO_CONFIG             = "auto"
AUTO_FALLBACK_CONFIG    = "auto-with-fallback"
STATIC_CONFIG           = "static"

PREDEFINED_CONFIG_TYPES = [
    AUTO_CONFIG,
    AUTO_FALLBACK_CONFIG,
    STATIC_CONFIG
]

# -------------------- TEMPLATE KEYS (pystache) --------------------

TEMPLATE_KEY_IFACES                     = "ifaces"
# Moved to shared.py: TEMPLATE_KEY_IFACE_PUSHES = "pushes_iface"
TEMPLATE_KEY_AUTO_NATTING_IFACES        = "auto_natting_ifaces"
TEMPLATE_KEY_MASQUERADES                = "masquerades"

# Moved to shared.py: TEMPLATE_KEY_ENABLE_CT_IFACES = "enable_ct_ifaces"

TEMPLATE_KEY_HAS_AUTO_NATTING_IFACES    = "has_auto_natting_ifaces"
TEMPLATE_KEY_HAS_VLANS                  = "has_vlans"
TEMPLATE_KEY_HAS_MASQUERADES            = "has_masquerades"
TEMPLATE_KEY_IS_VLAN                    = "is_vlan"
TEMPLATE_KEY_VLAN_INDEX_IS_MAC_STRING   = "vlan_index_is_mac_string"

TEMPLATE_KEY_INDEX                      = "index"
TEMPLATE_KEY_IP4                        = "ip4"
TEMPLATE_KEY_IP6                        = "ip6"
TEMPLATE_KEY_VLAN                       = "vlan"
TEMPLATE_KEY_SEND_QUEUE_LIMIT           = "send_queue_limit"
TEMPLATE_KEY_BUFFER_LIMIT               = "buffer_limit"

TEMPLATE_KEY_CONFIG_IS_AUTO             = "config_is_auto"
TEMPLATE_KEY_CONFIG_IS_AUTO_FALLBACK    = "config_is_auto_fallback"
TEMPLATE_KEY_CONFIG_IS_STATIC           = "config_is_static"

TEMPLATE_KEY_ADDRESS                    = "address"
TEMPLATE_KEY_NETMASK                    = "netmask"
TEMPLATE_KEY_PREFIX                     = "prefix"
TEMPLATE_KEY_GATEWAY                    = "gateway"
TEMPLATE_KEY_DNS                        = "dns"

TEMPLATE_KEY_IFACE_INDEX                = "iface_index"

TEMPLATE_KEY_VLAN_IFACES                = "vlan_ifaces"

# Helper function

def is_int(input):
    try:
        int(input)
    except ValueError:
        return False
    return True

# -------------------- Iface --------------------

class Iface(Typed):
    def __init__(self, nacl_state, idx, name, ctx, base_type, type_t):
        super(Iface, self).__init__(nacl_state, idx, name, ctx, base_type, type_t)

        self.chains = {}    # To handle setting of a chain multiple times in the same Iface
                            # Should not be handled as the ctx objects in self.members

        # Iface keys/members:
        # - index
        # - vlan
        # - send_queue_limit
        # - buffer_limit
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
        # 	- masquerade (?)
        # - ip6
        # 	- address
        #   - prefix
        # 	- gateway
        # 	- dns
        # 	- config
        # 	- prerouting
        # 	- input
        # 	- output
        # 	- postrouting
        # 	- masquerade (?)

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
            if (parent_key == IFACE_KEY_IP4 and key not in PREDEFINED_IFACE_IP4_KEYS) or \
                (parent_key == IFACE_KEY_IP6 and key not in PREDEFINED_IFACE_IP6_KEYS):
                exit_NaCl(value_ctx, "Invalid " + class_name + " member " + key + " in " + self.name + "." + parent_key)

        if level > 2:
            exit_NaCl(value_ctx, "Invalid " + class_name + " member " + parent_key + "." + key)

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
            # The config value is just resolved to a string ("auto", "auto-with-fallback" or "static")
            # Error if ip4.config or ip6.config is set but it has not been resolved to a string or the config value
            # is not a valid config value
            if found_element_value not in PREDEFINED_CONFIG_TYPES:
                exit_NaCl(value_ctx, "Invalid config type. Valid values are " + ", ".join(PREDEFINED_CONFIG_TYPES))
        else:
            # Default handling / case
            # IFACE_KEY_INDEX
            # IFACE_KEY_ADDRESS
            # IFACE_KEY_NETMASK
            # IFACE_KEY_GATEWAY
            # IFACE_KEY_DNS
            # and more
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
            TEMPLATE_KEY_NAME:              self.name,
            TEMPLATE_KEY_CHAIN:             chain,
            TEMPLATE_KEY_FUNCTION_NAMES:    function_names
        })

    def get_pystache_ip_object(self, protocol_key):
        if protocol_key != IFACE_KEY_IP4 and protocol_key != IFACE_KEY_IP6:
            exit_NaCl_internal_error("Invalid protocol key (" + protocol_key + ") given to Iface's get_pystache_ip_object method. " + \
                "Valid keys are " + IFACE_KEY_IP4 + " and " + IFACE_KEY_IP6)

        config_is_static = False
        config_is_auto = False
        config_is_auto_fallback = False

        ip = self.members.get(protocol_key)
        if ip is not None:
            # Error if ip (4 or 6) is not a dictionary (contains key value pairs)
            if not isinstance(ip, dict):
                predefined_keys = PREDEFINED_IFACE_IP4_KEYS if protocol_key == IFACE_KEY_IP4 else PREDEFINED_IFACE_IP6_KEYS
                exit_NaCl(self.ctx, "Invalid value of Iface member " + protocol_key + \
                    ". It needs to be an object containing " + ", ".join(predefined_keys))

            config = ip.get(IFACE_KEY_CONFIG)
            # If this is a vlan, require network configuration:
            if self.members.get(IFACE_KEY_VLAN) is not None:
                # Validate ip(4 or 6)'s config member
                # config value has previously been resolved to a string (lower case) (in resolve_dictionary_value)
                iface_key_netmask_or_prefix = IFACE_KEY_NETMASK if protocol_key == IFACE_KEY_IP4 else IFACE_KEY_PREFIX
                if (config is None or config != AUTO_CONFIG) and \
                    (ip.get(IFACE_KEY_ADDRESS) is None or ip.get(iface_key_netmask_or_prefix) is None):
                    exit_NaCl(self.ctx, "The members " + IFACE_KEY_ADDRESS + " and " + iface_key_netmask_or_prefix + \
                        " must be set for every vlan Iface (" + protocol_key + " member) if" + \
                        " the Iface configuration hasn't been set to " + AUTO_CONFIG)
                elif config is not None and config == AUTO_CONFIG and \
                    (ip.get(IFACE_KEY_ADDRESS) is not None or \
                    ip.get(iface_key_netmask_or_prefix) is not None or \
                    ip.get(IFACE_KEY_GATEWAY) is not None or \
                    ip.get(IFACE_KEY_DNS) is not None):
                    exit_NaCl(self.ctx, "An Iface with " + protocol_key + " config set to " + AUTO_CONFIG + \
                        " can not specify " + IFACE_KEY_ADDRESS + ", " + iface_key_netmask_or_prefix + ", " + \
                        IFACE_KEY_GATEWAY + " or " + IFACE_KEY_DNS)

                # It is not allowed (yet) to set buffer_limit or send_queue_limit on a vlan
                if self.members.get(IFACE_KEY_BUFFER_LIMIT) is not None or self.members.get(IFACE_KEY_SEND_QUEUE_LIMIT) is not None:
                    exit_NaCl(self.ctx, "The members send_queue_limit and buffer_limit can not be set on an Iface that is a vlan")

            if config is None or config == STATIC_CONFIG:
                config_is_static = True
            elif config == AUTO_CONFIG:
                config_is_auto = True
            else: # config == AUTO_FALLBACK_CONFIG
                config_is_auto_fallback = True

        pystache_ip_obj = None
        if ip is not None:
            pystache_ip_obj = {
                TEMPLATE_KEY_ADDRESS:                   ip.get(IFACE_KEY_ADDRESS),
                TEMPLATE_KEY_GATEWAY:                   ip.get(IFACE_KEY_GATEWAY),
                TEMPLATE_KEY_CONFIG_IS_STATIC:          config_is_static,
                TEMPLATE_KEY_CONFIG_IS_AUTO:            config_is_auto,
                TEMPLATE_KEY_CONFIG_IS_AUTO_FALLBACK:   config_is_auto_fallback
            }
            if protocol_key == IFACE_KEY_IP4:
                pystache_ip_obj[TEMPLATE_KEY_NETMASK]   = ip.get(IFACE_KEY_NETMASK)
                pystache_ip_obj[TEMPLATE_KEY_DNS]       = ip.get(IFACE_KEY_DNS)
            else: # protocol_key == IFACE_KEY_IP6
                pystache_ip_obj[TEMPLATE_KEY_PREFIX]    = ip.get(IFACE_KEY_PREFIX)
                # pystache_ip_obj[TEMPLATE_KEY_DNS]     = ip.get(IFACE_KEY_DNS)

        # Else we allow an Iface to be configured without network (ip4 and/or ip6)
        # (f.ex. if the user wants to set buffer_limit or send_queue_limit on an Iface without having to configure it)

        return [ pystache_ip_obj ]

    def add_iface(self):
        # This method should also validate the Iface object, f.ex. that every mandatory field is set

        # -- index --

        # index is a mandatory field
        index = self.members.get(IFACE_KEY_INDEX)
        if index is None:
            exit_NaCl(self.ctx, "Iface member " + IFACE_KEY_INDEX + " has not been set")

        # Check that an Iface with this Iface's index has not already been defined
        # If a vlan
        for key, el in self.nacl_state.elements.iteritems():
            if isinstance(el, Iface) and key != self.name:
                # If another Iface has been defined with the same index and neither this nor
                # that Iface is a vlan (has a vlan member), display an error
                el_idx = el.members.get(IFACE_KEY_INDEX)
                el_vlan = el.members.get(IFACE_KEY_VLAN)
                if el_idx is not None and el_idx == index and el_vlan is None and self.members.get(IFACE_KEY_VLAN) is None:
                    exit_NaCl(self.ctx, "Another Iface has been defined with index " + el_idx)

        pystache_ip4 = self.get_pystache_ip_object(IFACE_KEY_IP4)
        pystache_ip6 = self.get_pystache_ip_object(IFACE_KEY_IP6)

        # -- add the Iface --

        # Is this Iface a vlan or not
        is_vlan = False
        vlan_index_is_mac_string = False
        if self.members.get(IFACE_KEY_VLAN) is not None:
            is_vlan = True

            # Set vlan_index_is_mac_string to True if the index is a string
            # and not a number (but only necessary for an Iface that is a vlan)
            index = self.members.get(IFACE_KEY_INDEX)
            if not is_int(index):
                vlan_index_is_mac_string = True

            # Also add this Iface to the pystache data list TEMPLATE_KEY_VLAN_IFACES to be able to find
            # out (in final_registration) whether to #include relevant headers or not in mustache
            self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_VLAN_IFACES, {
                TEMPLATE_KEY_IFACE: self.name,
            })

        # Create object containing key value pairs with the data we have collected
        # Append this object to the ifaces list
        # Is to be sent to pystache renderer in handle_input function
        self.nacl_state.append_to_pystache_data_list(TEMPLATE_KEY_IFACES, {
            TEMPLATE_KEY_NAME:                      self.name,
            TEMPLATE_KEY_TITLE:                     self.name.title(),
            TEMPLATE_KEY_VLAN_INDEX_IS_MAC_STRING:  vlan_index_is_mac_string,
            TEMPLATE_KEY_INDEX:                     self.members.get(IFACE_KEY_INDEX),
            TEMPLATE_KEY_IS_VLAN:                   is_vlan,
            TEMPLATE_KEY_VLAN:                      self.members.get(IFACE_KEY_VLAN),

            TEMPLATE_KEY_IP4:                       pystache_ip4,
            TEMPLATE_KEY_IP6:                       pystache_ip6,

            TEMPLATE_KEY_SEND_QUEUE_LIMIT:          self.members.get(IFACE_KEY_SEND_QUEUE_LIMIT),
            TEMPLATE_KEY_BUFFER_LIMIT:              self.members.get(IFACE_KEY_BUFFER_LIMIT)
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

    # This method is overridden because an Iface can be created with only one value: 'Iface eth0 auto'
    # The default is that self.ctx is an obj() (object), but in an Iface it can also be a value_name() (auto)
    # Overriding
    def process_ctx(self):
        value_ctx = self.ctx.value() if hasattr(self.ctx, 'value') else self.ctx

        if value_ctx.value_name() is not None:
            # configuration type (auto, auto-with-fallback, static)
            config = value_ctx.value_name().getText().lower()
            if config in PREDEFINED_CONFIG_TYPES:
                self.members[IFACE_KEY_IP4] = {
                    IFACE_KEY_CONFIG: config
                }
            else:
                exit_NaCl(value_ctx, "Invalid Iface value " + value_ctx.value_name().getText())
        elif value_ctx.obj() is not None:
            self.process_obj(self.members, value_ctx.obj())
        else:
            exit_NaCl(value_ctx, "An Iface has to contain key value pairs, or be set to a configuration type (" + \
                ", ".join(PREDEFINED_CONFIG_TYPES) + ")")

    # Main processing method
    def process(self):
        if self.res is None:
            # Then process

            self.process_ctx()
            self.process_assignments()
            self.add_iface()
            self.enable_ct()

            self.res = self.members

        return self.res

    # Called from handle_input (NaCl.py) right before rendering, after the NaCl file has been processed
    # Register the last data here that can not be registered before this (set has-values f.ex.)
    @staticmethod
    def final_registration(nacl_state):
        if not nacl_state.pystache_list_is_empty(TEMPLATE_KEY_AUTO_NATTING_IFACES):
            nacl_state.register_pystache_data_object(TEMPLATE_KEY_HAS_AUTO_NATTING_IFACES, True)

        if not nacl_state.pystache_list_is_empty(TEMPLATE_KEY_VLAN_IFACES):
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
        TEMPLATE_KEY_VLAN_IFACES, \
        TEMPLATE_KEY_MASQUERADES, \
        TEMPLATE_KEY_ENABLE_CT_IFACES
        # TEMPLATE_KEY_HAS_MASQUERADES, \
        # TEMPLATE_KEY_HAS_AUTO_NATTING_IFACES, \
        # TEMPLATE_KEY_HAS_VLANS \
        # These three are added in the final_registration method
    ])

def init(nacl_state):
    # print "Init iface: Iface"
    nacl_state.add_type_processor(TYPE_IFACE, Iface)
    create_iface_pystache_lists(nacl_state)
