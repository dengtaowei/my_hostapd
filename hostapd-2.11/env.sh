#!/bin/bash
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

run() {
    echo "$*"
    "$@" || exit $?
}

ip link set eth0 name ens32

# Use the ip address that was allocated by the daemon to this
# container. The IP of the second docker network (ens32) is used,
# because the first one is by default the one used for exposed ports,
# and we rely on exposed ports for UCC communication.
bridge_ip="$(ip addr show dev ens32 | awk '/^ *inet / {print $2}')"

run ip link add          br-lan   type bridge

# When an interface is added to the bridge, the bridge inherits its MAC address.
# It shouldn't be the same as any other interface because that messes up the topology in the
# controller, however. Therefore, save the MAC address an re-apply it later.
bridge_mac="$(ip link show dev br-lan | awk '/^ *link\/ether / {print $2}')"

run ip link set      dev ens32     master br-lan
run ip link set      dev wlan0    master br-lan

run ip address flush dev ens32


run ip link set      dev br-lan   addr "$bridge_mac"
run ip address add   dev br-lan "$bridge_ip"
run ip link set      dev br-lan   up
