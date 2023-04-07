//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.node.compromised;

import inet.node.base.ApplicationLayerNodeBase;

//
// This module implements a wireless sensor node. It has one 802.15.4 wireless interface
// and an energy storage module by default.
//# TODO and energyconsumer in the radio
//# TODO there is no management; the IdealEnergyStorage never depletes...
//
module SensorNode_Victim extends ApplicationLayerNodeBase
{
    parameters:
        @display("i=misc/sensor2");
        @figure[submodules];
        numWlanInterfaces = default(2);
        energyStorage.typename = default("SimpleEpEnergyStorage");
        energyManagement.typename = default("SimpleEpEnergyManagement");
        wlan[0].typename = default("Ieee802154NarrowbandInterface");
        wlan[1].typename = default("Ieee80211Interface");
        wlan[*].radio.energyConsumer.typename = default("StateBasedEpEnergyConsumer");
		
}
