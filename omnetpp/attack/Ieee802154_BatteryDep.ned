package ieee802154_BatteryDep;

import inet.examples.inet.routerperf.BurstHost;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.dymo.DymoRouter;
import inet.node.ethernet.Eth100M;
import inet.node.inet.SensorNode;
import inet.node.compromised.SensorNode_infected;
import inet.node.compromised.SensorNode_Victim;
import inet.node.inet.StandardHost;
import inet.node.inet.WirelessHost;
import inet.physicallayer.wireless.apsk.packetlevel.ApskScalarRadioMedium;
import inet.physicallayer.wireless.ieee802154.bitlevel.Ieee802154UwbIrRadioMedium;
import inet.physicallayer.wireless.ieee802154.packetlevel.Ieee802154NarrowbandScalarRadioMedium;
import inet.visualizer.common.IntegratedMultiVisualizer;
import inet.visualizer.common.IntegratedVisualizer;


network Ieee802154_BatteryDep
{
    @display("bgb=20,20;bgi=showcases/floorplan,s");
    types:
    submodules:
        sensor1: SensorNode_Victim {
            @display("p=9.467456,3.7141557;i=misc/sensor");
        }
        sensor2: SensorNode_Victim {
            @display("p=9.5,16.5;i=misc/sensor");
        }
        sensor3: SensorNode_Victim {
            @display("p=10.75,10.75;i=misc/sensor");
        }
        sensor4: SensorNode_Victim {
            @display("p=2.5,17.5;i=misc/sensor");
        }
        infsensor: SensorNode_infected {
            @display("p=2.4761038,8.484297;i=misc/sensor,red;i2=status/excl");
        }
        lamp1: SensorNode {
            @display("p=8,5;i=status/bulb");
        }
        lamp2: SensorNode {
            @display("p=8.75,13.5;i=status/bulb");
        }
        lamp3: SensorNode {
            @display("p=13.5,8.5;i=status/bulb");
        }
        lamp4: SensorNode {
            @display("p=16.5,9.5;i=status/bulb");
        }
        lamp5: SensorNode {
            @display("p=13.5,14;i=status/bulb");
        }
        lamp6: SensorNode {
            @display("p=4,13;i=status/bulb");
        }
        lamp7: SensorNode {
            @display("p=4,10.5;i=status/bulb");
        }
        lamp8: SensorNode {
            @display("p=4,5;i=status/bulb");
        }
        controller: SensorNode {
            @display("p=6.5,10.5;i=misc/sensorgateway");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=17.405554,0.7282658");
        }
        radioMedium: Ieee802154NarrowbandScalarRadioMedium {
            @display("p=16.895767,2.9130633");
        }
        visualizer: IntegratedMultiVisualizer {
            @display("p=18.497952,4.770141");
        }
        sensor5: SensorNode_Victim {
            @display("p=17.405554,6.991352;i=misc/sensor");
        }
        sensor6: SensorNode_Victim {
            @display("p=15.584888,16.968594;i=misc/sensor");
        }
        sensor7: SensorNode_Victim {
            @display("p=8.884843,11.61584;i=misc/sensor");
        }
        sensor8: SensorNode_Victim {
            @display("p=10.75,10.75;i=misc/sensor");
        }
        sensor9: SensorNode_Victim {
            @display("p=6.08102,3.4228494;i=misc/sensor");
        }
    connections:
}
