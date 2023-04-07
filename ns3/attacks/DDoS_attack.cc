//Paolo Trungadi

/*
    Network Topology
    n0 - - - - n1 - - - - n2
        p2p   / | \      p2p
            /  |  \ 
            a0,a1,..,ax

    n0 is a legitimated node that needs to communicate with the home gateway (e.g., smart thermostat)
    n1 is the Smart Hubg
    n2 is the Home Router/GW
    a0-aX are the infected Smart Home nodes that now act as malicious bots (e.g., all the infected smart-lightbulbs of the house)

    In this examples the nodes are connected with p2p connections just for the sake of visualization clarity.
*/

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/nstime.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ssid.h"
#include "ns3/netanim-module.h"
#include "ns3/ipv4-global-routing-helper.h"


#define TCP_PORT 9000
#define UDP_PORT 9001
#define ATK_RATE "20480kb/s"
#define SIM_TIME 10.0


using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DDoS_attack");

int main(int argc, char* argv[])
{
    int nAtk = 6;

    CommandLine cmd(__FILE__);
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    
    NodeContainer legitNodes_c,atkNodes_c;
    legitNodes_c.Create(3);
    atkNodes_c.Create(nAtk);

    //Separate p2p links so atk can be done with different settings
    PointToPointHelper p2pLegitNodes_h,p2pAtkNodes_h;
    p2pLegitNodes_h.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pLegitNodes_h.SetChannelAttribute("Delay", StringValue("1ms"));
    p2pAtkNodes_h.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pAtkNodes_h.SetChannelAttribute("Delay", StringValue("1ms"));

    NetDeviceContainer p2pLegitDevices_c[2],p2pAtkDevices_c[nAtk];
    p2pLegitDevices_c[0] = p2pLegitNodes_h.Install(legitNodes_c.Get(0),legitNodes_c.Get(1));
    p2pLegitDevices_c[1] = p2pLegitNodes_h.Install(legitNodes_c.Get(1),legitNodes_c.Get(2));

    for(int i=0; i<nAtk; i++){
        p2pAtkDevices_c[i] = p2pAtkNodes_h.Install(atkNodes_c.Get(i),legitNodes_c.Get(1));
    }
    
    InternetStackHelper stack_h;
    stack_h.Install(legitNodes_c);
    stack_h.Install(atkNodes_c);


    Ipv4AddressHelper address01_h,address12_h,atk_address_h;

    address01_h.SetBase("10.1.1.0", "255.255.255.0");
    address12_h.SetBase("10.1.2.0", "255.255.255.0");
    atk_address_h.SetBase("10.1.0.0", "255.255.255.252");

    Ipv4InterfaceContainer p2pLegitInterfaces01_c,p2pLegitInterfaces12_c;
    p2pLegitInterfaces01_c = address01_h.Assign(p2pLegitDevices_c[0]);
    p2pLegitInterfaces12_c = address12_h.Assign(p2pLegitDevices_c[1]);
    for(int i=0; i<nAtk; i++){
        atk_address_h.Assign(p2pAtkDevices_c[i]);
        atk_address_h.NewNetwork();
    }
    
  

    //APP

    //Legit node
    BulkSendHelper bulkSend_h("ns3::TcpSocketFactory", InetSocketAddress(p2pLegitInterfaces12_c.GetAddress(1), TCP_PORT));
    bulkSend_h.SetAttribute("MaxBytes", UintegerValue(100000));
    ApplicationContainer bulkSendApp = bulkSend_h.Install(legitNodes_c.Get(0));
    bulkSendApp.Start(Seconds(0.0));
    bulkSendApp.Stop(Seconds(SIM_TIME - 10));

    //Sinks
    PacketSinkHelper TCPsink_h("ns3::TcpSocketFactory",InetSocketAddress(Ipv4Address::GetAny(), TCP_PORT));
    ApplicationContainer TCPSinkApp = TCPsink_h.Install(legitNodes_c.Get(2));
    TCPSinkApp.Start(Seconds(0.0));
    TCPSinkApp.Stop(Seconds(SIM_TIME));

    PacketSinkHelper UDPsink("ns3::UdpSocketFactory",Address(InetSocketAddress(Ipv4Address::GetAny(), UDP_PORT)));
    ApplicationContainer UDPSinkApp = UDPsink.Install(legitNodes_c.Get(2));
    UDPSinkApp.Start(Seconds(0.0));
    UDPSinkApp.Stop(Seconds(SIM_TIME));

    //Attackers 
    OnOffHelper onoff_h("ns3::UdpSocketFactory", Address(InetSocketAddress(p2pLegitInterfaces12_c.GetAddress(1), UDP_PORT)));
    onoff_h.SetConstantRate(DataRate(ATK_RATE));
    onoff_h.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=30]"));
    onoff_h.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer atkApps_c;
    atkApps_c = onoff_h.Install(atkNodes_c);
    atkApps_c.Start(Seconds(0.0));
    atkApps_c.Stop(Seconds(SIM_TIME));


    //Mobility & animation
    MobilityHelper mobility_h;
    mobility_h.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX",
                                  DoubleValue(0.0),
                                  "MinY",
                                  DoubleValue(0.0),
                                  "DeltaX",
                                  DoubleValue(20.0),
                                  "DeltaY",
                                  DoubleValue(5.0),
                                  "GridWidth",
                                  UintegerValue(3),
                                  "LayoutType",
                                  StringValue("RowFirst"));

    mobility_h.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility_h.Install(legitNodes_c);
    mobility_h.Install(atkNodes_c);

    AnimationInterface anim("DDoS.xml");
    anim.EnablePacketMetadata(true);

    uint32_t x_pos = 0;
    for(int i=0; i<nAtk; i++){
        anim.UpdateNodeColor(atkNodes_c.Get(i),255,255,255);
        anim.UpdateNodeDescription(atkNodes_c.Get(i),"Infected node");
        anim.SetConstantPosition(atkNodes_c.Get(i),x_pos,30);
        x_pos+=5;
    }

    

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Simulator::Stop(Seconds(SIM_TIME));

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
