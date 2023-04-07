//Paolo Trungadi

// Network Topology
//
//   Wifi 10.1.3.0
//                 AP
//  *    *    *    *    *    *    *
//  |    |    |    |    |    |    |    10.1.1.0
// n2   n3   n4   n5   n6   n7   n0 -------------- n1   
//                                  point-to-point  |  
// 
// n0 is the SmartHub
// n1 is the Home Router/GW
// n2-n7 are the SmartHome Nodes


#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ssid.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/netanim-module.h"


#define ATK_RATE "20480kb/s"


using namespace ns3;

int main(int argc, char* argv[]){
    bool verbose = true;
    uint32_t nBase = 6;
    uint32_t nAtk = 1;
    bool tracing = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nBase", "Number of wifi base host devices", nBase);
    cmd.AddValue("verbose", "Tell echo applications to log if true", verbose);
    cmd.AddValue("tracing", "Enable pcap tracing", tracing);

    cmd.Parse(argc, argv);

    if (verbose)
    {
        LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
        LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    }

    NodeContainer p2pNodes_c;
    p2pNodes_c.Create(2);

    PointToPointHelper p2p_h;
    p2p_h.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p_h.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer p2pDevices;
    p2pDevices = p2p_h.Install(p2pNodes_c);

    NodeContainer wifi_Nodes_c;
    wifi_Nodes_c.Create(nBase);
    NodeContainer wifi_atk_Node_c;
    wifi_atk_Node_c.Create(nAtk);
    NodeContainer wifi_Ap_Node_c = p2pNodes_c.Get(0);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy_ch;
    phy_ch.SetChannel(channel.Create());

    WifiMacHelper mac_h;
    Ssid ssid = Ssid("ns-3-ssid");

    WifiHelper wifi;

    NetDeviceContainer baseDevices_c;
    mac_h.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
    baseDevices_c = wifi.Install(phy_ch, mac_h, wifi_Nodes_c);

    NetDeviceContainer atkDevices_c;
    mac_h.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
    atkDevices_c = wifi.Install(phy_ch, mac_h, wifi_atk_Node_c);

    NetDeviceContainer apDevices_c;
    mac_h.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
    apDevices_c = wifi.Install(phy_ch, mac_h, wifi_Ap_Node_c);

    MobilityHelper mobility_h;

    UniformDiscPositionAllocator disc_all;
    disc_all.SetRho(30.0);
    disc_all.SetX(25.0);
    disc_all.SetY(25.0);
    disc_all.SetZ(25.0);
    mobility_h.SetPositionAllocator(&disc_all);

    mobility_h.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility_h.Install(p2pNodes_c.Get(1));
    mobility_h.Install(wifi_Ap_Node_c);
    mobility_h.Install(wifi_atk_Node_c);
    mobility_h.Install(wifi_Nodes_c);
    
    

    AnimationInterface anim("Wifi.xml");
    anim.UpdateNodeColor(wifi_atk_Node_c.Get(0),255,255,255);
    anim.UpdateNodeDescription(wifi_atk_Node_c.Get(0),"Attacker");
    anim.EnablePacketMetadata(true);
    anim.SetConstantPosition(p2pNodes_c.Get(1),25,25);
    

    InternetStackHelper stack_h;
    stack_h.Install(wifi_Ap_Node_c);
    stack_h.Install(wifi_Nodes_c);
    stack_h.Install(wifi_atk_Node_c);
    stack_h.Install(p2pNodes_c.Get(1));

    Ipv4AddressHelper address_h;

    address_h.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfaces_c;
    p2pInterfaces_c = address_h.Assign(p2pDevices);



    Ipv4InterfaceContainer baseNodes_Interfaces_c;
    address_h.SetBase("10.1.2.0", "255.255.255.0");
    address_h.Assign(apDevices_c);
    address_h.Assign(atkDevices_c);
    baseNodes_Interfaces_c = address_h.Assign(baseDevices_c);

    //APP

    //Base behaviour
    UdpEchoServerHelper echoServer_h(9);
    ApplicationContainer echoserver_App_c = echoServer_h.Install(p2pNodes_c.Get(1));
    echoserver_App_c.Start(Seconds(1.0));
    echoserver_App_c.Stop(Seconds(20.0));

    UdpEchoClientHelper echoClient_h(p2pInterfaces_c.GetAddress(1), 9);
    ApplicationContainer clientApps_c = echoClient_h.Install(wifi_Nodes_c);
    clientApps_c.Start(Seconds(2.0));
    clientApps_c.Stop(Seconds(15.0));

    //Attackers app + sink for udp packets
    OnOffHelper atk_client_h("ns3::UdpSocketFactory",Address(InetSocketAddress(p2pInterfaces_c.GetAddress(1),9001)));
    atk_client_h.SetConstantRate(DataRate(ATK_RATE));
    atk_client_h.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=15]"));
    atk_client_h.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer atk_apps_c = atk_client_h.Install(wifi_atk_Node_c);
    atk_apps_c.Start(Seconds(5.0));
    atk_apps_c.Stop(Seconds(20.0));

    PacketSinkHelper udpsink_h("ns3::UdpSocketFactory",Address(InetSocketAddress(Ipv4Address::GetAny(),9001)));
    ApplicationContainer udpsink_App_c = udpsink_h.Install(p2pNodes_c.Get(1));
    udpsink_App_c.Start(Seconds(1.0));
    udpsink_App_c.Stop(Seconds(20.0));


    

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Simulator::Stop(Seconds(20.0));

    if (tracing)
    {
        phy_ch.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
        p2p_h.EnablePcapAll("third");
        phy_ch.EnablePcap("third", apDevices_c.Get(0));
    }

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
