//Paolo Trungadi

/* Wormhole Attack Simulation with AODV Routing Protocol - Sample Program
  Network topology

                            p2p
            n0 <---------------------------> n5 
            |                                 | 
            |                                 |
            n1 - - - - n2 - - - - n3 - - - - n4

  Each wireless node is in the range of its immediate adjacent.
  Source Node: n1
  Destination Node: n4
  Worm Tunnel: p2p tunnel between n0 and n5, which would otherwise not be able to communicate

  Output of this file:
  1. Generates wormhole_atk.xml file for viewing animation in NetAnim.
 */

#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ipv4-global-routing-helper.h"

NS_LOG_COMPONENT_DEFINE("wormhole_mix_attack");

using namespace ns3;


int main (int argc, char *argv[]){
  bool enableAtk=false;

  CommandLine cmd(__FILE__);
  cmd.AddValue("enableAtk", "Attack behaviour switch", enableAtk);
  cmd.Parse(argc, argv);
  
  if(enableAtk)
    std::cout<<"Wormhole attack enabled. \n";
  else
    std::cout<<"Wormhole attack is not enabled. \n";

// Topology
  NS_LOG_INFO ("Create nodes.");
  NodeContainer nodes_c; 
  NodeContainer not_malicious_c;
  NodeContainer malicious_c;
  nodes_c.Create(6);

  not_malicious_c.Add(nodes_c.Get(1));
  not_malicious_c.Add(nodes_c.Get(2));
  not_malicious_c.Add(nodes_c.Get(3));
  not_malicious_c.Add(nodes_c.Get(4));
  malicious_c.Add(nodes_c.Get(0));
  malicious_c.Add(nodes_c.Get(5));


  // WiFi
  WifiHelper wifi_h;
  wifi_h.SetStandard(WIFI_STANDARD_80211b);

  YansWifiPhyHelper wifiPhy_h;
  wifiPhy_h.SetErrorRateModel("ns3::NistErrorRateModel");
  wifiPhy_h.SetPcapDataLinkType(YansWifiPhyHelper::DLT_IEEE802_11);

  YansWifiChannelHelper wifiChannel_h;
  wifiChannel_h.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel_h.AddPropagationLoss("ns3::TwoRayGroundPropagationLossModel", "SystemLoss", DoubleValue(1), "HeightAboveZ", DoubleValue(1.5));

  // Settings for a range of ~250m
  wifiPhy_h.Set("TxPowerStart", DoubleValue(33));
  wifiPhy_h.Set("TxPowerEnd", DoubleValue(33));
  wifiPhy_h.Set("TxPowerLevels", UintegerValue(1));
  wifiPhy_h.Set("TxGain", DoubleValue(0));
  wifiPhy_h.Set("RxGain", DoubleValue(0));
  wifiPhy_h.Set("RxSensitivity", DoubleValue(-61.8));
  wifiPhy_h.Set("CcaEdThreshold", DoubleValue(-64.8));
  wifiPhy_h.SetChannel(wifiChannel_h.Create());

  WifiMacHelper wifiMac_h;
  wifiMac_h.SetType("ns3::AdhocWifiMac");

  PointToPointHelper p2p_wormtunnel_h;
  p2p_wormtunnel_h.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  p2p_wormtunnel_h.SetChannelAttribute("Delay", StringValue("1ms"));


  NetDeviceContainer devices, mal_devices_c;
  devices = wifi_h.Install(wifiPhy_h, wifiMac_h, nodes_c);
  mal_devices_c = p2p_wormtunnel_h.Install(nodes_c.Get(0),nodes_c.Get(5));


  // Setting up internet and routing protocols
  AodvHelper aodv;
  AodvHelper malicious_aodv; 
 
  InternetStackHelper internet;

  internet.SetRoutingHelper(aodv);
  internet.Install(not_malicious_c);
  
  malicious_aodv.Set("EnableWrmAttack",BooleanValue(enableAtk)); 
  malicious_aodv.Set("FirstEndWifiWormTunnel",Ipv4AddressValue("10.0.1.1"));
  malicious_aodv.Set("SecondEndWifiWormTunnel",Ipv4AddressValue("10.0.1.6"));
  malicious_aodv.Set("FirstEndOfWormTunnel",Ipv4AddressValue("10.1.2.1"));
  malicious_aodv.Set("SecondEndOfWormTunnel",Ipv4AddressValue("10.1.2.2"));

  internet.SetRoutingHelper(malicious_aodv);
  internet.Install(malicious_c);

  // Set up Addresses
  Ipv4AddressHelper ipv4_h;
  NS_LOG_INFO("Assign IP Addresses.");
  ipv4_h.SetBase("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces_c = ipv4_h.Assign(devices);

  ipv4_h.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer mal_interfaces_c = ipv4_h.Assign(mal_devices_c);



  NS_LOG_INFO ("Create Applications.");

  //Server application
  uint16_t port = 4000;
  UdpServerHelper server_h(port);
  ApplicationContainer serverApp_c = server_h.Install(nodes_c.Get(4));
  serverApp_c.Start(Seconds(1.0));
  serverApp_c.Stop(Seconds(50.0));

  //Client application
  uint32_t MaxPacketSize = 1024;
  Time interPacketInterval = Seconds(1.0);
  uint32_t MaxPacketCount = 10;
  UdpClientHelper client_h(Address(interfaces_c.GetAddress(4)),port);
  client_h.SetAttribute("MaxPackets",UintegerValue(MaxPacketCount));
  client_h.SetAttribute("Interval",TimeValue(interPacketInterval));
  client_h.SetAttribute("PacketSize",UintegerValue(MaxPacketSize));
  ApplicationContainer clientApp_c = client_h.Install(nodes_c.Get(1));
  clientApp_c.Start(Seconds(1.0));
  clientApp_c.Stop(Seconds(50.0));

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // Mobility & animation
  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
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
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes_c);

  AnimationInterface anim ("wormhole_atk.xml"); 

  anim.SetConstantPosition(nodes_c.Get(0), 100, 100);
  anim.SetConstantPosition(nodes_c.Get(5), 700, 100);
  anim.UpdateNodeDescription(nodes_c.Get(0),"Atkr");
  anim.UpdateNodeDescription(nodes_c.Get(5),"Atkr");
  anim.UpdateNodeColor(nodes_c.Get(0),255,255,255);
  anim.UpdateNodeColor(nodes_c.Get(5),255,255,255);
  
  anim.SetConstantPosition(nodes_c.Get(1), 100, 300);
  anim.SetConstantPosition(nodes_c.Get(2), 300, 300); 
  anim.SetConstantPosition(nodes_c.Get(3), 500, 300);
  anim.SetConstantPosition(nodes_c.Get(4), 700, 300); 

  for(int i=0; i<6; i++)
    anim.UpdateNodeSize(i, double(10), double(10));

  anim.EnablePacketMetadata(true);


// Throughput calculation using Flowmonitor
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();
//
// Now, do the actual simulation.
//
  NS_LOG_INFO("Run Simulation.");
  Simulator::Stop(Seconds(50.0));
  Simulator::Run();


  monitor->CheckForLostPackets();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
      if ((t.sourceAddress=="10.0.1.2" && t.destinationAddress == "10.1.2.5"))
      {
          std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
          std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
          std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
      	  std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps\n";
      }
     }


  return 0;
}
