//Paolo Trungadi
/*
  Simulation of a Blackhole attack in a WiFi network using the AODV routing protocol.
   

  Network Topology:
    
    n1 ------ n0 ------ n2 ------ n3
    
    Each node is in the wireless range of the immediate neighbours.
    
    n1,n2, and n3 are legitimate nodes with n1 acting as source and sending packets to the destination n3.
    n0 is the malicious device, which drops the packet instead of forwarding if the blackhole attack is activated.
    
  File Output:
    1. blackhole_atk.xml: the NetAnim file to visualize the simulation
  
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

NS_LOG_COMPONENT_DEFINE ("blackhole_attack");

using namespace ns3;

int main (int argc, char *argv[])
{
  bool enableAtk=false;
  
  CommandLine cmd;
  cmd.AddValue("enableAtk", "Attack behaviour switch", enableAtk);
  cmd.Parse(argc, argv);
  if(enableAtk)
    std::cout<<"Blackhole attack enabled. \n";
  else
    std::cout<<"Blackhole attack is not enabled. \n";

// Topology
  NS_LOG_INFO ("Create nodes.");
  NodeContainer nodes_c; 
  NodeContainer not_malicious;
  NodeContainer malicious;
  nodes_c.Create(6);

  not_malicious.Add(nodes_c.Get(1));
  not_malicious.Add(nodes_c.Get(2));
  not_malicious.Add(nodes_c.Get(3));
  not_malicious.Add(nodes_c.Get(4));
  not_malicious.Add(nodes_c.Get(5));
  malicious.Add(nodes_c.Get(0));
  
  
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


  NetDeviceContainer devices_c;
  devices_c = wifi_h.Install(wifiPhy_h, wifiMac_h, nodes_c);


//  Setting up AODV protocol
  AodvHelper aodv;
  AodvHelper malicious_aodv; 
 

  // Setting up internet and routing protocols
  InternetStackHelper internet;

  internet.SetRoutingHelper(aodv);
  internet.Install(not_malicious);
 
  malicious_aodv.Set("EnableBHatk",BooleanValue(enableAtk)); 
  internet.SetRoutingHelper(malicious_aodv);
  internet.Install(malicious);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer ifcont = ipv4.Assign(devices_c);


  //Server application
  uint16_t port = 4000;
  UdpServerHelper server_h(port);
  ApplicationContainer serverApp_c = server_h.Install(nodes_c.Get(3));
  serverApp_c.Start(Seconds(1.0));
  serverApp_c.Stop(Seconds(50.0));

  //Client application
  uint32_t MaxPacketSize = 1024;
  Time interPacketInterval = Seconds(1.0);
  uint32_t MaxPacketCount = 10;
  UdpClientHelper client_h(Address(ifcont.GetAddress(3)),port);
  client_h.SetAttribute("MaxPackets",UintegerValue(MaxPacketCount));
  client_h.SetAttribute("Interval",TimeValue(interPacketInterval));
  client_h.SetAttribute("PacketSize",UintegerValue(MaxPacketSize));
  ApplicationContainer clientApp_c = client_h.Install(nodes_c.Get(1));
  clientApp_c.Start(Seconds(1.0));
  clientApp_c.Stop(Seconds(50.0));


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
                              DoubleValue(20.0),
                              "GridWidth",
                              UintegerValue(5),
                              "LayoutType",
                              StringValue("RowFirst"));

  mobility_h.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility_h.Install(nodes_c);


  AnimationInterface anim("blackhole_atk2.xml"); 
  anim.SetConstantPosition(nodes_c.Get(0), 100, 150);
  anim.UpdateNodeDescription(nodes_c.Get(0),"Atkr");
  anim.UpdateNodeColor(nodes_c.Get(0),255,255,255);
  anim.SetConstantPosition(nodes_c.Get(1), 0, 250);
  anim.SetConstantPosition(nodes_c.Get(2), 300, 150);
  anim.SetConstantPosition(nodes_c.Get(3), 400, 250); 
  anim.SetConstantPosition(nodes_c.Get(4), 100, 350);
  anim.SetConstantPosition(nodes_c.Get(5), 300, 350);
  anim.EnablePacketMetadata(true);
  for(int i=0; i<6; i++)
    anim.UpdateNodeSize(i, double(10), double(10));
  

  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("blackhole_atk2.routes", std::ios::out);
  aodv.PrintRoutingTableAllAt(Seconds(60.0), routingStream);


// Throughput calculation using Flowmonitor
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();


// Simulation
  NS_LOG_INFO("Run Simulation.");
  Simulator::Stop(Seconds(100.0));
  Simulator::Run();

  monitor->CheckForLostPackets();

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
      if ((t.sourceAddress=="10.1.2.2" && t.destinationAddress == "10.1.2.4"))
      {
          std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
          std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
          std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
      	  std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps\n";
      }
     }

  monitor->SerializeToXmlFile("lab-4.flowmon", true, true);

}
