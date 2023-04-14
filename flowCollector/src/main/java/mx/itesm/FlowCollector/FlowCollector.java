/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mx.itesm.FlowCollector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import mx.itesm.FlowCollector.jnetpcap.BasicFlow;


import java.util.*;


import java.io.InputStream;
import java.io.*;



// Packets for scalability

import java.util.concurrent.TimeUnit;

// Yung CIC flow Collector
import mx.itesm.FlowCollector.jnetpcap.BasicFlow;
import mx.itesm.FlowCollector.jnetpcap.FlowGenerator;
import mx.itesm.FlowCollector.jnetpcap.PacketReader;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/////////////////////////////////
// HTTP CLIENT TEST
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;




/**
 * Flow collector application
 */
public class FlowCollector {

    /** Properties. */
    private static Logger log = LoggerFactory.getLogger(FlowCollector.class);
    private Stack<Short> lastPackets = new Stack<Short>();

    // Flow Collector Yung
    public PacketReader packetReader = new PacketReader();
    private Udp  udp = new Udp();
    private Tcp  tcp = new Tcp();
    //public FlowGenerator flowGen = new FlowGenerator(true,600000000L, 1000000L);
    public FlowGenerator flowGen = new FlowGenerator(true,10000000L, 1000000L);
    

    public boolean finishedFlowsProcessing = false;
    private ArrayList<String> listOfKeysToRemove; //to remove finished flows
    public int flows_selected_counter  = 0;
    private int mcounter = 0;
    

    long timeElapsed = 0;
    long timeStart   = (System.nanoTime())/60000000;



    /**
     * Packet processor implementation, will call processPacket() for every TCP packet received
     */
    public static void main(String[] args) {
        System.out.print("Intelligent DDoS detector started");
        FlowCollector flowCollector = new FlowCollector();
        flowCollector.start();
    }

    public void start(){
        String device = "s101-eth1";
        int snaplen = 64 * 1024;//2048; // Truncate packet at this size
        int promiscous = Pcap.MODE_PROMISCUOUS;
        int timeout = 1 * 100; // In milliseconds
        
        StringBuilder errbuf = new StringBuilder();

        Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);
        // filtering only tcp and udp packets
        PcapBpfProgram filter = new PcapBpfProgram();
        String expression = "ip proto tcp and ip proto udp";
        int optimize = 0; // 1 means true, 0 means false
        int netmask = 0;
         
        int r = pcap.compile(filter, expression, optimize, netmask);
        if (r != Pcap.OK) {
           System.out.println("Filter error: " + pcap.getErr());
        }
        pcap.setFilter(filter);
        if (pcap == null) {
            System.out.print("open {} fail -> {}"+device+errbuf.toString());
        }


        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {

            PcapPacket permanent = new PcapPacket(Type.POINTER);
            packet.transferStateAndDataTo(permanent);
            try{
                if (permanent.hasHeader(this.tcp)||permanent.hasHeader(this.udp)) {
                    String devID = "1";
                    buidFlows(permanent, devID); 
                    IDSModule();
                }
            }
            catch(Exception e)  {
                 System.out.println("null packet received");
            }
        };

        System.out.println("Pcap is listening....");
        System.out.println("progress open successfully listening: "+device);
        int ret = pcap.loop(-1, jpacketHandler, device); // negative for infinite loop

        String str;
        switch (ret) {
            case 0:
                str = "listening: " + device + " finished";
                break;
            case -1:
                str = "listening: " + device + " error";
                break;
            case -2:
                str = "stop listening: " + device;
                break;
                default:
                    str = String.valueOf(ret);
        }
        System.out.println(str);
    }

     
    /**
     * Built flows
     * @param eth ethernet packet
     */
    private void buidFlows(PcapPacket packet, String devID) {              
        flowGen.addPacket(PacketReader.getBasicPacketInfo(packet, true, false));
        
        if (packet.hasHeader(this.udp)) {         
            flowGen.addPacket(PacketReader.getBasicPacketInfo(packet, true, false));                                       // if udp, stopping flag is required
        }     
    }



    // Forward to the Intrusion Detection System
    private void IDSModule(){
        if (!finishedFlowsProcessing) {      /// Thread processing, for finishedFlows resource sharing control search for better way pending :(
            finishedFlowsProcessing = true; 
            this.listOfKeysToRemove = new ArrayList<String>(); 
            for (Map.Entry<String, BasicFlow>  newFlow:flowGen.finishedFlowsTCP.entrySet()) {
                this.listOfKeysToRemove.add((newFlow.getValue()).getFlowId());  
                String jsonFlow1 =  (newFlow.getValue()).SelectedCICDoS2017FlowBasedFeatures();
                String jsonFlow2 =  (newFlow.getValue()).SelectedCICDDoS2019FlowBasedFeatures();
                //log.info("=============================================================================");
                //System.out.println("NFlow:  "+flowGen.publishFlowCount());
                System.out.println("New - flow");
                /*log.info("Id: {}, Fdura: {}, TFwdPkts: {}, TBwdPkts: {}", 
                        (newFlow.getValue()).getFlowId(), (newFlow.getValue()).getFlowDuration(), 
                       (newFlow.getValue()).getTotalFwdPackets(), (newFlow.getValue()).getTotalBackwardPackets());*/
                //System.out.println(jsonFlow1);
                //log.info(jsonFlow2);
                //log.info(topologyMonitor.getTopologyDevices());
                //log.info("=============================================================================");
                
                // avoid monitoring host
                if((newFlow.getValue()).getSrcIP().equals("10.0.2.201")||(newFlow.getValue()).getDstIP().equals("10.0.2.201"))continue; 
                 // save all attack events
                if (((newFlow.getValue()).getSrcIP().equals("10.0.2.111")||(newFlow.getValue()).getDstIP().equals("10.0.2.111"))) {
                    Thread IntrusionDetectionSystemThread = new Thread("IDS") {
                        public void run () {
                            try {
                                Client client = ClientBuilder.newClient();
                                String response = client.target("http://127.0.0.1:9001/AttackStarted").request().post(Entity.entity(jsonFlow1,MediaType.APPLICATION_JSON),String.class);
                                System.out.println ("saved:");
                            } catch (Exception e) {
                                System.out.println ("Error communicating trigger ATTACK event.");
                            }
                        }
                    };
                    IntrusionDetectionSystemThread.start();  
                }
                // flow filtering
                if ((!SelectiveFlowSampling((newFlow.getValue()).getTotalFwdPackets(),(newFlow.getValue()).getTotalBackwardPackets()))){}
                else {
                    //log.info("Selected Flow: {}", ++flows_selected_counter);
                    Thread IntrusionDetectionSystemThread = new Thread("IDS") {
                        public void run () {
                            try {
                                Client client = ClientBuilder.newClient();
                                //String response = client.target("http://localhost:9001/save").request().post(Entity.entity(jsonFlow1,MediaType.APPLICATION_JSON),String.class);
                                String response = client.target("http://127.0.0.1:9001/predict/slowrate").request().post(Entity.entity(jsonFlow1,MediaType.APPLICATION_JSON),String.class);
                                if (!response.equals("incomplete")){
                                    //log.info("Response from server: {}",response);
                                    System.out.println ("Response from slow-rate server:"+response);
                                }
                            } catch (Exception e) {
                                //log.error("Error communicating to slow rate service.");
                                System.out.println ("Error communicating to slow-rate service.");
                            }
                        }
                    };
                    IntrusionDetectionSystemThread.start();
                }
            } 
            flowGen.finishedFlowsTCP.keySet().removeAll(this.listOfKeysToRemove); // already processed flows
            finishedFlowsProcessing = false;  
        }  
    }


    // Selective flow sampling, defined for IDS applications, Jazi, et al. 2017 (Detecting HTTP-based App. Layer ...)
    private  boolean SelectiveFlowSampling(long fwdPkts, long bwdPkts){ // 
        double x = (double) (fwdPkts + bwdPkts);
        double z = 488*0.1;  // threshold, that indicates the flow size considered to be large.  Can be defined by o a % of available throughput
        double c = 0.3;   // fixed probability for small flows
        double n = 1;     // weighting parameter 
 
        double Pr_x = 0.00;  // sampling probability parameter
        if (x>z){
            Pr_x = z/(x*n); // Sampling probability for heavy flows
        }
        else{
            Pr_x = c;       // Sampling probability for small flows
        }
        // roulete
        return (Math.random() < (Pr_x));
    }

}
