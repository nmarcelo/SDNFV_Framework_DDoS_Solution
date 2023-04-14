/*
 * Copyright 2014 Open Networking Foundation
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
package org.itesm.resetConnection.impl;
import org.itesm.resetConnection.intf.ResetConnectionService;
import com.google.common.collect.ImmutableSet;
import org.onlab.packet.Data;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.util.KryoNamespace;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.MultiValuedTimestamp;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static org.itesm.resetConnection.impl.OsgiPropertyConstants.*;

import static org.slf4j.LoggerFactory.getLogger;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.constraint.BandwidthConstraint;
import org.onosproject.net.intent.constraint.LatencyConstraint;
import java.util.LinkedList;
import org.onlab.util.Bandwidth;
import java.time.Duration;
import java.time.temporal.ChronoUnit;


import java.util.EnumSet;
import java.util.Set;
import com.google.common.collect.Sets;


@Component(
        immediate = true,
        service = {ResetConnectionService.class, }
)

public class ResetConnection implements ResetConnectionService{

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    private ApplicationId appId;


    private ExecutorService blackHoleExecutor;

    private MyPacketProcessor packetProcessor;

    @Activate
    public void activate(ComponentContext context) {
        
        appId = coreService.registerApplication("mx.itesm.resetConnection");
        packetProcessor = new MyPacketProcessor();

        packetService.addProcessor(packetProcessor, PacketProcessor.advisor(1));

        requestPushPacket();

        log.info("Started, {}", appId.id());
    }

    @Deactivate
    public void deactivate() {
        cancelPushPacket();
        packetService.removeProcessor(packetProcessor);
        log.info("Stopped");
    }



    /**
     * Request packet in via packet service.
     */
    private void requestPushPacket() {
        TrafficSelector selector = DefaultTrafficSelector.builder().matchEthType(PROBE_ETHERTYPE).build();
        packetService.requestPackets(selector, PacketPriority.HIGH, appId);
    }

    /**
     * Cancel request for packet in via packet service.
     */
    
     private void cancelPushPacket() {
        TrafficSelector selector = DefaultTrafficSelector.builder().matchEthType(PROBE_ETHERTYPE).build();
        packetService.cancelPackets(selector, PacketPriority.HIGH, appId);
    }

    @Override
    public Boolean sendResetConnection(PortNumber portNumber, DeviceId deviceId, String sourceMACAddress, String destinationMACAddress, String sourceIpAddress, String destinationIpAddress, int SrcTcpPort) {

        TrafficTreatment treatmentAll = DefaultTrafficTreatment.builder()
                .setOutput(portNumber).build();

        // create and load packet 
        TCP tcp = new TCP();
        tcp.setDestinationPort(PCEP_PORT);
        tcp.setSourcePort(SrcTcpPort);
        tcp.setFlags((short)4); // set RST flag

        IPv4 ipv4 = new IPv4();
        ipv4.setProtocol(IPv4.PROTOCOL_TCP);
        ipv4.setSourceAddress(sourceIpAddress);
        ipv4.setDestinationAddress(destinationIpAddress);
        ipv4.setPayload(tcp);


        Ethernet probePkt = new Ethernet();
        probePkt.setDestinationMACAddress(destinationMACAddress);
        probePkt.setSourceMACAddress(sourceMACAddress);
        probePkt.setEtherType(Ethernet.TYPE_IPV4);

        probePkt.setPayload(ipv4);

        packetService.emit(new DefaultOutboundPacket(deviceId, treatmentAll,
                ByteBuffer.wrap(probePkt.serialize())));
        
        return true;
    }

    /**
     * Packet processor responsible for gathering packets for link delay measurement
     */
    private class MyPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Do nothing
        }
    }

}