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
package org.itesm.linkDelay.impl;
import org.itesm.linkDelay.intf.LinkQualityService;
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
import static org.itesm.linkDelay.impl.OsgiPropertyConstants.*;

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
        service = {LinkQualityService.class, },
        property = {
                PROBE_INTERVAL + ":Integer=" + PROBE_INTERVAL_DEFAULT,
                CALCULATE_INTERVAL + ":Integer=" + CALCULATE_INTERVAL_DEFAULT,
                LATENCY_AVERAGE_SIZE + ":Integer=" + LATENCY_AVERAGE_SIZE_DEFAULT,
        }
)

public class LinkQualityManager implements LinkQualityService{

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


    private static final DeviceId mirrorDeviceID = DeviceId.deviceId("of:0000000000000065");
    

    private ApplicationId appId;


    private ExecutorService blackHoleExecutor;


     /** Interval for sending probe. */
    private int probeInterval = PROBE_INTERVAL_DEFAULT;

    /** Interval for calculating latency. */
    private int calculateInterval = CALCULATE_INTERVAL_DEFAULT; // ms

    /** Number of buffered latency records. */
    private int latencyAverageSize = LATENCY_AVERAGE_SIZE_DEFAULT;

    private ProbeLinkQualityTask probeTask;
    private CalculateLinkQualityTask calculateTask;
    private ExecutorService probeWorker;
    private LinkProbeReceiver linkProbeReceiver;


     // hold last 5 records for averages.
    private final Map<Link, List<Float>> linkLatencies = new ConcurrentHashMap<>();
    private final Map<Link, Long> initLinklatencies = new ConcurrentHashMap<>();
    private final Map<DeviceId, Long> controlLinkLatencies = new ConcurrentHashMap<>();


    @Activate
    public void activate(ComponentContext context) {
        
        //cfgService.registerProperties(getClass());
        loadConfiguration(context);

        appId = coreService.registerApplication("mx.itesm.linkDelay");

        linkProbeReceiver = new LinkProbeReceiver();

        packetService.addProcessor(linkProbeReceiver, PacketProcessor.advisor(1));

        requestPushPacket();

        probeTask = new ProbeLinkQualityTask();
        calculateTask = new CalculateLinkQualityTask();
        probeWorker = Executors.newCachedThreadPool();
        probeWorker.submit(probeTask);
        probeWorker.submit(calculateTask);
        log.info("Started, {}", appId.id());

    }

    @Deactivate
    public void deactivate() {
        probeTask.requireShutdown();
        calculateTask.requireShutdown();
        probeWorker.shutdown();
        try {
            log.info("waits thread pool to shutdown...");
            probeWorker.awaitTermination(3, TimeUnit.SECONDS);
            log.info("thread pool shutdown ok.");
        } catch (InterruptedException e) {
            e.printStackTrace();
            log.warn("thread pool shutdown timeout.");
        }

        cancelPushPacket();
        packetService.removeProcessor(linkProbeReceiver);
        //cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped");

    }


    @Modified
    public void modified(ComponentContext context) {
        loadConfiguration(context);
    }


    /**
     *  Configuration
     */

    private void loadConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();

        probeInterval = Tools.getIntegerProperty(properties, PROBE_INTERVAL, PROBE_INTERVAL_DEFAULT);
        log.info("Configured. Probe Interval is configured to {} ms", probeInterval);

        calculateInterval = Tools.getIntegerProperty(properties, CALCULATE_INTERVAL, CALCULATE_INTERVAL_DEFAULT);
        log.info("Configured. Calculate Interval is configured to {} ms", calculateInterval);

        latencyAverageSize = Tools.getIntegerProperty(properties, LATENCY_AVERAGE_SIZE, LATENCY_AVERAGE_SIZE_DEFAULT);
        log.info("Configured. Latency Average Size is configured to {}", latencyAverageSize);
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
    public int getLinkLatency(Link link) {
        int sum = 0;
        List<Integer> latencies = linkLatencies.getOrDefault(link, Collections.EMPTY_LIST);
        for (Integer l : latencies) {
            sum += l;
        }
        return sum / latencyAverageSize;
    }

    @Override
    public Map<Link, Float> getAllLinkLatencies() {
        Map<Link, Float> result = new HashMap<>();
        linkLatencies.forEach((link, list) -> {
            // ignore traffic mirroring SW
            if(!(link.src().deviceId().toString().equals("of:0000000000000065")|| link.dst().deviceId().toString().equals("of:0000000000000065"))){
                //log.info("link:{}, Latencies:{}",link.toString(),list.toString());
                float sum = 0;
                float k = 0;
                for (Float l : list) {
                    sum += l;
                    k +=1;
                }
                //result.put(link, sum / latencyAverageSize);
                if(k>0) result.put(link, sum / k); // k max = latencyAverageSize
                else result.put(link, k);
            } 
            
        });
        return Collections.unmodifiableMap(result);
    }


    @Override
    public Map<Link, Long> getAllInitLatencies() {
        return Collections.unmodifiableMap(initLinklatencies);
    }


    @Override
    public Map<DeviceId, Long> getAllControlLatencies() {
        return Collections.unmodifiableMap(controlLinkLatencies);
    }

    @Override
    public Map<Link, List<Float>> getDebugLinkLatancies() {
        return Collections.unmodifiableMap(linkLatencies);
    }



    /**
     *  Calculate links' delay
     */

     private class CalculateLinkQualityTask implements Runnable {

        private boolean toRun = true;

        public void requireShutdown() {
            toRun = false;
        }

        @Override
        public void run() {
            while (toRun) {
                initLinklatencies.forEach((link, latency) -> {
                    latency -= controlLinkLatencies.getOrDefault(link.src().deviceId(), 0L) / 2;
                    latency -= controlLinkLatencies.getOrDefault(link.dst().deviceId(), 0L) / 2;

                    List<Float> records;
                    if (!linkLatencies.containsKey(link)) {
                        records = new ArrayList<>();
                        linkLatencies.put(link, records);
                    } else {
                        records = linkLatencies.get(link);
                    }

                    if (records.size() >= latencyAverageSize) {
                        records.remove(0);
                    }
                    records.add(latency < 0 ? 0.0f : ((float)latency)); // in miliseconds
                });
                //log.info("linkLatencies:{}",linkLatencies.toString());
                try {
                    Thread.sleep(calculateInterval);
                } catch (InterruptedException e) {
                    break;
                }
            }
            log.info("Calculate latency task stopped.");
        }
    }

    /**
     *  Sends (packet) probes to measure link delay
     */

    private class ProbeLinkQualityTask implements Runnable {

        private boolean toRun = true;

        public void requireShutdown() {
            toRun = false;
        }

        @Override
        public void run() {
            while (toRun) {
                for (Device device : deviceService.getAvailableDevices()) {

                    DeviceId deviceId = device.id();

                    // ignore traffic mirroring SW
                    if(deviceId.toString().equals("of:0000000000000065"))continue; 

                    TrafficTreatment treatmentAll = DefaultTrafficTreatment.builder()
                            .setOutput(PortNumber.ALL).build();
                    TrafficTreatment treatmentController = DefaultTrafficTreatment.builder()
                            .setOutput(PortNumber.CONTROLLER).build();

                    Ethernet probePkt = new Ethernet();
                    probePkt.setDestinationMACAddress(PROBE_DST);
                    probePkt.setSourceMACAddress(PROBE_SRC);
                    probePkt.setEtherType(PROBE_ETHERTYPE);

                    byte[] probeData = (deviceId.toString() + PROBE_SPLITER + System.currentTimeMillis()).getBytes();
                    probePkt.setPayload(new Data(probeData));
                    packetService.emit(new DefaultOutboundPacket(deviceId, treatmentAll,
                            ByteBuffer.wrap(probePkt.serialize())));


                    probeData = (deviceId.toString() + PROBE_SPLITER + System.currentTimeMillis()).getBytes();
                    probePkt.setPayload(new Data(probeData));
                    packetService.emit(new DefaultOutboundPacket(deviceId, treatmentController,
                            ByteBuffer.wrap(probePkt.serialize())));
                }
                try {
                    Thread.sleep(probeInterval);
                } catch (InterruptedException e) {
                    break;
                }
            }
            log.info("Probe latency task stopped.");
        }
    }

    /**
     * Packet processor responsible for gathering packets for link delay measurement
     */
    private class LinkProbeReceiver implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            
            long now = System.currentTimeMillis();

            if (context.isHandled()) {
                return;
            }

            Ethernet pkt = context.inPacket().parsed();
            if (pkt.getEtherType() == PROBE_ETHERTYPE) {
                byte[] probePacket = pkt.getPayload().serialize();
                String[] deviceProbe = new String(probePacket).split(PROBE_SPLITER);

                DeviceId probeSrc = DeviceId.deviceId(deviceProbe[0]);
                long before = Long.parseLong(deviceProbe[1]);

                if (context.inPacket().receivedFrom().port().equals(PortNumber.CONTROLLER)) {
                    //log.info("probeSrc: {}, probeDst: {}, t: {}", probeSrc, context.inPacket().receivedFrom().deviceId().toString(), now-before);
                    controlLinkLatencies.put(context.inPacket().receivedFrom().deviceId(),  (now - before));

                } else {
                    Set<Link> links = linkService.getIngressLinks(context.inPacket().receivedFrom());
                    if (links.isEmpty()) {
                        log.warn("link is not exist. {}", context.inPacket().receivedFrom());
                        return;
                    }
                    //log.info("probeSrc1: {}, probeDst1: {}, t1: {}, ", probeSrc, context.inPacket().receivedFrom().deviceId().toString(), now-before);
                    for (Link link : links) { // may >2 in broadcast network.
                        if (link.src().deviceId().equals(probeSrc)) {
                            initLinklatencies.put(link,  (now - before));
                            break;
                        }
                    }
                }
                context.block();
            }
        }
    }

}