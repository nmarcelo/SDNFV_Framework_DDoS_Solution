package org.itesm.trafficEngineering;

import org.itesm.linkDelay.intf.LinkQualityService;

import org.itesm.resetConnection.intf.ResetConnectionService;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.Ethernet;

import javax.ws.rs.*;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.onlab.graph.ScalarWeight;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.statistic.PortStatisticsService;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.intent.util.IntentFilter;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.net.topology.PathService;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.net.link.*;
import org.onosproject.net.*;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.instructions.*;



import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;  
import java.util.Set;  



/**
 * REST API
 */
@Path("")
public class TrafficEngineeringResource extends AbstractWebResource {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private static final int DROP_RULE_TIMEOUT = 50;
    private static final int FLOW_TIMEOUT = 1000;
    private static final DeviceId mirrorDeviceID = DeviceId.deviceId("of:0000000000000065");
    private static final PortNumber mirrorPortNumber = PortNumber.portNumber(1);  // can change

    
    @GET
    @Path("/test")
    public Response getTest() {
        ObjectNode responseBody = new ObjectNode(JsonNodeFactory.instance);
        responseBody.put("message", "it works!");
        return Response.status(200).entity(responseBody).build();
    }

    /**
     * Get bandwidth of all links and edges.
     *
     * @return BW [Kbps] of topology
     */
    @GET
    @Path("state/bandwidth")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTopologyBandwidth() {

        LinkService linkService = get(LinkService.class);
        HostService hostService = get(HostService.class);
        PortStatisticsService portStatisticsService = get(PortStatisticsService.class);
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode_ = mapper.createObjectNode();

        ArrayNode linksNode = mapper.createArrayNode();

        // bandwidth of links between SWs
        for (Link link: linkService.getActiveLinks()){

            // get badwidth utilization
            long srcBw = portStatisticsService.load(link.src()).rate() * 8 / 1000;  // unit: Kbps
            long dstBw = portStatisticsService.load(link.dst()).rate() * 8 / 1000;  // unit: Kbps

            // ignore traffic mirroring SW
            if (link.src().deviceId().toString().equals("of:0000000000000065") || link.dst().deviceId().toString().equals("of:0000000000000065")) continue; 
            
            // create bw utilization to be sent
            ObjectNode linkNode = mapper.createObjectNode()
                    .put("src", link.src().deviceId().toString())
                    .put("dst", link.dst().deviceId().toString())
                    .put("bw", (srcBw + dstBw) / 2 );

            // add link bwd link info to be sent
            linksNode.add(linkNode);
        }

        // links bw info to sent
        rootNode_.set("links", linksNode);

        return ok(rootNode_).build();
    }




    /**
     * Get latency of all links
     *
     * @return BW [Kbps] of topology
     */

    @GET
    @Path("state/latency")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLinksLatency() {

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode_ = mapper.createObjectNode();
        ArrayNode linksNode = mapper.createArrayNode();

        Map<Link, Float> linksDelay;
        LinkQualityService service = getService(LinkQualityService.class);
        log.info("====== Link Latencies ======");
        linksDelay = service.getAllLinkLatencies();

        linksDelay.forEach((link, latency)-> {
            // create latency to be sent
            ObjectNode linkNode = mapper.createObjectNode()
                    .put("src", link.src().deviceId().toString())
                    .put("dst", link.dst().deviceId().toString())
                    .put("latency", (latency));
            // add link bwd link info to be sent
            linksNode.add(linkNode);

        });

        // links latency info to sent
        rootNode_.set("links", linksNode);
        
        return Response.status(200).entity(rootNode_).build();
    }
            

    /**
     * Get state of connectivity between two hosts: INTENTS
     *
     * @return 200 OK
     */
    @GET
    @Path("state/connectivity")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnectivityBandwidth() {

        CoreService coreService = get(CoreService.class);
        IntentService intentService = get(IntentService.class);
        FlowRuleService flowRuleService = get(FlowRuleService.class);
        IntentFilter intentFilter = new IntentFilter(intentService, flowRuleService);
        HostService hostService = get(HostService.class);
        LinkService linkService = get(LinkService.class);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ArrayNode connsNode = mapper.createArrayNode();

        ApplicationId h2hAppId = coreService.getAppId("mx.itesm.intentBasedNetworking");
        ApplicationId pathAppId = coreService.getAppId("org.itesm.path");

        for (Intent intent : intentService.getIntents()) {
            // require host-to-host intent or path intent
            ApplicationId appId = intent.appId();
            if(appId.equals(h2hAppId) || appId.equals(pathAppId)) {
                List<Intent> installable = intentService.getInstallableIntents(intent.key());
                // intent-related flow entries
                List<List<FlowEntry>> flowEntriesList = intentFilter.readIntentFlows(installable);
                if(flowEntriesList.size() == 0) continue;
                List<FlowEntry> flowEntries = flowEntriesList.get(0);
                long _life = 0;
                long _byte = 0;
                long _flowId = 0;
                // select flow entry with max life for this intent
                for(FlowEntry flowEntry: flowEntries) {
                    if (flowEntry.life() > _life) {
                        _life = flowEntry.life();
                        _byte = flowEntry.bytes();
                        _flowId = flowEntry.id().value();
                    }
                }
                Iterator<NetworkResource> resourcesIterator = intent.resources().iterator();
                DeviceId srcDev = null;
                DeviceId dstDev = null;
                HostId oneId  = null;
                HostId twoId  = null;

                if (intent instanceof PointToPointIntent) {
                    ConnectPoint connectPointOut = ((PointToPointIntent) intent).filteredEgressPoint().connectPoint();
                    Link linkconn = getNodesConnection(linkService, connectPointOut);
                    if (linkconn==null) continue;
                    srcDev = linkconn.src().deviceId();
                    dstDev = linkconn.dst().deviceId();
                }
                if (intent instanceof SinglePointToMultiPointIntent) {
                    ConnectPoint connectPointOut = ((((SinglePointToMultiPointIntent) intent).filteredEgressPoints()).iterator()).next().connectPoint();
                    Link linkconn = getNodesConnection(linkService, connectPointOut);
                    if (linkconn==null) continue;
                    srcDev = linkconn.src().deviceId();
                    dstDev = linkconn.dst().deviceId();
                }
                if (intent instanceof PathIntent) {
                    while(resourcesIterator.hasNext()){
                        NetworkResource networkResource = resourcesIterator.next();
                        if (networkResource instanceof DefaultEdgeLink) {
                            if (oneId == null) {
                                oneId = ((DefaultEdgeLink) networkResource).hostId();
                            }
                            else if (twoId == null){
                                twoId = ((DefaultEdgeLink) networkResource).hostId();
                            }
                        }
                    }
                }
                ObjectNode node = mapper.createObjectNode();
                node.put( "one", srcDev.toString())
                        .put("two", dstDev.toString())
                        .put("byte", _byte)
                        .put("life", _life)
                        .put("flowid", _flowId)
                        .put("appid", intent.appId().name());
                connsNode.addPOJO(node);
            }
        }

        rootNode.set("connectivities", connsNode);

        return ok(rootNode).build();

    }


    /**
     * Get state of connectivity between two hosts: OBJECTIVE FORWARDING FRAMEWORK
     *
     * @return 200 OK
     */
    @GET
    @Path("state/connsbandwidth")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnectivityBandwidthOBJFWD() {

        CoreService coreService = get(CoreService.class);
        IntentService intentService = get(IntentService.class);
        FlowRuleService flowRuleService = get(FlowRuleService.class);
        IntentFilter intentFilter = new IntentFilter(intentService, flowRuleService);
        HostService hostService = get(HostService.class);
        LinkService linkService = get(LinkService.class);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ArrayNode connsNode = mapper.createArrayNode();

        ApplicationId dropAppId = coreService.getAppId("mx.itesm");
        int i = 0; 

        for (Host hostSrc : hostService.getHosts()) {  // Source hosts
            //ignore mirroring host
            if ((hostSrc.location().deviceId()).equals(mirrorDeviceID)) continue;

            // ignore testing pc
            Boolean IsIpOfTestingHost = false;
            for (IpAddress IpOfHost : hostSrc.ipAddresses()) {
                if (IpOfHost.toString().equals("10.0.2.201")) IsIpOfTestingHost=true;
            }
            if (IsIpOfTestingHost) continue;


            for (Host hostDst : hostService.getHosts()) { // destination hosts
                //ignore mirroring host
                if ((hostDst.location().deviceId()).equals(mirrorDeviceID)) continue;

                // ignore testing pc
                IsIpOfTestingHost = false;
                for (IpAddress IpOfHost : hostDst.ipAddresses()) {
                    if (IpOfHost.toString().equals("10.0.2.201")) IsIpOfTestingHost=true;
                }
                if (IsIpOfTestingHost) continue;

                //log.info("hostSrc:{}, hostDst: {} ,deviceId: {}, i: {}",hostSrc.mac(),hostDst.mac(),hostSrc.location().deviceId(),i); 

                long _life = Long.MAX_VALUE;
                long _byte = 0;
                long _flowId = 0;
                
                int counter = 0;
                for (FlowEntry flowEntry : flowRuleService.getFlowEntries(hostSrc.location().deviceId())){  // flows entries 
                    // avoid Drop rules statistics

                    Boolean isdropRule = false;
                    for (Instruction instruction : flowEntry.treatment().allInstructions()) {
                        if (instruction.type().equals(Instruction.Type.NOACTION)){
                            isdropRule = true;
                        }
                    }
                    if (isdropRule) continue;
                    MacAddress srcAddress = null;
                    MacAddress dstAddress = null;
                    for (Criterion criterion : flowEntry.selector().criteria()) {
                        if (criterion.type().equals(Criterion.Type.ETH_DST))dstAddress = ((EthCriterion)criterion).mac();
                        if (criterion.type().equals(Criterion.Type.ETH_SRC))srcAddress = ((EthCriterion)criterion).mac();
                        if ((hostSrc.mac()).equals(srcAddress) && (hostDst.mac()).equals(dstAddress)) {       // flow rule of eth type
                            if (flowEntry.life() < _life) {// select flow entry with min life for this destination host
                                _life = flowEntry.life();
                                _byte = flowEntry.bytes();
                                _flowId = flowEntry.id().value();
                            }   
                        }
                    }
                }
                i ++;
                //log.info("hostSrc:{}, hostDst: {} ,deviceId: {}",hostSrc.mac(),hostDst.mac(),hostSrc.location().deviceId());  
                //if(_byte>0) log.info("Flow rules: _life: {}, _byte: {}, _flowId : {}",_life, _byte,_flowId); 
                ObjectNode node = mapper.createObjectNode();
                node.put( "Src", hostSrc.mac().toString())
                        .put("Dst", hostDst.mac().toString())
                        .put("byte", _byte)
                        .put("life", _life)
                        .put("flowid", _flowId);
                connsNode.addPOJO(node);
            }
        }

        rootNode.set("connectivities", connsNode);
        //log.info("Size: {}", i);
        return ok(rootNode).build();

    }


    /**
     * Post a list of rerouting paths.
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("reroute")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response reRouteIntents(InputStream stream) {

        ObjectMapper mapper = new ObjectMapper();

        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        try {

            ObjectNode rootNode = mapper.createObjectNode();

            ProviderId providerId = new ProviderId("provider.scheme", "provider.id");
            Routes routes = mapper.readValue(stream, Routes.class);



            List<Route> routeList = routes.getPaths();
            if (routeList == null || routeList.size() == 0) {
                rootNode.put("response", "no paths");
                return ok(rootNode).build();
            }
            for (Route route : routeList) {
                HostId srcId = route.getSrcId();
                HostId dstId = route.getDstId();
                List<DeviceId> deviceIds = route.getDeviceIds();
                submitPathIntent(providerId, deviceIds, srcId, dstId);
            }

            rootNode.put("response", "OK");
            return ok(rootNode).build();

        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }

    }

    private void submitPathIntent(ProviderId providerId, List<DeviceId> deviceIds, HostId srcId, HostId dstId) {
        
        HostService hostService = get(HostService.class);
        PathService pathService = get(PathService.class);
        IntentService intentService = get(IntentService.class);
        CoreService coreService = get(CoreService.class);

        List<Link> links = new ArrayList<>();

        EdgeLink srcLink = new DefaultEdgeLink(providerId, new ConnectPoint((ElementId) srcId, PortNumber.portNumber(0)), hostService.getHost(srcId).location(),true);
        links.add(srcLink);

        int deviceNum = deviceIds.size();
        for (int i = 0; i < deviceNum - 1; i++) {
            links.addAll(pathService
                    .getPaths(deviceIds.get(i), deviceIds.get(i + 1))
                    .iterator()
                    .next()
                    .links()
            );
        }

        EdgeLink dstLink = new DefaultEdgeLink(providerId, new ConnectPoint((ElementId) dstId, PortNumber.portNumber(0)), hostService.getHost(dstId).location(),false);
        links.add(dstLink);

        int priority = 1;

        // set priority of this path intent the same as the existing one
        ApplicationId appId = coreService.registerApplication("org.itesm.path");
        Key key = Key.of("Path(" + srcId.toString() + dstId.toString() + ")", appId);
        PathIntent pathIntent = (PathIntent) intentService.getIntent(key);
        if(pathIntent != null) {
            priority = pathIntent.priority();
            // remove the existing one
            while (intentService.getIntent(key) != null) {
                intentService.withdraw(pathIntent);
                intentService.purge(pathIntent);
            }
        }

        // set priority of this path intent higher than host to host intent which builds shortest path
        ApplicationId h2hAppId = coreService.getAppId("mx.itesm.intentBasedNetworking");
        Key h2hIntentKey;
        if(srcId.toString().compareTo(dstId.toString()) < 0) {
            h2hIntentKey= Key.of(srcId.toString() + dstId.toString(), h2hAppId);
        } else {
            h2hIntentKey = Key.of( dstId.toString() + srcId.toString(), h2hAppId);
        }
        HostToHostIntent h2hIntent = (HostToHostIntent) intentService.getIntent(h2hIntentKey);
        if(h2hIntent != null && intentService.getIntentState(h2hIntentKey) == IntentState.INSTALLED) {
            priority = h2hIntent.priority();
        }

        pathIntent = PathIntent.builder()
                .path( new DefaultPath(providerId, links, ScalarWeight.toWeight(1)))
                .appId(appId)
                .key(key)
                .priority(priority + 1)
                .selector(DefaultTrafficSelector.builder().matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build())
                .treatment(DefaultTrafficTreatment.emptyTreatment())
                .build();

        // submit path intent
        while (intentService.getIntent(key) == null) {
            intentService.submit(pathIntent);
        }

    }

    private Link getNodesConnection(LinkService linkService, ConnectPoint connectPoint) {

        for (Link link: linkService.getActiveLinks()){
           // unit: Kbps
            if (link.src().deviceId().toString().equals("of:0000000000000065") || link.dst().deviceId().toString().equals("of:0000000000000065")) continue; // ignore traffic mirroring SW
            if (connectPoint.equals(link.src())) {
                    return link;
            }         
        }

        return null;

    }

        /**
     * Post a list of dropping pairs of hosts.
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("dropping")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response droppingStrategy(InputStream stream) {
        HostService hostService = get(HostService.class);
        FlowObjectiveService flowObjectiveService = get(FlowObjectiveService.class);
        CoreService coreService = get(CoreService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        ApplicationId appId = coreService.registerApplication("mx.itesm");

        try {

            ObjectNode rootNode = mapper.createObjectNode();

            ProviderId providerId = new ProviderId("provider.scheme", "provider.id");
            Map<String, Object> suspicious_ = mapper.readValue(stream, Map.class);
            //Routes routes = mapper.readValue(stream, Routes.class);

            if (suspicious_ == null || suspicious_.size() == 0) {
                rootNode.put("response", "No given hosts to drop packets");
                return ok(rootNode).build();
            }

             for (Map.Entry<String, Object> entry : suspicious_.entrySet()) {
                String src = (((Map)entry.getValue()).get("macsrc")).toString();
                String dst = (((Map)entry.getValue()).get("macdst")).toString();
                HostId srcId = null;
                HostId dstId = null;
                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(src));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    srcId = host.id();
                }
                hosts = hostService.getHostsByMac(MacAddress.valueOf(dst));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    dstId = host.id();
                }

                if (srcId == null || dstId == null) continue;
                
                // at src device
                TrafficSelector objectiveSelector1 = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective1 = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector1)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(101)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

                
                flowObjectiveService.forward(hostService.getHost(srcId).location().deviceId(),
                                         objective1);

                log.info("Drop rule installed for: src: {}, dst: {}, Dev : {}", srcId.toString(), dstId.toString(),
                    hostService.getHost(srcId).location().deviceId().toString());

                // at dst device
                TrafficSelector objectiveSelector2 = DefaultTrafficSelector.builder()
                        .matchEthSrc(dstId.mac()).matchEthDst(srcId.mac()).build();

                ForwardingObjective objective2 = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector2)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(101)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();
                
                flowObjectiveService.forward(hostService.getHost(dstId).location().deviceId(),
                                         objective2);

                log.info("Drop rule installed for: src: {}, dst: {}, Dev : {}", dstId.toString(), srcId.toString(),
                    hostService.getHost(dstId).location().deviceId().toString());
            }

            rootNode.put("response", "OK");
            return ok(rootNode).build();

        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }

    }


    /**
     * Post a list of pairs of hosts to deletes blocking rules given by mx.itesm.
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("removeBlockRules")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response removeBlockRulesStrategy(InputStream stream) {
        HostService hostService = get(HostService.class);
        FlowObjectiveService flowObjectiveService = get(FlowObjectiveService.class);
        CoreService coreService = get(CoreService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        FlowRuleService flowRuleService = get(FlowRuleService.class);

        try {

            ObjectNode rootNode = mapper.createObjectNode();

            ProviderId providerId = new ProviderId("provider.scheme", "provider.id");
            Map<String, Object> suspicious_ = mapper.readValue(stream, Map.class);
            //Routes routes = mapper.readValue(stream, Routes.class);

            if (suspicious_ == null || suspicious_.size() == 0) {
                rootNode.put("response", "No given hosts to remove block rule");
                return ok(rootNode).build();
            }

             ApplicationId appId = coreService.getAppId("mx.itesm");
             short groupId = 0;

             for (Map.Entry<String, Object> entry : suspicious_.entrySet()) {
                String src = (((Map)entry.getValue()).get("macsrc")).toString();
                String dst = (((Map)entry.getValue()).get("macdst")).toString();

                HostId srcId = null;
                HostId dstId = null;
                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(src));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    srcId = host.id();
                }
                hosts = hostService.getHostsByMac(MacAddress.valueOf(dst));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    dstId = host.id();
                }

                if (srcId == null || dstId == null || appId == null) continue;


                for (FlowRule flowRule : flowRuleService.getFlowRulesByGroupId​(appId, groupId)) {  // delete flows entries at the source 
                    if(!((flowRule.deviceId().equals(hostService.getHost(srcId).location().deviceId())) || flowRule.deviceId().equals(hostService.getHost(dstId).location().deviceId()))) continue;
                    
                    MacAddress srcAddress = null;
                    MacAddress dstAddress = null;

                    for (Criterion criterion : flowRule.selector().criteria()) {
                        if (criterion.type().equals(Criterion.Type.ETH_DST))dstAddress = ((EthCriterion)criterion).mac();
                        if (criterion.type().equals(Criterion.Type.ETH_SRC))srcAddress = ((EthCriterion)criterion).mac();
                        if ((srcId.mac()).equals(srcAddress) && (dstId.mac()).equals(dstAddress) || (srcId.mac()).equals(dstAddress) && (dstId.mac()).equals(srcAddress)) { 
                            flowRuleService.removeFlowRules(flowRule);
                            //log.info("Remove: {}", flowRule.toString());
                            }   
                    }
                }
                        
                log.info("Remove block rule for: src: {}, dst: {}, Dev : {}", srcId.toString(), dstId.toString(),
                    hostService.getHost(srcId).location().deviceId().toString());

                } 

            rootNode.put("response", "OK");
            return ok(rootNode).build();


        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }

    }



    /**
     * Post a list of pairs of hosts to delete Snat rules rules given by org.itesm.mtd.
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("removeSNATRules")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response removeSNATRulesStrategy(InputStream stream) {
        HostService hostService = get(HostService.class);
        FlowObjectiveService flowObjectiveService = get(FlowObjectiveService.class);
        CoreService coreService = get(CoreService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        FlowRuleService flowRuleService = get(FlowRuleService.class);

        try {

            ObjectNode rootNode = mapper.createObjectNode();

            ProviderId providerId = new ProviderId("provider.scheme", "provider.id");
            Map<String, Object> suspicious_ = mapper.readValue(stream, Map.class);
            //Routes routes = mapper.readValue(stream, Routes.class);

            if (suspicious_ == null || suspicious_.size() == 0) {
                rootNode.put("response", "No given hosts to remove SNAT rules");
                return ok(rootNode).build();
            }

             ApplicationId appId = coreService.getAppId("org.itesm.mtd");
             short groupId = 0;

             for (Map.Entry<String, Object> entry : suspicious_.entrySet()) {
                String src = (((Map)entry.getValue()).get("macsrc")).toString();
                String dst = (((Map)entry.getValue()).get("macdst")).toString();

                Host srcHost = null;
                Host dstHost = null;
                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(src));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    srcHost= host;
                }
                hosts = hostService.getHostsByMac(MacAddress.valueOf(dst));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    dstHost = host;
                }

                if (srcHost == null || dstHost == null || appId == null) continue;


                IpAddress IpOfSrc= null;
                for (IpAddress IpOfHost : srcHost.ipAddresses()) {
                        IpOfSrc = IpOfHost;
                }

                if(IpOfSrc==null) continue;
                IpPrefix scrIPPrefix = IpPrefix.valueOf(IpOfSrc, 32);

                IpAddress IpOfDst = null;
                for (IpAddress IpOfHost : dstHost.ipAddresses()) {
                        IpOfDst = IpOfHost;
                }

                if(IpOfDst==null) continue;
                IpPrefix dstIPPrefix = IpPrefix.valueOf(IpOfDst, 32);

                for (FlowRule flowRule : flowRuleService.getFlowRulesByGroupId​(appId, groupId)) {  // delete flows entries                  
                    IpPrefix srcAddress = null;
                    IpPrefix dstAddress = null;

                    for (Criterion criterion : flowRule.selector().criteria()) {
                        if (criterion.type().equals(Criterion.Type.IPV4_DST))dstAddress = ((IPCriterion)criterion).ip();
                        if (criterion.type().equals(Criterion.Type.IPV4_SRC))srcAddress = ((IPCriterion)criterion).ip();
                        if ((scrIPPrefix).equals(srcAddress) || (scrIPPrefix).equals(dstAddress)) { 
                            flowRuleService.removeFlowRules(flowRule);
                            //log.info("Remove: {}", flowRule.toString());
                            }   
                    }
                }
                        
                log.info("Remove block rule for: src: {}, dst: {}, Dev : {}", srcHost.id().toString(), dstHost.id().toString(),
                    hostService.getHost(srcHost.id()).location().deviceId().toString());

                } 

            rootNode.put("response", "OK");
            return ok(rootNode).build();


        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }

    }


        /**
     * Post a list of rerouting paths 
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("rerouting")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response reroutingStrategy(InputStream stream) {
        HostService hostService = get(HostService.class);
        LinkService linkService = get(LinkService.class);
        PathService pathService = get(PathService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        

        try {

            ObjectNode rootNode = mapper.createObjectNode();

            ProviderId providerId = new ProviderId("provider.scheme", "provider.id");
            Map<String,  Map<String, String>> newPaths = mapper.readValue(stream, Map.class);
          

            if (newPaths == null || newPaths.size() == 0) {
                rootNode.put("response", "No given paths to reroute");
                return ok(rootNode).build();
            }

             for (Map.Entry<String, Map<String, String>> newpath : newPaths.entrySet()) { // iterate over paths
                String [] macs = newpath.getKey().split("-"); 
                String macsrc = macs[0];
                String macdst = macs[1];
                HostId srcHost = null;
                HostId dstHost = null;
                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(macsrc));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    srcHost = host.id();
                }

                hosts = hostService.getHostsByMac(MacAddress.valueOf(macdst));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    dstHost = host.id();
                }
                int i = 0;
                DeviceId srcDevId = null;
                DeviceId dstDevId = null;
                for (Map.Entry<String, String> route : newpath.getValue().entrySet()) { // iterate over links
                    if(i==0) {  // First device
                        srcDevId = DeviceId.deviceId(route.getValue());
                    } else {
                        dstDevId = DeviceId.deviceId(route.getValue());
                        for (Link link:linkService.getActiveLinks()){
                            if(link.src().deviceId().equals(srcDevId) && link.dst().deviceId().equals(dstDevId)){
                                installRule(srcHost, dstHost, link.src().deviceId(), link.src().port(),false);
                                continue;
                            }
                        }
                        srcDevId = DeviceId.deviceId(route.getValue()); 
                    }
                    i++; //  next device
                }

                
                installRule(srcHost, dstHost, hostService.getHost(dstHost).location().deviceId(),
                                hostService.getHost(dstHost).location().port(), true); // connect dstHost to SW.
              
                log.info("New path installed for: src: {}, dst: {}, path:{}",  srcHost.toString(), dstHost.toString(),
                newpath.getValue());
            }

            rootNode.put("response", "OK");
            return ok(rootNode).build();

        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }

    }

    /**
     * Install path rules
     *
     */

    private void installRule(HostId srcHost, HostId dstHost, DeviceId deviceId,PortNumber portNumber, Boolean isEndDevice) {
        FlowObjectiveService flowObjectiveService = get(FlowObjectiveService.class);
        CoreService coreService = get(CoreService.class);

        TrafficTreatment treatment;

        /*log.info("Installing: treatment src: {}, dst: {}, DeviceId: {}, PortNumber: {}, isEndDevice: {}", 
            srcHost.toString(), dstHost.toString(), deviceId.toString(), portNumber.toString(), String.valueOf(isEndDevice));*/

        if(isEndDevice){
            treatment = DefaultTrafficTreatment.builder()
            .setOutput(portNumber)
            .setOutput(mirrorPortNumber)
            .build();           
        }else{
            treatment = DefaultTrafficTreatment.builder()
            .setOutput(portNumber)
            .build();
        }


        TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcHost.mac()).matchEthDst(dstHost.mac()).build();

        ApplicationId appId = coreService.registerApplication("mx.itesm");

       ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(objectiveSelector)
                .withTreatment(treatment)
                .withPriority(101)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(DROP_RULE_TIMEOUT) // same that for the timeout 
                .add();

       flowObjectiveService.forward(deviceId,
                                     forwardingObjective);
    }


    /**
     * Set action Reset Communication
     *
     * @return 200 OK
     */

    @POST
    @Path("resetCommunication")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response ResetConnectionAction(InputStream stream) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        HostService hostService = get(HostService.class);

        ResetConnectionService reset_service = getService(ResetConnectionService.class);

        try {

            ObjectNode rootNode = mapper.createObjectNode();
            Map<String, Object> suspicious_ = mapper.readValue(stream, Map.class);

            if (suspicious_ == null || suspicious_.size() == 0) {
                rootNode.put("response", "No given hosts to shallow");
                return ok(rootNode).build();
            }

            for (Map.Entry<String, Object> entry : suspicious_.entrySet()) {
                String attacker_mac = (((Map)entry.getValue()).get("macattacker")).toString();
                String server_mac = (((Map)entry.getValue()).get("macserver")).toString();
                String tcp_attacker = (((Map)entry.getValue()).get("tcpattacker")).toString();

                Host attackerHost = null;
                Host serverHost = null;

                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(attacker_mac));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    attackerHost = host;
                }
                hosts = hostService.getHostsByMac(MacAddress.valueOf(server_mac));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    serverHost = host;
                }

                IpAddress IpOfAttacker= null;
                for (IpAddress IpOfHost : attackerHost.ipAddresses()) {
                        IpOfAttacker = IpOfHost;
                }

                IpAddress IpOfServer = null;
                for (IpAddress IpOfHost : serverHost.ipAddresses()) {
                        IpOfServer = IpOfHost;
                }


                //TODO use interface to send RST
                reset_service.sendResetConnection(hostService.getHost(serverHost.id()).location().port(), 
                                                        hostService.getHost(serverHost.id()).location().deviceId(),
                                                        attacker_mac, server_mac, IpOfAttacker.toString(), IpOfServer.toString(), Integer.valueOf(tcp_attacker));
            }
            
            rootNode.put("response", "OK");
            return ok(rootNode).build();

        } catch (Exception e) {
        return Response
                .status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(e.toString())
                .build();
        }

        
    }



    /**
     * GET get all hosts
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @GET
    @Path("getHosts")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getHosts() {
        HostService hostService = get(HostService.class);
        CoreService coreService = get(CoreService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        try {

            ObjectNode rootNode_ = mapper.createObjectNode();
            ArrayNode hostsNode = mapper.createArrayNode();

            for (Host host: hostService.getHosts()){
                // unit: Kbps
                if(host.location().deviceId().toString().equals("of:0000000000000065")) continue; // ignore flow collector PC
                
                // ignore testing pc
                Boolean IsIpOfTestingHost = false;
                for (IpAddress IpOfHost : host.ipAddresses()) {
                    if (IpOfHost.toString().equals("10.0.2.201")) IsIpOfTestingHost=true;
                }
                if (IsIpOfTestingHost) continue;

                ObjectNode hostNode = mapper.createObjectNode()
                        .put("host", host.mac().toString())
                        .put("location", host.location().deviceId().toString());

                hostsNode.add(hostNode);
            }

            rootNode_.set("hosts", hostsNode);
            return Response.status(200).entity(rootNode_).build();

        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }
    }



    /**
     * POST get host location
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("getHostLocation")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getHostLocation(InputStream stream) {
        HostService hostService = get(HostService.class);
        CoreService coreService = get(CoreService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        ObjectNode rootNode_ = mapper.createObjectNode();
        ArrayNode locationNode = mapper.createArrayNode();
        

        try {

            ObjectNode rootNode = mapper.createObjectNode();

            Map<String, Object> host_locate = mapper.readValue(stream, Map.class);

            if (host_locate == null || host_locate.size() == 0) {
                rootNode.put("response", "No given hosts to locate");
                return ok(rootNode).build();
            }
             

             for (Map.Entry<String, Object> entry : host_locate.entrySet()) {
                String macHost = (((Map)entry.getValue()).get("macHost")).toString();

                Host host_ = null;

                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(macHost));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    host_ = host;
                }

                if (host_.id() == null) continue; 

                ObjectNode node = mapper.createObjectNode();
                node.put("location", (hostService.getHost(host_.id()).location().deviceId()).toString());
                locationNode.addPOJO(node);
            }
            rootNode_.set("locations", locationNode);
            return Response.status(200).entity(rootNode_).build();

        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }
        

    }



    /**
     * POST moving Target Defense strategy
     *
     * @param stream input JSON
     * @return 200 OK
     */
    @POST
    @Path("movingTargetDefense")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response movingTargetDefense(InputStream stream) {
        HostService hostService = get(HostService.class);
        CoreService coreService = get(CoreService.class);
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        try {

            ObjectNode rootNode = mapper.createObjectNode();

            Map<String, Object> suspicious_ = mapper.readValue(stream, Map.class);

            if (suspicious_ == null || suspicious_.size() == 0) {
                rootNode.put("response", "No given hosts to shallow");
                return ok(rootNode).build();
            }
             ApplicationId appId = coreService.registerApplication("org.itesm.mtd"); // ID of RFwd is mx.itesm.reactiveFwd 
             short groupId = 0;

             for (Map.Entry<String, Object> entry : suspicious_.entrySet()) {
                String attacker = (((Map)entry.getValue()).get("macattacker")).toString();
                String server = (((Map)entry.getValue()).get("macserver")).toString();
                String shadowserver = (((Map)entry.getValue()).get("macshadowserver")).toString();

                Host attackerHost = null;
                Host serverHost = null;
                Host shadowserverHost = null;

                Set<Host> hosts = hostService.getHostsByMac(MacAddress.valueOf(attacker));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    attackerHost = host;
                }
                hosts = hostService.getHostsByMac(MacAddress.valueOf(server));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    serverHost = host;
                }
                hosts = hostService.getHostsByMac(MacAddress.valueOf(shadowserver));
                if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    shadowserverHost = host;
                }

                

                if (attackerHost.id() == null || serverHost.id() == null || shadowserverHost.id() == null || appId == null) continue;

                // TODO reroute shadow server
                log.info("macattacker: {}", attackerHost.mac());
                log.info("macserver: {}", serverHost.mac());
                log.info("macshadowserver: {}", shadowserverHost.mac());

                if(rerouteTowardsShadowServer(attackerHost, serverHost, shadowserverHost, appId)){ // if success on installing path
                    log.info("rules installed for: src: {}, dst: {}", attackerHost.id().toString(), shadowserverHost.id().toString());
                    
                }
                else{
                    log.info("Unable to install for: src: {}, dst: {}", attackerHost.id().toString(), shadowserverHost.id().toString());
                }
                
            }
            rootNode.put("response", "OK");
            return ok(rootNode).build();

        } catch (Exception e) {
            return Response
                    .status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.toString())
                    .build();
        }

    }


    /**
     * Install forwading path towards the shadow server
     *
     */

    private boolean rerouteTowardsShadowServer(Host attackerHost, Host serverHost, Host shadowserverHost, ApplicationId appId) {
        TopologyService topologyService = get(TopologyService.class);

        HostService hostService = get(HostService.class);

        DeviceId deviceId_attacker = hostService.getHost(attackerHost.id()).location().deviceId();
        DeviceId deviceId_shadowServer = hostService.getHost(shadowserverHost.id()).location().deviceId();
        PortNumber portNumber_attacker = hostService.getHost(attackerHost.id()).location().port();
        PortNumber portNumber_shadowServer = hostService.getHost(shadowserverHost.id()).location().port();

        // Install rule in the ATTACKER DEVICE

        // Get a set of paths that lead from here to the destination edge switch.

        Set<org.onosproject.net.Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                                             deviceId_attacker,
                                             deviceId_shadowServer);
        if (paths.isEmpty()) {
            // If there are no paths, flood and bail.
            return false;
        }

        // Otherwise, pick a path that does not lead back to where we
        // came from; if no such path, flood and bail.
        org.onosproject.net.Path path = pickForwardPathIfPossible(paths, portNumber_attacker);

        if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                         deviceId_attacker, attackerHost.mac(), shadowserverHost.mac());
                return false;
            }

        // Otherwise forward and be done with it.
        intallPathMTD(attackerHost, serverHost, shadowserverHost, appId, path, deviceId_attacker,  true);



        // Install rule in the SHADOW SERVER DEVICE

        // Get a set of paths that lead from here to the destination edge switch.
        paths = topologyService.getPaths(topologyService.currentTopology(),
                                             deviceId_shadowServer,
                                             deviceId_attacker);
        if (paths.isEmpty()) {
            // If there are no paths, flood and bail.
            return false;
        }

        // Otherwise, pick a path that does not lead back to where we
        // came from; if no such path, flood and bail.
        path = pickForwardPathIfPossible(paths, portNumber_shadowServer);

        if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                         deviceId_shadowServer, shadowserverHost.mac(), attackerHost.mac());
                return false;
            }

        // Otherwise forward and be done with it.
        intallPathMTD(attackerHost, serverHost, shadowserverHost, appId, path, deviceId_shadowServer, false);

        return true;

    }


     /**
     * Selects a path from the given set that does not lead back to the specified port if possible.
     *
     */

    private org.onosproject.net.Path pickForwardPathIfPossible(Set<org.onosproject.net.Path> paths, PortNumber notToPort) {
        org.onosproject.net.Path pathAvailable = null;
        PortNumber temporal = null;
        for (org.onosproject.net.Path path : paths) {
            Boolean includeMirrorDevice = false;
            for (Link link:path.links()){
                if (link.dst().deviceId().equals(mirrorDeviceID)) { // avoid paths that pass to the mirrorring SW
                    includeMirrorDevice = true;
                    temporal = link.dst().port();
                }
            }
            if (!path.src().port().equals(notToPort) && !includeMirrorDevice) { // do not return to the same port
                         pathAvailable = path;
            }
        }
        return pathAvailable;
    }

    /**
     * Install path for MTD
     *
     */

    private void intallPathMTD(Host attackerHost, Host serverHost, Host shadowserverHost, ApplicationId appId, org.onosproject.net.Path path, DeviceId deviceId , Boolean forward) {
        FlowObjectiveService flowObjectiveService = get(FlowObjectiveService.class);
        CoreService coreService = get(CoreService.class);

        TrafficTreatment treatment;
        TrafficSelector objectiveSelector;

        /*log.info("Installing: treatment src: {}, dst: {}, DeviceId: {}, PortNumber: {}, isEndDevice: {}", 
            srcHost.toString(), dstHost.toString(), deviceId.toString(), portNumber.toString(), String.valueOf(isEndDevice));*/

        // TODO forward through a path
        boolean isEndDevice;
        if(forward){
            for (Link link:path.links()){
                installruleMTD(attackerHost,  shadowserverHost,  serverHost, link, appId, false, true); // forward
                if (link.dst().deviceId().equals(shadowserverHost.location().deviceId())) // at the dst
                    installruleMTD(attackerHost,  shadowserverHost,  serverHost, link, appId, true, true); // forward and end device

                
            }
        } else{
            for (Link link:path.links()){
                installruleMTD(shadowserverHost, attackerHost,  serverHost, link, appId, false, false); // backward
                if (link.dst().deviceId().equals(attackerHost.location().deviceId())) // at the dst
                    installruleMTD(shadowserverHost, attackerHost,  serverHost, link, appId, true, false); // backward and end device
            }  
        }

    }

    /**
     * Install rule for
     *
     */

    private void installruleMTD(Host srcHost, Host dstHost, Host hiddenHost, Link link, ApplicationId appId, Boolean isEndDevice, Boolean forward) {
        FlowObjectiveService flowObjectiveService = get(FlowObjectiveService.class);
        CoreService coreService = get(CoreService.class);

        TrafficTreatment treatment;
        TrafficSelector objectiveSelector;
        ForwardingObjective forwardingObjective;

        //log.info("Installing: treatment src: {}, dst: {}, DeviceId: {}, PortNumber: {}, isEndDevice: {}", 
        //    srcHost.toString(), dstHost.toString(), deviceId.toString(), portNumber.toString(), String.valueOf(isEndDevice));
        
        // TODO forward through a path

        // get ip addresses 
        IpAddress IpOfServer= null;

        for (IpAddress IpOfHost : hiddenHost.ipAddresses()) {
                IpOfServer = IpOfHost;
        }

        if(IpOfServer==null) return;

        IpAddress IpOfSrc= null;
        for (IpAddress IpOfHost : srcHost.ipAddresses()) {
                IpOfSrc = IpOfHost;
        }

        if(IpOfSrc==null) return;

        IpAddress IpOfDst = null;
        for (IpAddress IpOfHost : dstHost.ipAddresses()) {
                IpOfDst = IpOfHost;
        }

        if(IpOfDst==null) return;
        IpPrefix ipPrefix = IpPrefix.valueOf(IpOfSrc, 32);

        if(isEndDevice){   // change IP and forward towards the mirroring device
            if(forward){   // attacker towards shadow server
                
                objectiveSelector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchIPSrc(IpPrefix.valueOf(IpOfSrc, 32))
                            .matchIPDst(IpPrefix.valueOf(IpOfServer, 32))
                            .build();    

                treatment = DefaultTrafficTreatment.builder()
                .setIpDst(IpOfDst)
                .setEthDst(dstHost.mac())
                .setOutput(dstHost.location().port()) //shadowserverHost PortNumber
                .setOutput(mirrorPortNumber) 
                .build(); 

                      
            }

            else{     // shadow server to attacker

               objectiveSelector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            .matchIPSrc(IpPrefix.valueOf(IpOfSrc, 32))
                            .matchIPDst(IpPrefix.valueOf(IpOfDst, 32))
                            .build(); 

               treatment = DefaultTrafficTreatment.builder()
                .setIpSrc(IpOfServer) // serverHost
                .setOutput(dstHost.location().port()) // attackerHost
                .setOutput(mirrorPortNumber)
                .build(); 

                    
            }

            forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(objectiveSelector)
                    .withTreatment(treatment)
                    .withPriority(101)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT) // same that for the timeout 
                    .add();

            flowObjectiveService.forward(dstHost.location().deviceId(),
                                         forwardingObjective); 
        }

        else{ // normall traffic
            if(forward){
                objectiveSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(IpPrefix.valueOf(IpOfSrc, 32))
                    .matchIPDst(IpPrefix.valueOf(IpOfServer, 32))
                    .build(); 
            } else{
                objectiveSelector = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(IpPrefix.valueOf(IpOfSrc, 32))
                    .matchIPDst(IpPrefix.valueOf(IpOfDst, 32))
                    .build(); 
            }
            
            treatment = DefaultTrafficTreatment.builder()
                .setOutput(link.src().port())
                .build(); 

            forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(objectiveSelector)
                .withTreatment(treatment)
                .withPriority(101)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(FLOW_TIMEOUT) // same that for the timeout 
                .add();

           flowObjectiveService.forward(link.src().deviceId(),
                                         forwardingObjective);
        }
    }
}
