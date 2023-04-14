package mx.itesm.FlowCollector.jnetpcap;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicFlow {
	public static final Logger log = LoggerFactory.getLogger(BasicFlow.class);
	private final static String separator = ",";
	private     SummaryStatistics 		fwdPktStats = null;
	private		SummaryStatistics 		bwdPktStats = null;
	private 	List<BasicPacketInfo> 	forward = null;
	private		List<BasicPacketInfo> 	backward = null;

	private 	long forwardBytes;
	private 	long backwardBytes;
	private 	long fHeaderBytes;
	private 	long bHeaderBytes;
	
	private 	boolean isBidirectional;

	private 	HashMap<String, MutableInt> flagCounts;

	private 	int fPSH_cnt;
	private 	int bPSH_cnt;
	private 	int fURG_cnt;
	private 	int bURG_cnt;

	private 	long Act_data_pkt_forward;
	private 	long min_seg_size_forward;
	private 	int Init_Win_bytes_forward=0;
	private 	int Init_Win_bytes_backward=0;


	private		byte[] src;
    private    	byte[] dst;
 	private		byte[] srcMac;
    private    	byte[] dstMac;
    private    	int    srcPort;
    private    	int    dstPort;
    private    	int    protocol;
    private     String device_ID; // Switch ID
    private    	long   flowStartTime;
    private    	long   startActiveTime;
    private    	long   endActiveTime;
    private    	String flowId = null;
    
    private     SummaryStatistics flowIAT = null;
    private     SummaryStatistics forwardIAT = null;
    private     SummaryStatistics backwardIAT = null;
	private     SummaryStatistics flowLengthStats = null;
    private     SummaryStatistics flowActive = null;
    private     SummaryStatistics flowIdle = null;
    
    private	    long   flowLastSeen;
    private     long   forwardLastSeen;
    private     long   backwardLastSeen;

    public 		TcpState cstate; // Connection state of the client
    public 		TcpState sstate; // Connection state of the server
    public 		boolean valid; // Has the flow met the requirements of a bi-directional flow
    public      boolean hasData; // Whether the connection has had any data transmitted.
    public      short pdir; // Direction of the current packet
    static final int P_FORWARD = 0;
    static final int P_BACKWARD = 1;
    

	public BasicFlow(boolean isBidirectional,BasicPacketInfo packet, byte[] flowSrc, byte[] flowDst, int flowSrcPort, int flowDstPort) {
		super();
		this.initParameters();
		this.isBidirectional = isBidirectional;
		this.firstPacket(packet);
		this.src = flowSrc;
		this.dst = flowDst;
		this.srcPort = flowSrcPort;
		this.dstPort = flowDstPort;
	}    
    
	public BasicFlow(boolean isBidirectional,BasicPacketInfo packet) {
		super();
		this.initParameters();
		this.isBidirectional = isBidirectional;
		this.firstPacket(packet);
	}

	public BasicFlow(BasicPacketInfo packet) {
		super();
		this.initParameters();
		this.isBidirectional = true;		
		firstPacket(packet);
	}
	
	public void initParameters(){
		this.forward = new ArrayList<BasicPacketInfo>();
		this.backward = new ArrayList<BasicPacketInfo>();
		this.flowIAT = new SummaryStatistics();
		this.forwardIAT = new SummaryStatistics();
		this.backwardIAT = new SummaryStatistics();
		this.flowActive = new SummaryStatistics();
		this.flowIdle = new SummaryStatistics();
		this.flowLengthStats = new SummaryStatistics();
		this.fwdPktStats = new SummaryStatistics();
		this.bwdPktStats =  new SummaryStatistics();
		this.flagCounts = new HashMap<String, MutableInt>();
		initFlags();
		this.forwardBytes = 0L;
		this.backwardBytes = 0L;	
		this.startActiveTime = 0L;
		this.endActiveTime = 0L;
		this.src = null;
		this.dst = null;
		this.srcMac = null;
		this.dstMac = null;
		this.fPSH_cnt=0;
		this.bPSH_cnt=0;
		this.fURG_cnt=0;
		this.bURG_cnt=0;
		this.fHeaderBytes=0L;
		this.bHeaderBytes=0L;
		this.valid = false;
		this.pdir = P_FORWARD;
		this.hasData = false;
	}
	
	
	public void firstPacket(BasicPacketInfo packet){
		updateFlowBulk(packet);
		detectUpdateSubflows(packet);
		checkFlags(packet);
		this.flowStartTime = packet.getTimeStamp();
		this.flowLastSeen = packet.getTimeStamp();
		this.startActiveTime = packet.getTimeStamp();
		this.endActiveTime = packet.getTimeStamp();
		this.flowLengthStats.addValue((double)packet.getPayloadBytes());

		if(this.src==null){
			this.src = packet.getSrc();
			this.srcPort = packet.getSrcPort();
			this.srcMac = packet.getSrcMac();
		}
		if(this.dst==null){
			this.dst = packet.getDst();
			this.dstPort = packet.getDstPort();
			this.dstMac = packet.getDstMac();
		}	
		this.device_ID = packet.getdeviceID();  // get device ID
				
		if(Arrays.equals(this.src, packet.getSrc())){
			this.min_seg_size_forward = packet.getHeaderBytes();
			Init_Win_bytes_forward = packet.getTCPWindow();
			this.flowLengthStats.addValue((double)packet.getPayloadBytes());
			this.fwdPktStats.addValue((double)packet.getPayloadBytes());
			this.fHeaderBytes = packet.getHeaderBytes();
			this.forwardLastSeen = packet.getTimeStamp();
			this.forwardBytes+=packet.getPayloadBytes();
			this.forward.add(packet);
			if(packet.hasFlagPSH()){
				this.fPSH_cnt++;
			}
			if(packet.hasFlagURG()){
				this.fURG_cnt++;
			}
		}else{
			Init_Win_bytes_backward = packet.getTCPWindow();
			this.flowLengthStats.addValue((double)packet.getPayloadBytes());
			this.bwdPktStats.addValue((double)packet.getPayloadBytes());
			this.bHeaderBytes = packet.getHeaderBytes();
			this.backwardLastSeen = packet.getTimeStamp();
			this.backwardBytes+=packet.getPayloadBytes();
			this.backward.add(packet);
			if(packet.hasFlagPSH()){
				this.bPSH_cnt++;
			}
			if(packet.hasFlagURG()){
				this.bURG_cnt++;
			}
		}
		this.protocol = packet.getProtocol();
		this.flowId = packet.getFlowId();	

		if (this.protocol == 6) { // MY
        // TCP specific code:
	        this.cstate = new TcpState(TcpState.State.START);
	        this.sstate = new TcpState(TcpState.State.START);
	        if (packet.hasFlagPSH()) {
	            fPSH_cnt=1;
	        }
	        if (packet.hasFlagURG()) {
	            fURG_cnt=1;
	        }
        }
		this.updateStatus(packet);		
	}
    
	private void updateStatus(BasicPacketInfo packet) {
        if (this.protocol == 17) {
            if (valid) {
                return;
            }
            if (packet.getPayloadBytes()> 8) {
                hasData = true;
            }
            if (hasData && isBidirectional) {
                valid = true;
            }
        } else if (this.protocol == 6) {
            if (!valid) {
                if (cstate.getState() == TcpState.State.ESTABLISHED) {
                    if (packet.getPayloadBytes() > packet.getHeaderBytes()) {
                        valid = true;
                    }
                }
            }
            updateTcpState(packet);
        }
    }

     private void updateTcpState(BasicPacketInfo packet) {
        cstate.setState(packet, P_FORWARD, pdir);
        sstate.setState(packet, P_BACKWARD, pdir);
    }

    public boolean is_endTCP(BasicPacketInfo packet){
    	if(isBidirectional){
	    	if(Arrays.equals(this.src, packet.getSrc())){
	    		pdir = P_FORWARD;
	    	}else{
	    		pdir = P_BACKWARD;
	    	}
	    	updateStatus(packet);
	    	if (this.protocol == 6 && cstate.getState() == TcpState.State.CLOSED &&
            	sstate.getState() == TcpState.State.CLOSED) {
            	return true;
        	}else{
        		return false;
        	}
    	}else{
    		return false;    	
    	}
    }

    public void addPacket(BasicPacketInfo packet){
		updateFlowBulk(packet);
		detectUpdateSubflows(packet);
		checkFlags(packet);
    	long currentTimestamp = packet.getTimeStamp();
    	long last = getLastTime();

    	if(isBidirectional){
			this.flowLengthStats.addValue((double)packet.getPayloadBytes());
    		if(Arrays.equals(this.src, packet.getSrc())){
    			pdir = P_FORWARD;
				if(packet.getPayloadBytes() >=1){
					this.Act_data_pkt_forward++;
				}
				this.fwdPktStats.addValue((double)packet.getPayloadBytes());
				this.fHeaderBytes +=packet.getHeaderBytes();
    			this.forward.add(packet);   
    			this.forwardBytes+=packet.getPayloadBytes();
    			if (this.forward.size()>1)
    				this.forwardIAT.addValue(currentTimestamp -this.forwardLastSeen);
    			this.forwardLastSeen = currentTimestamp;
				this.min_seg_size_forward = Math.min(packet.getHeaderBytes(),this.min_seg_size_forward);

    		}else{
    			pdir = P_BACKWARD;
				this.bwdPktStats.addValue((double)packet.getPayloadBytes());
				Init_Win_bytes_backward = packet.getTCPWindow();
				this.bHeaderBytes+=packet.getHeaderBytes();
    			this.backward.add(packet);
    			this.backwardBytes+=packet.getPayloadBytes();
    			if (this.backward.size()>1)
    				this.backwardIAT.addValue(currentTimestamp-this.backwardLastSeen);
    			this.backwardLastSeen = currentTimestamp;
    		}
    	}
		else{
			if(packet.getPayloadBytes() >=1) {
				this.Act_data_pkt_forward++;
			}
			this.fwdPktStats.addValue((double)packet.getPayloadBytes());
			this.flowLengthStats.addValue((double)packet.getPayloadBytes());
			this.fHeaderBytes +=packet.getHeaderBytes();
    		this.forward.add(packet);    		
    		this.forwardBytes+=packet.getPayloadBytes();
    		this.forwardIAT.addValue(currentTimestamp-this.forwardLastSeen);
    		this.forwardLastSeen = currentTimestamp;
			this.min_seg_size_forward = Math.min(packet.getHeaderBytes(),this.min_seg_size_forward);
    	}

    	this.flowIAT.addValue(packet.getTimeStamp()-this.flowLastSeen);
    	this.flowLastSeen = packet.getTimeStamp();
    	updateStatus(packet);
    }

 // Yung
    private long getLastTime() {
    if (this.backwardLastSeen == 0) {
        return this.forwardLastSeen;
    }
    if (this.forwardLastSeen == 0) {
        return this.backwardLastSeen;
    }
    if (this.forwardLastSeen > this.backwardLastSeen) {
        return this.forwardLastSeen;
    }
    return this.backwardLastSeen;
    }

	public double getfPktsPerSecond(){
		long duration = this.flowLastSeen - this.flowStartTime;
		if(duration > 0){
			return (this.forward.size()/((double)duration/1000000L));
		}
		else
			return 0;
	}
	public double getbPktsPerSecond(){
		long duration = this.flowLastSeen - this.flowStartTime;
		if(duration > 0){
			return (this.backward.size()/((double)duration/1000000L));
		}
		else
			return 0;
	}

	public double getDownUpRatio(){
		if(this.forward.size() > 0){
			return (double)(this.backward.size()/this.forward.size());
		}
		return 0;
	}

	public double getAvgPacketSize(){
		if(this.packetCount() > 0){
			return (this.flowLengthStats.getSum()/this.packetCount());
		}
		return 0;
	}

	public double fAvgSegmentSize(){
		if (this.forward.size()!=0)
			return (this.fwdPktStats.getSum() / (double)this.forward.size());
		return 0;
	}

	public double bAvgSegmentSize(){
		if (this.backward.size()!=0)
			return (this.bwdPktStats.getSum() / (double)this.backward.size());
		return 0;
	}

    public void initFlags(){
		flagCounts.put("FIN", new MutableInt());
		flagCounts.put("SYN", new MutableInt());
		flagCounts.put("RST", new MutableInt());
		flagCounts.put("PSH", new MutableInt());
		flagCounts.put("ACK", new MutableInt());
		flagCounts.put("URG", new MutableInt());
		flagCounts.put("CWR", new MutableInt());
		flagCounts.put("ECE", new MutableInt());
	}

	public void checkFlags(BasicPacketInfo packet){
		if(packet.hasFlagFIN()){
			//MutableInt count1 = flagCounts.get("FIN");
			//count1.increment();
			flagCounts.get("FIN").increment();
		}
		if(packet.hasFlagSYN()){
			//MutableInt count2 = flagCounts.get("SYN");
			//count2.increment();
			flagCounts.get("SYN").increment();
		}
		if(packet.hasFlagRST()){
			//MutableInt count3 = flagCounts.get("RST");
			//count3.increment();
			flagCounts.get("RST").increment();
		}
		if(packet.hasFlagPSH()){
			//MutableInt count4 = flagCounts.get("PSH");
			//count4.increment();
			flagCounts.get("PSH").increment();
		}
		if(packet.hasFlagACK()){
			//MutableInt count5 = flagCounts.get("ACK");
			//count5.increment();
			flagCounts.get("ACK").increment();
		}
		if(packet.hasFlagURG()){
			//MutableInt count6 = flagCounts.get("URG");
			//count6.increment();
			flagCounts.get("URG").increment();
		}
		if(packet.hasFlagCWR()){
			//MutableInt count7 = flagCounts.get("CWR");
			//count7.increment();
			flagCounts.get("CWR").increment();
		}
		if(packet.hasFlagECE()){
			//MutableInt count8 = flagCounts.get("ECE");
			//count8.increment();
			flagCounts.get("ECE").increment();
		}
	}




	public long getSflow_fbytes(){
		if(sfCount <= 0) return 0;
		return this.forwardBytes/sfCount;
	}

	public long getSflow_fpackets(){
		if(sfCount <= 0) return 0;
		return this.forward.size()/sfCount;
	}

	public long getSflow_bbytes(){
		if(sfCount <= 0) return 0;
		return this.backwardBytes/sfCount;
	}
	public long getSflow_bpackets(){
		if(sfCount <= 0) return 0;
		return this.backward.size()/sfCount;
	}

	private long sfLastPacketTS=-1;
	private int sfCount=0;
	private long sfAcHelper=-1;

	void detectUpdateSubflows( BasicPacketInfo packet ){
		if(sfLastPacketTS == -1){
			sfLastPacketTS = packet.getTimeStamp();
			sfAcHelper   = packet.getTimeStamp();
		}
		//System.out.print(" - "+(packet.timeStamp - sfLastPacketTS));
		if( (packet.getTimeStamp() - (sfLastPacketTS)/(double)1000000)   > 1.0 ){
			sfCount ++ ;
			long lastSFduration = packet.getTimeStamp() - sfAcHelper;
			updateActiveIdleTime(packet.getTimeStamp() - sfLastPacketTS, 5000000L);
			sfAcHelper = packet.getTimeStamp();
		}

		sfLastPacketTS = packet.getTimeStamp() ;
	}

	//////////////////////////////
	private long fbulkDuration=0;
	private long fbulkPacketCount=0;
	private long fbulkSizeTotal=0;
	private long fbulkStateCount=0;
	private long fbulkPacketCountHelper=0;
	private long fbulkStartHelper=0;
	private long fbulkSizeHelper=0;
	private long flastBulkTS=0;
	private long bbulkDuration=0;
	private long bbulkPacketCount=0;
	private long bbulkSizeTotal=0;
	private long bbulkStateCount=0;
	private long bbulkPacketCountHelper=0;
	private long bbulkStartHelper=0;
	private long bbulkSizeHelper=0;
	private long blastBulkTS=0;


	public void updateFlowBulk (BasicPacketInfo packet){

		if(this.src == packet.getSrc()){
			updateForwardBulk(packet,blastBulkTS);
		}else {
			updateBackwardBulk(packet,flastBulkTS);
		}

	}

	public void updateForwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther){

		long size=packet.getPayloadBytes();
		if (tsOflastBulkInOther > fbulkStartHelper) fbulkStartHelper = 0;
		if (size <= 0) return ;

		packet.getPayloadPacket();

		if (fbulkStartHelper == 0){
			fbulkStartHelper = packet.getTimeStamp();
			fbulkPacketCountHelper = 1;
			fbulkSizeHelper = size ;
			flastBulkTS = packet.getTimeStamp();
		} //possible bulk
		else{
			// Too much idle time?
			if (((packet.getTimeStamp() - flastBulkTS)/(double)1000000) > 1.0){
				fbulkStartHelper = packet.getTimeStamp();
				flastBulkTS = packet.getTimeStamp();
				fbulkPacketCountHelper = 1;
				fbulkSizeHelper = size;
			}// Add to bulk
			else{
				fbulkPacketCountHelper += 1;
				fbulkSizeHelper        += size ;
				//New bulk
				if (fbulkPacketCountHelper == 4){
					fbulkStateCount  += 1;
					fbulkPacketCount += fbulkPacketCountHelper;
					fbulkSizeTotal   += fbulkSizeHelper;
					fbulkDuration    += packet.getTimeStamp() - fbulkStartHelper;
				} //Continuation of existing bulk
				else if (fbulkPacketCountHelper > 4){
					fbulkPacketCount += 1;
					fbulkSizeTotal   += size;
					fbulkDuration    += packet.getTimeStamp() - flastBulkTS;
				}
				flastBulkTS = packet.getTimeStamp();
			}
		}
	}

	public void updateBackwardBulk(BasicPacketInfo packet , long tsOflastBulkInOther){
		/*bAvgBytesPerBulk =0;
		bbulkSizeTotal=0;
		bbulkStateCount=0;*/
		long size=packet.getPayloadBytes();
		if (tsOflastBulkInOther > bbulkStartHelper) bbulkStartHelper = 0;
		if ( size<= 0) return ;

		packet.getPayloadPacket();

		if ( bbulkStartHelper == 0 ){
			bbulkStartHelper = packet.getTimeStamp();
			bbulkPacketCountHelper = 1;
			bbulkSizeHelper = size ;
			blastBulkTS = packet.getTimeStamp();
		} //possible bulk
		else{
			// Too much idle time?
			if (((packet.getTimeStamp() - blastBulkTS)/(double)1000000) > 1.0){
				bbulkStartHelper = packet.getTimeStamp();
				blastBulkTS = packet.getTimeStamp();
				bbulkPacketCountHelper = 1;
				bbulkSizeHelper = size;
			}// Add to bulk
			else{
				bbulkPacketCountHelper += 1;
				bbulkSizeHelper += size ;
				//New bulk
				if (bbulkPacketCountHelper == 4){
					bbulkStateCount  += 1;
					bbulkPacketCount += bbulkPacketCountHelper;
					bbulkSizeTotal   += bbulkSizeHelper;
					bbulkDuration    += packet.getTimeStamp() - bbulkStartHelper;
				} //Continuation of existing bulk
				else if (bbulkPacketCountHelper > 4){
					bbulkPacketCount += 1;
					bbulkSizeTotal   += size;
					bbulkDuration    += packet.getTimeStamp() - blastBulkTS;
				}
				blastBulkTS = packet.getTimeStamp();
			}
		}

	}

	public  long fbulkStateCount() {
		return fbulkStateCount;
	}

	public  long fbulkSizeTotal() {
		return fbulkSizeTotal;
	}

	public long fbulkPacketCount() {
		return fbulkPacketCount;
	}

	public long fbulkDuration() {
		return fbulkDuration;
	}
	public double fbulkDurationInSecond() {
		return fbulkDuration/(double)1000000;
	}



	//Client average bytes per bulk
	public long fAvgBytesPerBulk(){
		if (this.fbulkStateCount() != 0 )
			return (this.fbulkSizeTotal() / this.fbulkStateCount());
		return 0;
	}


	//Client average packets per bulk
	public long fAvgPacketsPerBulk(){
		if (this.fbulkStateCount() != 0 )
			return (this.fbulkPacketCount() / this.fbulkStateCount());
		return 0;
	}


	//Client average bulk rate
	public long fAvgBulkRate(){
		if (this.fbulkDuration() != 0 )
			return (long)(this.fbulkSizeTotal() / this.fbulkDurationInSecond());
		return 0;
	}


	//new features server
	public long bbulkPacketCount() {
		return bbulkPacketCount;
	}

	public long bbulkStateCount() {
		return bbulkStateCount;
	}

	public long bbulkSizeTotal() {
		return bbulkSizeTotal;
	}

	public long bbulkDuration() {
		return bbulkDuration;
	}
	public double bbulkDurationInSecond() {
		return bbulkDuration/(double)1000000;
	}

	//Server average bytes per bulk
	public long bAvgBytesPerBulk(){
		if(this.bbulkStateCount() != 0)
			return (this.bbulkSizeTotal() /  this.bbulkStateCount());
		return 0;
	}

	//Server average packets per bulk
	public long bAvgPacketsPerBulk(){
		if(this.bbulkStateCount() != 0 )
			return (this.bbulkPacketCount() /  this.bbulkStateCount());
		return 0;
	}
	//Server average bulk rate
	public long bAvgBulkRate(){
		if(this.bbulkDuration() != 0)
			return (long)(this.bbulkSizeTotal() / this.bbulkDurationInSecond());
		return 0;
	}

	////////////////////////////


    public void updateActiveIdleTime(long currentTime, long threshold){
    	if ((currentTime - this.endActiveTime) > threshold){
    		if((this.endActiveTime - this.startActiveTime) > 0){
	      		this.flowActive.addValue(this.endActiveTime - this.startActiveTime);	      		
    		}
    		this.flowIdle.addValue(currentTime - this.endActiveTime);
    		this.startActiveTime = currentTime;
    		this.endActiveTime = currentTime;
    	}else{
    		this.endActiveTime = currentTime;
    	}
    }
    
    public void endActiveIdleTime(long currentTime, long threshold, long flowTimeOut, boolean isFlagEnd){
		
    	if((this.endActiveTime - this.startActiveTime) > 0){
      		this.flowActive.addValue(this.endActiveTime - this.startActiveTime);	      		
		}
    	
    	if (!isFlagEnd && ((flowTimeOut - (this.endActiveTime-this.flowStartTime))>0)){
    		this.flowIdle.addValue(flowTimeOut - (this.endActiveTime-this.flowStartTime));
    	}
    }    

    public String dumpFlowBasedFeatures(){
    	String dump = "{\"FlowID\":";
		dump+="\""+this.flowId+"\""+",";
		dump+="\"SrcIP\":";
    	dump+="\""+FormatUtils.ip(src)+"\""+",";
    	dump+="\"SrcPort\":";
    	dump+=getSrcPort()+",";
    	dump+="\"DstIP\":";
    	dump+="\""+FormatUtils.ip(dst)+"\""+",";  
    	dump+="\"DstPort\":";  			
    	dump+=getDstPort()+",";
    	dump+="\"Protocol\":";
    	dump+=getProtocol()+",";
		dump+="\"Timestamp\":";
    	dump+="\""+DateFormatter.parseDateFromLong(this.flowStartTime/1000L, "dd/MM/yyyy hh:mm:ss")+"\""+",";
    	long flowDuration = this.flowLastSeen - this.flowStartTime; 
    	dump+="\"FlowDuration\":";
    	dump+=flowDuration+",";
    	dump+="\"TotFwdPkts\":";
		dump+=this.fwdPktStats.getN()+",";
		dump+="\"TotBwdPkts\":";
		dump+=this.bwdPktStats.getN()+",";
		dump+="\"TotLenFwdPkts\":";
		dump+=this.fwdPktStats.getSum()+",";
		dump+="\"TotLenBwdPkts\":";
		dump+=this.bwdPktStats.getSum()+",";
		if(fwdPktStats.getN() > 0L) {
			dump+="\"FwdPktLenMax\":";
			dump += this.fwdPktStats.getMax() + ",";
			dump+="\"FwdPktLenMin\":";
			dump += this.fwdPktStats.getMin() + ",";
			dump+="\"FwdPktLenMean\":";
			dump += this.fwdPktStats.getMean() + ",";
			dump+="\"FwdPktLenStd\":";
			dump += this.fwdPktStats.getStandardDeviation() + ",";
		}else{
			dump+="\"FwdPktLenMax\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenMin\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenMean\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenStd\":";
			dump += "0" + ",";
		}
		if(bwdPktStats.getN() > 0L) {
			dump+="\"BwdPktLenMax\":";
			dump += this.bwdPktStats.getMax() + ",";
			dump+="\"BwdPktLenMin\":";
			dump += this.bwdPktStats.getMin() + ",";
			dump+="\"BwdPktLenMean\":";
			dump += this.bwdPktStats.getMean() + ",";
			dump+="\"BwdPktLenStd\":";
			dump += this.bwdPktStats.getStandardDeviation() + ",";
		}else{
			dump+="\"BwdPktLenMax\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenMin\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenMean\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenStd\":";
			dump += "0" + ",";
		}
    	// flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
    	dump+="\"FlowBytss\":";
    	dump+=((double)(this.forwardBytes+this.backwardBytes))/((double)flowDuration/1000000L)+",";    			
    	dump+="\"FlowPktss\":";
    	dump+=((double)packetCount())/((double)flowDuration/1000000L)+",";
    	dump+="\"FlowIATMean\":";
    	dump+=this.flowIAT.getMean()+",";
    	dump+="\"FlowIATStd\":";
    	dump+=this.flowIAT.getStandardDeviation()+",";
    	dump+="\"FlowIATMax\":";
    	dump+=this.flowIAT.getMax()+",";
    	dump+="\"FlowIATMin\":";
    	dump+=this.flowIAT.getMin()+",";    	
    	if(this.forward.size()>1){
    		dump+="\"FwdIATTot\":";
			dump+=this.forwardIAT.getSum()+",";
			dump+="\"FwdIATMean\":";
        	dump+=this.forwardIAT.getMean()+",";
        	dump+="\"FwdIATStd\":";
        	dump+=this.forwardIAT.getStandardDeviation()+",";
        	dump+="\"FwdIATMax\":";
        	dump+=this.forwardIAT.getMax()+",";
        	dump+="\"FwdIATMin\":";
        	dump+=this.forwardIAT.getMin()+",";
    	}else{
    		dump+="\"FwdIATTot\":";
			dump+="0"+",";
			dump+="\"FwdIATMean\":";
        	dump+="0"+",";
        	dump+="\"FwdIATStd\":";
        	dump+="0"+",";
        	dump+="\"FwdIATMax\":";
        	dump+="0"+",";
        	dump+="\"FwdIATMin\":";
        	dump+="0"+",";
    	}
    	if(this.backward.size()>1){
    		dump+="\"BwdIATTot\":";
			dump+=this.backwardIAT.getSum()+",";
			dump+="\"BwdIATMean\":";
        	dump+=this.backwardIAT.getMean()+",";
        	dump+="\"BwdIATStd\":";
        	dump+=this.backwardIAT.getStandardDeviation()+",";
        	dump+="\"BwdIATMax\":";
        	dump+=this.backwardIAT.getMax()+",";
        	dump+="\"BwdIATMin\":";
        	dump+=this.backwardIAT.getMin()+","; 
    	}else{
    		dump+="\"BwdIATTot\":";
			dump+="0"+",";
			dump+="\"BwdIATMean\":";
        	dump+="0"+",";
        	dump+="\"BwdIATStd\":";
        	dump+="0"+",";
        	dump+="\"BwdIATMax\":";
        	dump+="0"+",";
        	dump+="\"BwdIATMin\":";
        	dump+="0"+",";
    	}

    	dump+="\"FwdPSHFlags\":";
		dump+=this.fPSH_cnt+",";
		dump+="\"BwdPSHFlags\":";
		dump+=this.bPSH_cnt+",";
		dump+="\"FwdURGFlags\":";
		dump+=this.fURG_cnt+",";
		dump+="\"BwdURGFlags\":";
		dump+=this.bURG_cnt+",";

		dump+="\"FwdHeaderLen\":";
		dump+=this.fHeaderBytes+",";
		dump+="\"BwdHeaderLen\":";
		dump+=this.bHeaderBytes+",";
		dump+="\"FwdPktss\":";
		dump+=getfPktsPerSecond()+",";
		dump+="\"BwdPktss\":";
		dump+=getbPktsPerSecond()+",";

		if(this.forward.size() > 0 || this.backward.size() > 0){
			dump+="\"PktLenMin\":";
			dump+=this.flowLengthStats.getMin()+",";
			dump+="\"PktLenMax\":";
			dump+=this.flowLengthStats.getMax()+",";
			dump+="\"PktLenMean\":";
			dump+=this.flowLengthStats.getMean()+",";
			dump+="\"PktLenStd\":";
			dump+=this.flowLengthStats.getStandardDeviation()+",";
			dump+="\"PktLenVar\":";
			dump+=flowLengthStats.getVariance()+",";
		}else{
			dump+="\"PktLenMin\":";
			dump+="0"+",";
			dump+="\"PktLenMax\":";
			dump+="0"+",";
			dump+="\"PktLenMean\":";
			dump+="0"+",";
			dump+="\"PktLenStd\":";
			dump+="0"+",";
			dump+="\"PktLenVar\":";
			dump+="0"+",";
		}

		String key = "FIN";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "SYN";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "RST";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "PSH";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "ACK";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "URG";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "CWR";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "ECE";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";

		dump+="\"DownUpRatio\":";
		dump+=getDownUpRatio()+",";
		dump+="\"PktSizeAvg\":";
		dump+=getAvgPacketSize()+",";
		dump+="\"FwdSegSizeAvg\":";
		dump+=fAvgSegmentSize()+",";
		dump+="\"BwdSegSizeAvg\":";
		dump+=bAvgSegmentSize()+",";
		
		//dump+=this.fHeaderBytes+",";  //this feature is duplicated



		dump+="\"FwdBytsbAvg\":";
		dump+=fAvgBytesPerBulk()+",";
		dump+="\"FwdPktsbAvg\":";
		dump+=fAvgPacketsPerBulk()+",";
		dump+="\"FwdBlkRateAvg\":";
		dump+=fAvgBulkRate()+",";
		dump+="\"BwdBytsbAvg\":";
		dump+=bAvgBytesPerBulk()+",";
		dump+="\"BwdPktsbAvg\":";
		dump+=bAvgPacketsPerBulk()+",";
		dump+="\"BwdBlkRateAvg\":";
		dump+=bAvgBulkRate()+",";

		dump+="\"SubflowFwdPkts\":";
		dump+=getSflow_fpackets()+",";
		dump+="\"SubflowFwdByts\":";
		dump+=getSflow_fbytes()+",";
		dump+="\"SubflowBwdPkts\":";
		dump+=getSflow_bpackets()+",";
		dump+="\"SubflowBwdByts\":";
		dump+=getSflow_bbytes()+",";

		dump+="\"InitFwdWinByts\":";
		dump+=this.Init_Win_bytes_forward+",";
		dump+="\"InitBwdWinByts\":";
		dump+=this.Init_Win_bytes_backward+",";
		dump+="\"FwdActDataPkts\":";
		dump+=this.Act_data_pkt_forward+",";
		dump+="\"FwdSegSizeMin\":";
		dump+=this.min_seg_size_forward+",";

    	if(this.flowActive.getN()>0){
    		dump+="\"ActiveMean\":";
        	dump+=this.flowActive.getMean()+",";
        	dump+="\"ActiveStd\":";
        	dump+=this.flowActive.getStandardDeviation()+",";
        	dump+="\"ActiveMax\":";
        	dump+=this.flowActive.getMax()+",";
        	dump+="\"ActiveMin\":";
        	dump+=this.flowActive.getMin()+",";  
    	}else{
    		dump+="\"ActiveMean\":";
        	dump+="0"+",";
        	dump+="\"ActiveStd\":";
        	dump+="0"+",";
        	dump+="\"ActiveMax\":";
        	dump+="0"+",";
        	dump+="\"ActiveMin\":";
        	dump+="0"+",";
    	}    	
    	
    	if(this.flowIdle.getN()>0){
    		dump+="\"IdleMean\":";
	    	dump+=this.flowIdle.getMean()+",";
	    	dump+="\"IdleStd\":";
	    	dump+=this.flowIdle.getStandardDeviation()+",";
	    	dump+="\"IdleMax\":";
	    	dump+=this.flowIdle.getMax()+",";
	    	dump+="\"IdleMin\":";
	    	dump+=this.flowIdle.getMin()+",";    
    	}else{
    		dump+="\"IdleMean\":";
	    	dump+="0"+",";
	    	dump+="\"IdleStd\":";
	    	dump+="0"+",";
	    	dump+="\"IdleMax\":";
	    	dump+="0"+",";
	    	dump+="\"IdleMin\":";
	    	dump+="0"+","; 
    	}
    	dump+="\"Label\":";
		dump+="\""+getLabel()+"\"";
		dump+="}";

		/*if(FormatUtils.ip(src).equals("147.32.84.165") | FormatUtils.ip(dst).equals("147.32.84.165")){
			dump+=",BOTNET";
		}
		else{
			dump+=",BENIGN";
		} */
		/////////////////////////////////
    	return dump;
    }      
    
public String SelectedCICDoS2017FlowBasedFeatures(){
    	String dump = "{\"SWID\":";
    	dump+=this.device_ID+","; 
    	dump+="\"SrcIP\":";
    	dump+="\""+FormatUtils.ip(src)+"\""+",";
    	dump+="\"SrcMac\":";
    	dump+="\""+FormatUtils.mac(srcMac)+"\""+",";
    	dump+="\"SrcPort\":";
    	dump+=getSrcPort()+",";
    	dump+="\"DstIP\":";
    	dump+="\""+FormatUtils.ip(dst)+"\""+",";  
    	dump+="\"DstMac\":";
    	dump+="\""+FormatUtils.mac(dstMac)+"\""+",";  
    	dump+="\"DstPort\":";  			
    	dump+=getDstPort()+",";
    	dump+="\"Protocol\":";
    	dump+=getProtocol()+",";
		dump+="\"Timestamp\":";
    	dump+="\""+DateFormatter.parseDateFromLong(this.flowStartTime/1000L, "dd/MM/yyyy hh:mm:ss")+"\""+",";
    	long flowDuration = this.flowLastSeen - this.flowStartTime; 
    	dump+="\"FlowDuration\":";
    	dump+=flowDuration+",";
    	dump+="\"TotFwdPkts\":";
		dump+=this.fwdPktStats.getN()+",";
		dump+="\"TotBwdPkts\":";
		dump+=this.bwdPktStats.getN()+",";
		dump+="\"TotLenFwdPkts\":";
		dump+=this.fwdPktStats.getSum()+",";
		dump+="\"TotLenBwdPkts\":";
		dump+=this.bwdPktStats.getSum()+",";
		if(fwdPktStats.getN() > 0L) {
			dump+="\"FwdPktLenMax\":";
			dump += this.fwdPktStats.getMax() + ",";
			dump+="\"FwdPktLenMin\":";
			dump += this.fwdPktStats.getMin() + ",";
			dump+="\"FwdPktLenStd\":";
			dump += this.fwdPktStats.getStandardDeviation() + ",";
		}else{
			dump+="\"FwdPktLenMax\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenMin\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenStd\":";
			dump += "0" + ",";
		}
		if(bwdPktStats.getN() > 0L) {
			dump+="\"BwdPktLenMax\":";
			dump += this.bwdPktStats.getMax() + ",";
			dump+="\"BwdPktLenMin\":";
			dump += this.bwdPktStats.getMin() + ",";
			dump+="\"BwdPktLenStd\":";
			dump += this.bwdPktStats.getStandardDeviation() + ",";
		}else{
			dump+="\"BwdPktLenMax\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenMin\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenStd\":";
			dump += "0" + ",";
		}
    	// flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
    	dump+="\"FlowBytss\":";
    	dump+=((double)(this.forwardBytes+this.backwardBytes))/((double)flowDuration/1000000L)+",";    			
    	dump+="\"FlowPktss\":";
    	dump+=((double)packetCount())/((double)flowDuration/1000000L)+",";
    	dump+="\"FlowIATMean\":";
    	dump+=this.flowIAT.getMean()+",";
    	dump+="\"FlowIATStd\":";
    	dump+=this.flowIAT.getStandardDeviation()+",";
    	dump+="\"FlowIATMax\":";
    	dump+=this.flowIAT.getMax()+",";
    	dump+="\"FlowIATMin\":";
    	dump+=this.flowIAT.getMin()+",";    	
    	if(this.forward.size()>1){
			dump+="\"FwdIATMean\":";
        	dump+=this.forwardIAT.getMean()+",";
        	dump+="\"FwdIATStd\":";
        	dump+=this.forwardIAT.getStandardDeviation()+",";
        	dump+="\"FwdIATMin\":";
        	dump+=this.forwardIAT.getMin()+",";
    	}else{
			dump+="\"FwdIATMean\":";
        	dump+="0"+",";
        	dump+="\"FwdIATStd\":";
        	dump+="0"+",";
        	dump+="\"FwdIATMin\":";
        	dump+="0"+",";
    	}
    	if(this.backward.size()>1){
    		dump+="\"BwdIATTot\":";
			dump+=this.backwardIAT.getSum()+",";
			dump+="\"BwdIATMean\":";
        	dump+=this.backwardIAT.getMean()+",";
        	dump+="\"BwdIATStd\":";
        	dump+=this.backwardIAT.getStandardDeviation()+",";
        	dump+="\"BwdIATMax\":";
        	dump+=this.backwardIAT.getMax()+",";
        	dump+="\"BwdIATMin\":";
        	dump+=this.backwardIAT.getMin()+","; 
    	}else{
    		dump+="\"BwdIATTot\":";
			dump+="0"+",";
			dump+="\"BwdIATMean\":";
        	dump+="0"+",";
        	dump+="\"BwdIATStd\":";
        	dump+="0"+",";
        	dump+="\"BwdIATMax\":";
        	dump+="0"+",";
        	dump+="\"BwdIATMin\":";
        	dump+="0"+",";
    	}

    	dump+="\"FwdPSHFlags\":";
		dump+=this.fPSH_cnt+",";
		dump+="\"FwdPktss\":";
		dump+=getfPktsPerSecond()+",";
		dump+="\"BwdPktss\":";
		dump+=getbPktsPerSecond()+",";

		if(this.forward.size() > 0 || this.backward.size() > 0){
			dump+="\"PktLenMin\":";
			dump+=this.flowLengthStats.getMin()+",";
			dump+="\"PktLenMax\":";
			dump+=this.flowLengthStats.getMax()+",";
			dump+="\"PktLenMean\":";
			dump+=this.flowLengthStats.getMean()+",";
			dump+="\"PktLenStd\":";
			dump+=this.flowLengthStats.getStandardDeviation()+",";
			dump+="\"PktLenVar\":";
			dump+=flowLengthStats.getVariance()+",";
		}else{
			dump+="\"PktLenMin\":";
			dump+="0"+",";
			dump+="\"PktLenMax\":";
			dump+="0"+",";
			dump+="\"PktLenMean\":";
			dump+="0"+",";
			dump+="\"PktLenStd\":";
			dump+="0"+",";
			dump+="\"PktLenVar\":";
			dump+="0"+",";
		}

		String key = "FIN";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "SYN";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "RST";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "PSH";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";

		dump+="\"DownUpRatio\":";
		dump+=getDownUpRatio()+",";
		
		//dump+=this.fHeaderBytes+",";  //this feature is duplicated

		dump+="\"BwdPktsbAvg\":";
		dump+=bAvgPacketsPerBulk()+",";
		dump+="\"BwdBlkRateAvg\":";
		dump+=bAvgBulkRate()+",";

		dump+="\"SubflowFwdPkts\":";
		dump+=getSflow_fpackets()+",";
		dump+="\"SubflowFwdByts\":";
		dump+=getSflow_fbytes()+",";
		dump+="\"SubflowBwdByts\":";
		dump+=getSflow_bbytes()+",";

		dump+="\"InitFwdWinByts\":";
		dump+=this.Init_Win_bytes_forward+",";
		dump+="\"InitBwdWinByts\":";
		dump+=this.Init_Win_bytes_backward+",";
		dump+="\"FwdSegSizeMin\":";
		dump+=this.min_seg_size_forward+",";

    	if(this.flowActive.getN()>0){
    	}else{
    	}    	
    	
    	if(this.flowIdle.getN()>0){
    		dump+="\"IdleMean\":";
	    	dump+=this.flowIdle.getMean()+",";
	    	dump+="\"IdleStd\":";
	    	dump+=this.flowIdle.getStandardDeviation()+",";
	    	dump+="\"IdleMin\":";
	    	dump+=this.flowIdle.getMin();    
    	}else{
    		dump+="\"IdleMean\":";
	    	dump+="0"+",";
	    	dump+="\"IdleStd\":";
	    	dump+="0"+",";
	    	dump+="\"IdleMin\":";
	    	dump+="0"; 
    	}
		dump+="}";

		/*if(FormatUtils.ip(src).equals("147.32.84.165") | FormatUtils.ip(dst).equals("147.32.84.165")){
			dump+=",BOTNET";
		}
		else{
			dump+=",BENIGN";
		} */
		/////////////////////////////////
    	return dump;
    }


    public String SelectedCICDDoS2019FlowBasedFeatures(){
    	String dump = "{\"SWID\":";
    	dump+=this.device_ID+","; 
		dump+="\"SrcIP\":";
    	dump+="\""+FormatUtils.ip(src)+"\""+",";
    	dump+="\"SrcMac\":";
    	dump+="\""+FormatUtils.mac(srcMac)+"\""+",";
    	dump+="\"SrcPort\":";
    	dump+=getSrcPort()+",";
    	dump+="\"DstIP\":";
    	dump+="\""+FormatUtils.ip(dst)+"\""+",";  
    	dump+="\"DstMac\":";
    	dump+="\""+FormatUtils.mac(dstMac)+"\""+","; 
    	dump+="\"DstPort\":";  			
    	dump+=getDstPort()+",";
    	dump+="\"Protocol\":";
    	dump+=getProtocol()+",";
		dump+="\"Timestamp\":";
    	dump+="\""+DateFormatter.parseDateFromLong(this.flowStartTime/1000L, "dd/MM/yyyy hh:mm:ss")+"\""+",";
    	long flowDuration = this.flowLastSeen - this.flowStartTime; 
    	dump+="\"FlowDuration\":";
    	dump+=flowDuration+",";
    	dump+="\"TotFwdPkts\":";
		dump+=this.fwdPktStats.getN()+",";
		dump+="\"TotLenFwdPkts\":";
		dump+=this.fwdPktStats.getSum()+",";
		dump+="\"TotLenBwdPkts\":";
		dump+=this.bwdPktStats.getSum()+",";
		if(fwdPktStats.getN() > 0L) {
			dump+="\"FwdPktLenMax\":";
			dump += this.fwdPktStats.getMax() + ",";
			dump+="\"FwdPktLenMin\":";
			dump += this.fwdPktStats.getMin() + ",";
			dump+="\"FwdPktLenStd\":";
			dump += this.fwdPktStats.getStandardDeviation() + ",";
		}else{
			dump+="\"FwdPktLenMax\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenMin\":";
			dump += "0" + ",";
			dump+="\"FwdPktLenStd\":";
			dump += "0" + ",";
		}
		if(bwdPktStats.getN() > 0L) {
			dump+="\"BwdPktLenMax\":";
			dump += this.bwdPktStats.getMax() + ",";
			dump+="\"BwdPktLenMin\":";
			dump += this.bwdPktStats.getMin() + ",";
			dump+="\"BwdPktLenMean\":";
			dump += this.bwdPktStats.getMean() + ",";
			dump+="\"BwdPktLenStd\":";
			dump += this.bwdPktStats.getStandardDeviation() + ",";
		}else{
			dump+="\"BwdPktLenMax\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenMin\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenMean\":";
			dump += "0" + ",";
			dump+="\"BwdPktLenStd\":";
			dump += "0" + ",";
		}
    	// flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
    	dump+="\"FlowBytss\":";
    	dump+=((double)(this.forwardBytes+this.backwardBytes))/((double)flowDuration/1000000L)+",";    			
    	dump+="\"FlowIATStd\":";
    	dump+=this.flowIAT.getStandardDeviation()+",";
    	dump+="\"FlowIATMax\":";
    	dump+=this.flowIAT.getMax()+",";
    	dump+="\"FlowIATMin\":";
    	dump+=this.flowIAT.getMin()+",";    	
    	if(this.forward.size()>1){
    		dump+="\"FwdIATTot\":";
			dump+=this.forwardIAT.getSum()+",";
			dump+="\"FwdIATMean\":";
        	dump+=this.forwardIAT.getMean()+",";
        	dump+="\"FwdIATMax\":";
        	dump+=this.forwardIAT.getMax()+",";
        	dump+="\"FwdIATMin\":";
        	dump+=this.forwardIAT.getMin()+",";
    	}else{
    		dump+="\"FwdIATTot\":";
			dump+="0"+",";
			dump+="\"FwdIATMean\":";
        	dump+="0"+",";
        	dump+="\"FwdIATMax\":";
        	dump+="0"+",";
        	dump+="\"FwdIATMin\":";
        	dump+="0"+",";
    	}
    	if(this.backward.size()>1){
    		dump+="\"BwdIATTot\":";
			dump+=this.backwardIAT.getSum()+",";
			dump+="\"BwdIATMean\":";
        	dump+=this.backwardIAT.getMean()+",";
        	dump+="\"BwdIATStd\":";
        	dump+=this.backwardIAT.getStandardDeviation()+",";
        	dump+="\"BwdIATMax\":";
        	dump+=this.backwardIAT.getMax()+",";
        	dump+="\"BwdIATMin\":";
        	dump+=this.backwardIAT.getMin()+","; 
    	}else{
    		dump+="\"BwdIATTot\":";
			dump+="0"+",";
			dump+="\"BwdIATMean\":";
        	dump+="0"+",";
        	dump+="\"BwdIATStd\":";
        	dump+="0"+",";
        	dump+="\"BwdIATMax\":";
        	dump+="0"+",";
        	dump+="\"BwdIATMin\":";
        	dump+="0"+",";
    	}

    	dump+="\"FwdPSHFlags\":";
		dump+=this.fPSH_cnt+",";

		dump+="\"FwdHeaderLen\":";
		dump+=this.fHeaderBytes+",";
		dump+="\"BwdHeaderLen\":";
		dump+=this.bHeaderBytes+",";
		dump+="\"FwdPktss\":";
		dump+=getfPktsPerSecond()+",";
		dump+="\"BwdPktss\":";
		dump+=getbPktsPerSecond()+",";

		if(this.forward.size() > 0 || this.backward.size() > 0){
			dump+="\"PktLenMax\":";
			dump+=this.flowLengthStats.getMax()+",";
			dump+="\"PktLenStd\":";
			dump+=this.flowLengthStats.getStandardDeviation()+",";
			dump+="\"PktLenVar\":";
			dump+=flowLengthStats.getVariance()+",";
		}else{
			dump+="\"PktLenMax\":";
			dump+="0"+",";
			dump+="\"PktLenStd\":";
			dump+="0"+",";
			dump+="\"PktLenVar\":";
			dump+="0"+",";
		}

		String key = "FIN";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "SYN";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "RST";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "PSH";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "ACK";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "CWR";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";
		key = "ECE";
		dump+= "\""+key+"Flag"+"Cnt\":"+flagCounts.get(key).value+",";

		dump+="\"DownUpRatio\":";
		dump+=getDownUpRatio()+",";
		dump+="\"PktSizeAvg\":";
		dump+=getAvgPacketSize()+",";
		dump+="\"BwdSegSizeAvg\":";
		dump+=bAvgSegmentSize()+",";
		
		//dump+=this.fHeaderBytes+",";  //this feature is duplicated



		dump+="\"BwdPktsbAvg\":";
		dump+=bAvgPacketsPerBulk()+",";
		dump+="\"BwdBlkRateAvg\":";
		dump+=bAvgBulkRate()+",";

		dump+="\"SubflowFwdPkts\":";
		dump+=getSflow_fpackets()+",";
		dump+="\"SubflowFwdByts\":";
		dump+=getSflow_fbytes()+",";
		dump+="\"SubflowBwdByts\":";
		dump+=getSflow_bbytes()+",";

		dump+="\"InitFwdWinByts\":";
		dump+=this.Init_Win_bytes_forward+",";
		dump+="\"InitBwdWinByts\":";
		dump+=this.Init_Win_bytes_backward+",";
		dump+="\"FwdActDataPkts\":";
		dump+=this.Act_data_pkt_forward+",";
		dump+="\"FwdSegSizeMin\":";
		dump+=this.min_seg_size_forward+",";

    	if(this.flowActive.getN()>0){
    	}else{
    	}    	
    	
    	if(this.flowIdle.getN()>0){
    		dump+="\"IdleMean\":";
	    	dump+=this.flowIdle.getMean()+",";
	    	dump+="\"IdleStd\":";
	    	dump+=this.flowIdle.getStandardDeviation(); 
    	}else{
    		dump+="\"IdleMean\":";
	    	dump+="0"+",";
	    	dump+="\"IdleStd\":";
	    	dump+="0";
    	}
		dump+="}";

		/*if(FormatUtils.ip(src).equals("147.32.84.165") | FormatUtils.ip(dst).equals("147.32.84.165")){
			dump+=",BOTNET";
		}
		else{
			dump+=",BENIGN";
		} */
		/////////////////////////////////
    	return dump;
    }      


    public int packetCount(){
    	if(isBidirectional){
    		return (this.forward.size() + this.backward.size()); 
    	}else{
    		return this.forward.size();    		
    	}
    }
    
	public List<BasicPacketInfo> getForward() {
		return new ArrayList<>(forward);
	}

	public void setForward(List<BasicPacketInfo> forward) {
		this.forward = forward;
	}

	public List<BasicPacketInfo> getBackward() {
		return new ArrayList<>(backward);
	}

	public void setBackward(List<BasicPacketInfo> backward) {
		this.backward = backward;
	}

	public boolean isBidirectional() {
		return isBidirectional;
	}

	public void setBidirectional(boolean isBidirectional) {
		this.isBidirectional = isBidirectional;
	}

	public byte[] getSrc() {
		return Arrays.copyOf(src,src.length);
	}

	public void setSrc(byte[] src) {
		this.src = src;
	}

	public byte[] getDst() {
		return Arrays.copyOf(dst,dst.length);
	}

	public void setDst(byte[] dst) {
		this.dst = dst;
	}

	public byte[] getSrcMac() {
		return srcMac;
	}

	public void setSrcMac(byte[] srcMac) {
		this.srcMac = srcMac;
	}

	public byte[] getDstMac() {
		return dstMac;
	}

	public void setDstMac(byte[] dstMac) {
		this.dstMac = dstMac;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public int getProtocol() {
		return protocol;
	}
	
	public String getProtocolStr() {
		switch(this.protocol){
		case(6):
			return "TCP";
		case(17):
		    return "UDP";
		}
		return "UNKNOWN";
	}	

	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	public long getFlowStartTime() {
		return flowStartTime;
	}

	public void setFlowStartTime(long flowStartTime) {
		this.flowStartTime = flowStartTime;
	}

	public String getFlowId() {
		return flowId;
	}

	public void setFlowId(String flowId) {
		this.flowId = flowId;
	}

	public long getLastSeen() {
		return flowLastSeen;
	}

	public void setLastSeen(long lastSeen) {
		this.flowLastSeen = lastSeen;
	}

	public long getStartActiveTime() {
		return startActiveTime;
	}

	public void setStartActiveTime(long startActiveTime) {
		this.startActiveTime = startActiveTime;
	}

	public long getEndActiveTime() {
		return endActiveTime;
	}

	public void setEndActiveTime(long endActiveTime) {
		this.endActiveTime = endActiveTime;
	}
		
	public String getSrcIP() {
		return FormatUtils.ip(src);
	}
	
	public String getDstIP() {
		return FormatUtils.ip(dst);
	}
	
	public String getTimeStamp() {
		return DateFormatter.parseDateFromLong(flowStartTime/1000L, "dd/MM/yyyy hh:mm:ss");
	}
	
	public long getFlowDuration() {
		return flowLastSeen - flowStartTime;
	}
	
	public long getTotalFwdPackets() {
		return fwdPktStats.getN();
	}
	
	public long getTotalBackwardPackets() {
		return bwdPktStats.getN();
	}
	
	public double getTotalLengthofFwdPackets() {
		return fwdPktStats.getSum();
	}
	
	public double getTotalLengthofBwdPackets() {
		return bwdPktStats.getSum();
	}
	
	public double getFwdPacketLengthMax() {
		return (fwdPktStats.getN() > 0L)? fwdPktStats.getMax():0;
	}
	
	public double getFwdPacketLengthMin() {
		return (fwdPktStats.getN() > 0L)? fwdPktStats.getMin():0;
	}
	
	public double getFwdPacketLengthMean() {
		return (fwdPktStats.getN() > 0L)? fwdPktStats.getMean():0;
	}
	
	public double getFwdPacketLengthStd() {
		return (fwdPktStats.getN() > 0L)? fwdPktStats.getStandardDeviation():0;
	}
	
	public double getBwdPacketLengthMax() {
		return (bwdPktStats.getN() > 0L)? bwdPktStats.getMax():0;
	}
	
	public double getBwdPacketLengthMin() {
		return (bwdPktStats.getN() > 0L)? bwdPktStats.getMin():0;
	}
	
	public double getBwdPacketLengthMean() {
		return (bwdPktStats.getN() > 0L)? bwdPktStats.getMean():0;
	}
	
	public double getBwdPacketLengthStd() {
		return (bwdPktStats.getN() > 0L)? bwdPktStats.getStandardDeviation():0;
	}
	
	public double getFlowBytesPerSec(){
		//flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
		return ((double)(forwardBytes+backwardBytes))/((double)getFlowDuration()/1000000L);
	}
	
	public double getFlowPacketsPerSec() {
		return ((double)packetCount())/((double)getFlowDuration()/1000000L);
	}
	
	public SummaryStatistics getFlowIAT() {
		return flowIAT;
	}
	
	public double getFwdIATTotal() {
		return (forward.size()>1)? forwardIAT.getSum():0;
	}
	
	public double getFwdIATMean() {
		return (forward.size()>1)? forwardIAT.getMean():0;
	}
	
	public double getFwdIATStd() {
		return (forward.size()>1)? forwardIAT.getStandardDeviation():0;
	}
	
	public double getFwdIATMax() {
		return (forward.size()>1)? forwardIAT.getMax():0;
	}
	
	public double getFwdIATMin() {
		return (forward.size()>1)? forwardIAT.getMin():0;
	}
	
	public double getBwdIATTotal() {
		return (backward.size()>1)? backwardIAT.getSum():0;
	}
	
	public double getBwdIATMean() {
		return (backward.size()>1)? backwardIAT.getMean():0;
	}
	
	public double getBwdIATStd() {
		return (backward.size()>1)? backwardIAT.getStandardDeviation():0;
	}
	
	public double getBwdIATMax() {
		return (backward.size()>1)? backwardIAT.getMax():0;
	}
	
	public double getBwdIATMin() {
		return (backward.size()>1)? backwardIAT.getMin():0;
	}
	
	public int getFwdPSHFlags() {
		return fPSH_cnt;
	}
	
	public int getBwdPSHFlags() {
		return bPSH_cnt;
	}
	
	public int getFwdURGFlags() {
		return fURG_cnt;
	}
	
	public int getBwdURGFlags() {
		return bURG_cnt;
	}
	
	public long getFwdHeaderLength() {
		return fHeaderBytes;
	}
	
	public long getBwdHeaderLength() {
		return bHeaderBytes;
	}
	
	public double getMinPacketLength() {
		return (forward.size() > 0 || backward.size() > 0)? flowLengthStats.getMin():0;
	}
	
	public double getMaxPacketLength() {
		return (forward.size() > 0 || backward.size() > 0)? flowLengthStats.getMax():0;
	}
	
	public double getPacketLengthMean() {
		return (forward.size() > 0 || backward.size() > 0)? flowLengthStats.getMean():0;
	}
	
	public double getPacketLengthStd() {
		return (forward.size() > 0 || backward.size() > 0)? flowLengthStats.getStandardDeviation():0;
	}
	
	public double getPacketLengthVariance() {
		return (forward.size() > 0 || backward.size() > 0)? flowLengthStats.getVariance():0;
	}
	
	public int getFlagCount(String key) {
		return flagCounts.get(key).value;
	}
	
	public int getInit_Win_bytes_forward() {
		return Init_Win_bytes_forward;
	}
	
	public int getInit_Win_bytes_backward() {
		return Init_Win_bytes_backward;
	}
	
	public long getAct_data_pkt_forward() {
		return Act_data_pkt_forward;
	}
	
	public long getmin_seg_size_forward() {
		return min_seg_size_forward;
	}
	
	public double getActiveMean() {
		return (flowActive.getN()>0)? flowActive.getMean():0;
	} 
	
	public double getActiveStd() {
		return (flowActive.getN()>0)? flowActive.getStandardDeviation():0;
	}
	
	public double getActiveMax() {
		return (flowActive.getN()>0)? flowActive.getMax():0;
	}
	
	public double getActiveMin() {
		return (flowActive.getN()>0)? flowActive.getMin():0;
	}
	
	public double getIdleMean() {
		return (flowIdle.getN()>0)? flowIdle.getMean():0;
	}
	
	public double getIdleStd() {
		return (flowIdle.getN()>0)? flowIdle.getStandardDeviation():0;
	}
	
	public double getIdleMax() {
		return (flowIdle.getN()>0)? flowIdle.getMax():0;
	}
	
	public double getIdleMin() {
		return (flowIdle.getN()>0)? flowIdle.getMin():0;
	}
	
	public String getLabel() {
		//the original is "|". I think it should be "||" need to check,
		/*if(FormatUtils.ip(src).equals("147.32.84.165") || FormatUtils.ip(dst).equals("147.32.84.165")){
			return "BOTNET";													
		}
		else{
			return "BENIGN";
		}*/
        return "No Label";
    }
	
    public String dumpFlowBasedFeaturesEx() {
    	StringBuilder dump = new StringBuilder();
    	
    	dump.append(flowId).append(separator);                						//1
    	dump.append(FormatUtils.ip(src)).append(separator);   						//2
    	dump.append(getSrcPort()).append(separator);          						//3
    	dump.append(FormatUtils.ip(dst)).append(separator);  						//4
    	dump.append(getDstPort()).append(separator);          						//5
    	dump.append(getProtocol()).append(separator);         						//6 
    	
    	String starttime = DateFormatter.convertMilliseconds2String(flowStartTime/1000L, "dd/MM/yyyy hh:mm:ss a");
    	dump.append(starttime).append(separator);									//7
    	
    	long flowDuration = flowLastSeen - flowStartTime;
    	dump.append(flowDuration).append(separator);								//8
    	
    	dump.append(fwdPktStats.getN()).append(separator);							//9
    	dump.append(bwdPktStats.getN()).append(separator);							//10	
    	dump.append(fwdPktStats.getSum()).append(separator);						//11
    	dump.append(bwdPktStats.getSum()).append(separator);						//12
    	
    	if(fwdPktStats.getN() > 0L) {
    		dump.append(fwdPktStats.getMax()).append(separator);					//13
    		dump.append(fwdPktStats.getMin()).append(separator);					//14
    		dump.append(fwdPktStats.getMean()).append(separator);					//15
    		dump.append(fwdPktStats.getStandardDeviation()).append(separator);		//16
    	}else {
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    	}
    	
    	if(bwdPktStats.getN() > 0L) {
    		dump.append(bwdPktStats.getMax()).append(separator);					//17
    		dump.append(bwdPktStats.getMin()).append(separator);					//18
    		dump.append(bwdPktStats.getMean()).append(separator);					//19
    		dump.append(bwdPktStats.getStandardDeviation()).append(separator);		//20
		}else{
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
		}
    	dump.append(((double)(forwardBytes+backwardBytes))/((double)flowDuration/1000000L)).append(separator);//21
    	dump.append(((double)packetCount())/((double)flowDuration/1000000L)).append(separator);//22
    	dump.append(flowIAT.getMean()).append(separator);							//23
    	dump.append(flowIAT.getStandardDeviation()).append(separator);				//24
    	dump.append(flowIAT.getMax()).append(separator);							//25
    	dump.append(flowIAT.getMin()).append(separator);							//26
    	
    	if(this.forward.size()>1){
        	dump.append(forwardIAT.getSum()).append(separator);						//27
        	dump.append(forwardIAT.getMean()).append(separator);					//28
        	dump.append(forwardIAT.getStandardDeviation()).append(separator);		//29	
        	dump.append(forwardIAT.getMax()).append(separator);						//30
        	dump.append(forwardIAT.getMin()).append(separator);						//31
        	
    	}else{
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    	}
    	if(this.backward.size()>1){
        	dump.append(backwardIAT.getSum()).append(separator);					//32
        	dump.append(backwardIAT.getMean()).append(separator);					//33
        	dump.append(backwardIAT.getStandardDeviation()).append(separator);		//34	
        	dump.append(backwardIAT.getMax()).append(separator);					//35
        	dump.append(backwardIAT.getMin()).append(separator);					//36
    	}else{
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    	}
    	
		dump.append(fPSH_cnt).append(separator);									//37
		dump.append(bPSH_cnt).append(separator);									//38
		dump.append(fURG_cnt).append(separator);									//39
		dump.append(bURG_cnt).append(separator);									//40

		dump.append(fHeaderBytes).append(separator);								//41
		dump.append(bHeaderBytes).append(separator);								//42
		dump.append(getfPktsPerSecond()).append(separator);							//43
		dump.append(getbPktsPerSecond()).append(separator);							//44
		
		
		if(this.forward.size() > 0 || this.backward.size() > 0){
			dump.append(flowLengthStats.getMin()).append(separator);				//45
			dump.append(flowLengthStats.getMax()).append(separator);				//46
			dump.append(flowLengthStats.getMean()).append(separator);				//47
			dump.append(flowLengthStats.getStandardDeviation()).append(separator);	//48
			dump.append(flowLengthStats.getVariance()).append(separator);			//49
		}else{//seem to less one
			dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
		}
		
		/*for(MutableInt v:flagCounts.values()) {
			dump.append(v).append(separator);
		}
		for(String key: flagCounts.keySet()){
			dump.append(flagCounts.get(key).value).append(separator);				//50,51,52,53,54,55,56,57
		} */
		dump.append(flagCounts.get("FIN").value).append(separator);                 //50
		dump.append(flagCounts.get("SYN").value).append(separator);                 //51
		dump.append(flagCounts.get("RST").value).append(separator);                  //52
		dump.append(flagCounts.get("PSH").value).append(separator);                  //53
		dump.append(flagCounts.get("ACK").value).append(separator);                  //54
		dump.append(flagCounts.get("URG").value).append(separator);                  //55
		dump.append(flagCounts.get("CWR").value).append(separator);                  //56
		dump.append(flagCounts.get("ECE").value).append(separator);                  //57
		
		dump.append(getDownUpRatio()).append(separator);							//58
		dump.append(getAvgPacketSize()).append(separator);							//59
		dump.append(fAvgSegmentSize()).append(separator);							//60
		dump.append(bAvgSegmentSize()).append(separator);							//61
		//dump.append(fHeaderBytes).append(separator);								//62 dupicate with 41
		
		dump.append(fAvgBytesPerBulk()).append(separator);							//63	
		dump.append(fAvgPacketsPerBulk()).append(separator);						//64
		dump.append(fAvgBulkRate()).append(separator);								//65
		dump.append(fAvgBytesPerBulk()).append(separator);							//66
		dump.append(bAvgPacketsPerBulk()).append(separator);						//67
		dump.append(bAvgBulkRate()).append(separator);								//68
    	
		dump.append(getSflow_fpackets()).append(separator);							//69
		dump.append(getSflow_fbytes()).append(separator);							//70
		dump.append(getSflow_bpackets()).append(separator);							//71
		dump.append(getSflow_bbytes()).append(separator);							//72
			
    	dump.append(Init_Win_bytes_forward).append(separator);						//73
    	dump.append(Init_Win_bytes_backward).append(separator);						//74
    	dump.append(Act_data_pkt_forward).append(separator);						//75
    	dump.append(min_seg_size_forward).append(separator);						//76
    	
    	
    	if(this.flowActive.getN()>0){
        	dump.append(flowActive.getMean()).append(separator);					//77
        	dump.append(flowActive.getStandardDeviation()).append(separator);		//78
        	dump.append(flowActive.getMax()).append(separator);						//79
        	dump.append(flowActive.getMin()).append(separator);						//80
    	}else{
			dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    	}    	
    	
    	if(this.flowIdle.getN()>0){
	    	dump.append(flowIdle.getMean()).append(separator);						//81
	    	dump.append(flowIdle.getStandardDeviation()).append(separator);			//82
	    	dump.append(flowIdle.getMax()).append(separator);						//83
	    	dump.append(flowIdle.getMin()).append(separator);						//84	
    	}else{
			dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    		dump.append(0).append(separator);
    	}

        dump.append(getLabel());

    	
    	return dump.toString();
    }
}
class MutableInt {
	int value = 0; // note that we start at 1 since we're counting
	public void increment () { ++value;      }
	public int  get ()       { return value; }
	
	
}



