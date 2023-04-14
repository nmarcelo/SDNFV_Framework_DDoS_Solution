package mx.itesm.FlowCollector.jnetpcap.worker;

import mx.itesm.FlowCollector.jnetpcap.BasicFlow;

public interface FlowGenListener {
    void onFlowGenerated(BasicFlow flow);
}
