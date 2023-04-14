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
package mx.itesm.FlowCollector.jnetpcap;

/**
 * TcpState 
 */
public class TcpState{

    public enum State {
        START,
        SYN,
        SYNACK,
        ESTABLISHED,
        FIN,
        CLOSED;
    }


    static final long TCP_FIN = 0x01;
    static final long TCP_SYN = 0x02;
    static final long TCP_RST = 0x04;
    static final long TCP_PSH = 0x08;
    static final long TCP_ACK = 0x10;
    static final long TCP_URG = 0x20;
    static final long TCP_ECE = 0x40;
    static final long TCP_CWR = 0x80;

    private State state;

    public TcpState(State state) {
        this.state = state;
    }

    public State getState(){
        return state;
    }

    public void setState(BasicPacketInfo packet, int dir, short pdir){
        if (packet.hasFlagRST()) { // is RST?
            state = State.CLOSED;
        } else if (packet.hasFlagFIN() && (dir == pdir)) { // is FIN
            state = State.FIN;
        } else if (state == State.FIN) {
            if (packet.hasFlagACK() && (dir != pdir)) { // is ACK
                state = State.CLOSED;
            }
        } else if (state == State.START) {
            if (packet.hasFlagSYN() && (dir == pdir)) { // is SYN from Client
                state = State.SYN;
            }
        } else if (state == State.SYN) {
            if (packet.hasFlagSYN()&& packet.hasFlagACK() && (dir != pdir)) { // is SYN-ACK from server
                state = State.SYNACK;
            }
        } else if (state == State.SYNACK) {                     
            if (packet.hasFlagACK() && (dir == pdir)) { // Ack from client: TCP connection stablished
                state = State.ESTABLISHED;
            }
        }
    }

    public boolean is_flags_FIN(short flags){ //
        return tcpSet(TCP_FIN, flags);
    }
    public boolean is_flags_SYN(short flags){ //
        return tcpSet(TCP_SYN, flags);
    }

    public boolean is_flags_RST(short flags){//
        return tcpSet(TCP_RST, flags);
    }

    public boolean is_flags_PSH(short flags){//
        return tcpSet(TCP_PSH, flags);
    }

    public boolean is_flags_ACK(short flags){//
        return tcpSet(TCP_ACK, flags);
    }

    public boolean is_flags_URG(short flags){//
        return tcpSet(TCP_URG, flags);
    }

    public boolean is_flags_ECE(short flags){//
        return tcpSet(TCP_ECE, flags);
    }

    public boolean is_flags_CWR(short flags){//
        return tcpSet(TCP_CWR, flags);
    }

    static boolean tcpSet(long find, short flags) {
        return ((find & flags) == find);
    }
    
}