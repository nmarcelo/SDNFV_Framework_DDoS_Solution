/*
 * Copyright 2018-present Open Networking Foundation
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

package org.itesm.resetConnection.intf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Link Quality Measurement Service.
 */
public interface ResetConnectionService {

    /**
     * Send connection reset
     * @param 
     * @return ok if successfully done
     */
    Boolean sendResetConnection(PortNumber portNumber, DeviceId deviceId, String sourceMACAddress, String destinationMACAddress, String sourceIpAddress, String destinationIpAddress, int SrcTcpPort);

}