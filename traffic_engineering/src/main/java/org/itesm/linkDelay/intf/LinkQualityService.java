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

package org.itesm.linkDelay.intf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;

import java.util.List;
import java.util.Map;

/**
 * Link Quality Measurement Service.
 */
public interface LinkQualityService {

    /**
     * Get latency for one link.
     * @param link directional link.
     * @return the one-way latency of the specific link.
     */
    int getLinkLatency(Link link);

    /**
     * Get latencies for all links.
     *
     * @return one-way latencies of all links.
     */
    Map<Link, Float> getAllLinkLatencies();


    // ========== debug usages ==========
    Map<Link, Long> getAllInitLatencies();
    Map<DeviceId, Long> getAllControlLatencies();

    Map<Link, List<Float>> getDebugLinkLatancies();
}