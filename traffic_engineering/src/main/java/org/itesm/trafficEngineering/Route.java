package org.itesm.trafficEngineering;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import org.onosproject.net.DeviceId;
import org.onosproject.net.HostId;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

public class Route {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private HostId srcId;
    private HostId dstId;
    private List<DeviceId> deviceIds;

    @JsonCreator
    public Route (@JsonProperty("path") List<String> path) {

        try {

            checkNotNull(path, "Path must not be null.");

            int deviceNum = path.size();
            checkArgument(deviceNum >= 3, "Number of devices on path must not be less than 3.");

            this.srcId = HostId.hostId(path.get(0));
            this.dstId = HostId.hostId(path.get(deviceNum - 1));
            this.deviceIds = new ArrayList<DeviceId>();
            for (int i = 1; i < deviceNum - 1; i++) {
                this.deviceIds.add(DeviceId.deviceId(path.get(i)));
            }

        } catch (IllegalArgumentException | NullPointerException e) {

            log.error(e.getMessage());

        }
    }

    public HostId getDstId() {
        return this.dstId;
    }

    public HostId getSrcId() {
        return this.srcId;
    }

    public List<DeviceId> getDeviceIds() {
        return this.deviceIds;
    }

    @Override
    public String toString() {
        return MoreObjects
                .toStringHelper(this)
                .add("srcId", this.srcId)
                .add("dstId", this.dstId)
                .add("deviceIds", this.deviceIds)
                .toString();
    }

}
