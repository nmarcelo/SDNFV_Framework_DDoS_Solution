package org.itesm.trafficEngineering;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;

import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Routes {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private List<Route> paths;

    @JsonCreator
    public Routes (@JsonProperty("paths") List<Route> paths) {

        try {

            checkNotNull(paths, "Paths must not be null.");

            int pathNum = paths.size();
            checkArgument(pathNum >= 1, "Number of paths must not be 0.");

            this.paths = paths;

        } catch (IllegalArgumentException | NullPointerException e) {

            log.error(e.getMessage());

        }

    }

    public List<Route> getPaths () {
        return this.paths;
    }

    @Override
    public String toString () {
        return MoreObjects
                .toStringHelper(this)
                .add("paths", this.paths)
                .toString();
    }

}