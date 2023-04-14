package org.itesm.trafficEngineering;

import org.onlab.rest.AbstractWebApplication;

import java.util.Set;

/**
 * Sample REST API web application.
 */
public class TrafficEngineeringApplication extends AbstractWebApplication {
    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(TrafficEngineeringResource.class);
    }
}
