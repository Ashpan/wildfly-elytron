/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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
package org.wildfly.security.http.util;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.http.util.ElytronMessages.log;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A {@link HttpServerAuthenticationMechanismFactory} that is an aggregation of other factories.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class AggregateServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory[] factories;

    /**
     * Construct an instance of {@code AggregateServerMechanismFactory} with an array of factories to aggregate.
     *
     * @param factories the array of factories to aggregate.
     */
    public AggregateServerMechanismFactory(HttpServerAuthenticationMechanismFactory... factories) {
        this.factories = checkNotNullParam("factories", factories);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (HttpServerAuthenticationMechanismFactory current : factories) {
            if (current != null) {
                Collections.addAll(names, current.getMechanismNames(properties));
            }
        }
        if (log.isTraceEnabled()) {
            log.tracef("%s provided by factories in %s: %s", HttpServerAuthenticationMechanismFactory.class.getSimpleName(), getClass().getSimpleName(), Arrays.toString(factories));
        }
        return names.toArray(new String[names.size()]);
    }

    /**
     * @throws HttpAuthenticationException if there is a problem creating the mechanism instance.
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String,
     *      java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties,
            CallbackHandler callbackHandler) throws HttpAuthenticationException {
        for (HttpServerAuthenticationMechanismFactory current : factories) {
            if (current != null) {
                HttpServerAuthenticationMechanism mechanism = current.createAuthenticationMechanism(mechanismName, properties,
                        callbackHandler);
                if (mechanism != null) {
                    return mechanism;
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.tracef("Mechanism %s not provided as %s is not provided by factories in %s: %s",
                    mechanismName, HttpServerAuthenticationMechanismFactory.class.getSimpleName(),
                    getClass().getSimpleName(), Arrays.toString(factories));
        }
        return null;
    }

}
