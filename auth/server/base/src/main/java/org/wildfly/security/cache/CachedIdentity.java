/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.cache;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.Serializable;
import java.security.Principal;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * Represents a cached identity, managed by an {@link IdentityCache}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @see IdentityCache
 */
public final class CachedIdentity implements Serializable {

    private static final long serialVersionUID = -6408689383511392746L;

    private final String mechanismName;
    private final boolean programmatic;
    private final String name;
    private final transient SecurityIdentity securityIdentity;

    /**
     * Creates a new instance based on the given <code>mechanismName</code> and <code>securityIdentity</code>.
     *
     * @param mechanismName the name of the authentication mechanism used to authenticate/authorize the identity
     * @param programmatic indicates if this identity was created as a result of programmatic authentication
     * @param securityIdentity the identity to cache
     */
    public CachedIdentity(String mechanismName, boolean programmatic, SecurityIdentity securityIdentity) {
        this(mechanismName, programmatic, checkNotNullParam("securityIdentity", securityIdentity), securityIdentity.getPrincipal());
    }

    /**
     * Creates a new instance based on the given <code>mechanismName</code> and <code>principal</code>.
     *
     * @param mechanismName the name of the authentication mechanism used to authenticate/authorize the identity
     * @param programmatic indicates if this identity was created as a result of programmatic authentication
     * @param principal the principal of this cached identity
     */
    public CachedIdentity(String mechanismName, boolean programmatic, Principal principal) {
        this(mechanismName, programmatic, null, principal);
    }

    private CachedIdentity(String mechanismName, boolean programmatic, SecurityIdentity securityIdentity, Principal principal) {
        this.mechanismName = checkNotNullParam("mechanismName", mechanismName);
        this.programmatic = programmatic;
        this.name = checkNotNullParam("name", checkNotNullParam("principal", principal).getName());
        this.securityIdentity = securityIdentity;
    }

    /**
     * Returns the name of the authentication mechanism used to authenticate/authorize the identity.
     *
     * @return the name of the authentication mechanism used to authenticate/authorize the identity
     */
    public String getMechanismName() {
        return this.mechanismName;
    }

    /**
     * Returns the principal name associated with the cached identity.
     *
     * @return the principal name associated with the cached identity. The name should never be null, as it will be used to re-create the identity when necessary (not {@code null})
     */
    public String getName() {
        return this.name;
    }

    /**
     * Returns the identity represented by this instance.
     *
     * @return the identity represented by this instance. This method may return {@code null} in case the cache is holding the principal name only
     */
    public SecurityIdentity getSecurityIdentity() {
        return this.securityIdentity;
    }

    /**
     * Returns {@code true} if this identity was established using programmatic authentication, {@code false} otherwise.
     *
     * @return {@code true} if this identity was established using programmatic authentication, {@code false} otherwise.
     */
    public boolean isProgrammatic() {
        return programmatic;
    }

    @Override
    public String toString() {
        return "CachedIdentity{" + mechanismName + ", '" + name + "', " + securityIdentity + ", " + programmatic + "}";
    }
}
