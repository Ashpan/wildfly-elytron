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
package org.wildfly.security.auth.realm.ldap;

import java.nio.charset.Charset;
import java.security.Provider;
import java.util.function.Supplier;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.evidence.Evidence;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface IdentityEvidenceVerifier {

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or definitely not supported.
     *
     * @param evidenceType the evidence type (must not be {@code null})
     * @param algorithmName the algorithm name, if any
     * @param providers the providers to use when checking the ability to verify evidence.
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is unavailable to verify credentials.
     */
    SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName, Supplier<Provider[]> providers) throws RealmUnavailableException;

    /**
     * Verify the given evidence against the named credential.
     *
     * @param evidence the evidence to verify.
     * @param providers the providers to use when verifying evidence.
     * @return {@code true} if the evidence is successfully verified, {@code false} otherwise.
     * @throws RealmUnavailableException if the realm is unavailable to verify credentials.
     */
    boolean verifyEvidence(final Evidence evidence, Supplier<Provider[]> providers) throws RealmUnavailableException;

    /**
     * Verify the given evidence against the named credential.
     *
     * @param evidence the evidence to verify.
     * @param providers the providers to use when verifying evidence.
     * @param hashCharset the name of the character set (must not be {@code null}).
     * @return {@code true} if the evidence is successfully verified, {@code false} otherwise.
     * @throws RealmUnavailableException if the realm is unavailable to verify credentials.
     */
    default boolean verifyEvidence(final Evidence evidence, Supplier<Provider[]> providers, Charset hashCharset) throws RealmUnavailableException {
        return verifyEvidence(evidence, providers);
    }

}
