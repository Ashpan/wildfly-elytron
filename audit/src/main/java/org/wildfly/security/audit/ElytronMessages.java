/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.audit;

import java.io.IOException;
import java.net.PortUnreachableException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 11001, max = 11007),
    @ValidIdRange(min = 12000, max = 12999)
})
interface ElytronMessages extends BasicLogger {
    ElytronMessages audit = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.audit");

    /* Audit Exceptions */

    // 11000 - Unused in any Final release

    @LogMessage(level = Logger.Level.FATAL)
    @Message(id = 11001, value = "Endpoint unable to handle SecurityEvent priority=%s, message=%s")
    void endpointUnavaiable(String priority, String message, @Cause Throwable cause);

    @Message(id = 11002, value = "Invalid EventPriority '%s' passed to AuditEndpoint.")
    IllegalArgumentException invalidEventPriority(EventPriority eventPriority);

    @LogMessage(level = Logger.Level.ERROR)
    @Message(id = 11003, value = "Unable to rotate log file")
    void unableToRotateLogFile( @Cause Throwable cause);

    @Message(id = 11004, value = "Invalid suffix \"%s\" - rotating by second or millisecond is not supported")
    IllegalArgumentException rotatingBySecondUnsupported(String suffix);

    @LogMessage(level = Logger.Level.FATAL)
    @Message(id = 11007, value = "Endpoint unable to accept SecurityEvent.")
    void unableToAcceptEvent(@Cause Throwable cause);

    /*
     * The error code 12000 had accidentally been used twice, to avoid ambiguity it has been replaced with 12003.
     */

    //@Message(id = 12000, value = "The reconnect attempts value of %s is invalid. Please use an integer value >= -1.")
    //IllegalArgumentException badReconnectAttemptsNumber(int reconnectAttempts);

    @Message(id = 12001, value = "The maximum reconnect attempts value of %s was reached. The syslog endpoint will be shutdown.")
    IOException syslogMaximumReconnectAttemptsReached(int reconnectAttempts);

    @Message(id = 12002, value = "The configured UDP port is unavailable.")
    PortUnreachableException udpPortUnavailable(@Cause Throwable cause);

    @Message(id = 12003, value = "The reconnect attempts value of %s is invalid. Please use an integer value >= -1.")
    IllegalArgumentException badReconnectAttemptsNumber(int reconnectAttempts);

}
