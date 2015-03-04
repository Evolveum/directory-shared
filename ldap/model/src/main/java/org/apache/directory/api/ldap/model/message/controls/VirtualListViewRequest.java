/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.message.controls;

import org.apache.directory.api.ldap.model.message.Control;

/**
 * Virtual List View control as specified in draft-ietf-ldapext-ldapv3-vlv-09.
 * 
 *  VirtualListViewRequest ::= SEQUENCE {
 *         beforeCount    INTEGER (0..maxInt),
 *         afterCount     INTEGER (0..maxInt),
 *         target       CHOICE {
 *                        byOffset        [0] SEQUENCE {
 *                             offset          INTEGER (1 .. maxInt),
 *                             contentCount    INTEGER (0 .. maxInt) },
 *                        greaterThanOrEqual [1] AssertionValue },
 *         contextID     OCTET STRING OPTIONAL }
 * 
 * Simplistic implementation that only supports byOffset choice.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface VirtualListViewRequest extends Control
{
    String OID = "2.16.840.1.113730.3.4.9";
    
    int getBeforeCount();
    
    void setBeforeCount( int beforeCount );
    
    int getAfterCount();
    
    void setAfterCount( int afterCount );
    
    int getOffset();
    
    void setOffset( int offset );

    int getContentCount();
    
    void setContentCount( int contentCount );
    
    byte[] getContextId();
    
    void setContextId( byte[] contextId );

}
