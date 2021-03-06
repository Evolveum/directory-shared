/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;


/**
 * 
 * A decoder for PasswordModifyRequest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyResponseDecoder extends Asn1Decoder
{
    /** The decoder */
    private static final Asn1Decoder decoder = new Asn1Decoder();


    /**
     * Decode a PDU which must contain a PwdModifyRequest extended operation.
     * Note that the stream of bytes much contain a full PDU, not a partial one.
     * 
     * @param stream The bytes to be decoded
     * @return a PwdModifyRequest object
     * @throws org.apache.directory.api.asn1.DecoderException If the decoding failed
     */
    public PasswordModifyResponse decode( byte[] stream ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( stream );
        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();
        decoder.decode( bb, container );
        PasswordModifyResponseDecorator pwdModifyResponse = container.getPwdModifyResponse();

        // Clean the container for the next decoding
        container.clean();

        return pwdModifyResponse;
    }
}
