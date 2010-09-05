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
package org.apache.directory.shared.asn1.util;


import org.apache.directory.shared.asn1.ber.tlv.Value;
import org.apache.directory.shared.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Parse and decode a Boolean value.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BooleanDecoder
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( BooleanDecoder.class );


    /**
     * This is a helper class, there is no reason to define a public constructor for it.
     */
    private BooleanDecoder()
    {
        // Do nothing
    }


    /**
     * Parse a byte buffer and send back a booelan.
     * 
     * @param value The byte buffer to parse
     * @return A boolean.
     * @throws BooleanDecoderException Thrown if the byte stream does not contains a boolean
     */
    public static boolean parse( Value value ) throws BooleanDecoderException
    {
        byte[] bytes = value.getData();

        if ( ( bytes == null ) || ( bytes.length == 0 ) )
        {
            throw new BooleanDecoderException( I18n.err( I18n.ERR_00034_0_BYTES_LONG_BOOLEAN ) );
        }

        if ( bytes.length != 1 )
        {
            throw new BooleanDecoderException( I18n.err( I18n.ERR_00035_N_BYTES_LONG_BOOLEAN ) );
        }

        if ( ( bytes[0] != 0 ) && ( bytes[0] != ( byte ) 0xFF ) )
        {
            LOG.warn( "A boolean must be encoded with a 0x00 or a 0xFF value" );
        }

        return bytes[0] != 0;
    }
}
