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

package org.apache.directory.api.ldap.codec.controls.search.vlv;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.controls.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.message.controls.VirtualListViewRequestImpl;

/**
 * TODO VirtualListViewRequestDecorator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestDecorator extends ControlDecorator<VirtualListViewRequest> implements VirtualListViewRequest
{
    private int vlvSeqLength;
    private int targetSeqLength;

    private static final Asn1Decoder decoder = new Asn1Decoder();
    
    
    public VirtualListViewRequestDecorator( LdapApiService codec )
    {
        this( codec, new VirtualListViewRequestImpl() );
    }
    
    
    public VirtualListViewRequestDecorator( LdapApiService codec, VirtualListViewRequest vlvRequest )
    {
        super( codec, vlvRequest );
    }
    
    public int computeLength()
    {
        int beforeCountLength = 1 + 1 + BerValue.getNbBytes( getBeforeCount() );
        int afterCountLength = 1 + 1 + BerValue.getNbBytes( getAfterCount() );

        int offsetLength = 1 + 1 + BerValue.getNbBytes( getOffset() );
        int contentCountLength = 1 + 1 + BerValue.getNbBytes( getContentCount() );
        
        int contextIdLength;

        if ( getContextId() != null )
        {
            contextIdLength = 1 + TLV.getNbBytes( getContextId().length ) + getContextId().length;
        }
        else
        {
            contextIdLength = 1 + 1;
        }

        targetSeqLength = offsetLength + contentCountLength;
        int targetValLength = 1 + TLV.getNbBytes(targetSeqLength) + targetSeqLength;
        vlvSeqLength = beforeCountLength + afterCountLength + targetValLength + contextIdLength;
        valueLength = 1 + TLV.getNbBytes( vlvSeqLength ) + vlvSeqLength;

        return valueLength;
    }
    
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( vlvSeqLength ) );

        BerValue.encode( buffer, getBeforeCount() );
        BerValue.encode( buffer, getAfterCount() );
        
        buffer.put( ( byte ) 0xa0 ); // TODO: cleanup
        buffer.put( TLV.getBytes( targetSeqLength ) );
        
        BerValue.encode( buffer, getOffset() );
        BerValue.encode( buffer, getContentCount() );
        
        BerValue.encode( buffer, getContextId() );

        return buffer;
    }
    
    public byte[] getValue()
    {
        if ( value == null )
        {
            try
            {
                computeLength();
                ByteBuffer buffer = ByteBuffer.allocate( valueLength );

                value = encode( buffer ).array();
            }
            catch ( Exception e )
            {
                return null;
            }
        }

        return value;
    }


    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        ByteBuffer buffer = ByteBuffer.wrap( controlBytes );
        VirtualListViewRequestContainer container = new VirtualListViewRequestContainer( this, getCodecService() );
        decoder.decode( buffer, container );
        return this;
    }


    @Override
    public int getBeforeCount()
    {
        return getDecorated().getBeforeCount();
    }


    @Override
    public void setBeforeCount( int beforeCount )
    {
        getDecorated().setBeforeCount( beforeCount );
    }


    @Override
    public int getAfterCount()
    {
        return getDecorated().getAfterCount();
    }


    @Override
    public void setAfterCount( int afterCount )
    {
        getDecorated().setAfterCount( afterCount );
    }


    @Override
    public int getOffset()
    {
        return getDecorated().getOffset();
    }


    @Override
    public void setOffset( int offset )
    {
        getDecorated().setOffset( offset );
    }


    @Override
    public int getContentCount()
    {
        return getDecorated().getContentCount();
    }


    @Override
    public void setContentCount( int contentCount )
    {
        getDecorated().setContentCount( contentCount );
    }


    @Override
    public byte[] getContextId()
    {
        return getDecorated().getContextId();
    }


    @Override
    public void setContextId( byte[] contextId )
    {
        getDecorated().setContextId( contextId );
    }

}
