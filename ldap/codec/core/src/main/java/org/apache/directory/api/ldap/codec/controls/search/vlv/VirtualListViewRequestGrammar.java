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

import java.util.Arrays;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.StringConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO VirtualListViewRequestGrammar.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestGrammar extends AbstractGrammar<VirtualListViewRequestContainer>
{
    static final Logger LOG = LoggerFactory.getLogger(VirtualListViewRequestGrammar.class);
    
    static final boolean IS_DEBUG = LOG.isDebugEnabled();
    
    private static Grammar<?> instance = new VirtualListViewRequestGrammar();
    
    private VirtualListViewRequestGrammar()
    {
        setName( VirtualListViewRequestGrammar.class.getName() );

        super.transitions = new GrammarTransition[VirtualListViewRequestStates.LAST_STATE.ordinal()][256];

        super.transitions[VirtualListViewRequestStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.START_STATE,
                VirtualListViewRequestStates.VLV_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null );
        
        super.transitions[VirtualListViewRequestStates.VLV_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.VLV_SEQUENCE_STATE,
                VirtualListViewRequestStates.BEFORE_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new GrammarAction<VirtualListViewRequestContainer>( "Set VLV Request beforeCount" )
                {
                    @Override
                    public void action( VirtualListViewRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();
                        try
                        {
                            // Check that the value is into the allowed interval
                            int beforeCount = IntegerDecoder.parse( value, 0, Integer.MAX_VALUE );

                            if ( IS_DEBUG )
                            {
                                LOG.debug( "beforeCount = " + beforeCount );
                            }

                            container.getDecorator().setBeforeCount( beforeCount );
                        }
                        catch ( IntegerDecoderException e )
                        {
                            String msg = I18n.err( I18n.ERR_04050 );
                            LOG.error( msg, e );
                            throw new DecoderException( msg );
                        }
                        
                    }
                } );
        
        super.transitions[VirtualListViewRequestStates.BEFORE_COUNT_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.BEFORE_COUNT_STATE,
                VirtualListViewRequestStates.AFTER_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new GrammarAction<VirtualListViewRequestContainer>( "Set VLV Request afterCount" )
                {
                    @Override
                    public void action( VirtualListViewRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();
                        try
                        {
                            // Check that the value is into the allowed interval
                            int afterCount = IntegerDecoder.parse( value, 0, Integer.MAX_VALUE );

                            if ( IS_DEBUG )
                            {
                                LOG.debug( "afterCount = " + afterCount );
                            }

                            container.getDecorator().setAfterCount( afterCount );
                        }
                        catch ( IntegerDecoderException e )
                        {
                            String msg = I18n.err( I18n.ERR_04050 );
                            LOG.error( msg, e );
                            throw new DecoderException( msg );
                        }
                        
                    }
                } );
        
        super.transitions[VirtualListViewRequestStates.AFTER_COUNT_STATE.ordinal()][(byte)0xa0] = // TODO: cleanup
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.AFTER_COUNT_STATE,
                VirtualListViewRequestStates.TARGET_BY_OFFSET_STATE,
                (byte)0xa0, null ); // TODO: cleanup
        
        super.transitions[VirtualListViewRequestStates.TARGET_BY_OFFSET_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.TARGET_BY_OFFSET_STATE,
                VirtualListViewRequestStates.OFFSET_STATE,
                UniversalTag.INTEGER.getValue(),
                new GrammarAction<VirtualListViewRequestContainer>( "Set VLV Request offset" )
                {
                    @Override
                    public void action( VirtualListViewRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();
                        try
                        {
                            // Check that the value is into the allowed interval
                            int offset = IntegerDecoder.parse( value, 1, Integer.MAX_VALUE );

                            if ( IS_DEBUG )
                            {
                                LOG.debug( "offset = " + offset );
                            }

                            container.getDecorator().setOffset( offset );
                        }
                        catch ( IntegerDecoderException e )
                        {
                            String msg = I18n.err( I18n.ERR_04050 );
                            LOG.error( msg, e );
                            throw new DecoderException( msg );
                        }
                        
                    }
                } );
        
        super.transitions[VirtualListViewRequestStates.OFFSET_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.OFFSET_STATE,
                VirtualListViewRequestStates.CONTENT_COUNT_STATE,
                UniversalTag.INTEGER.getValue(),
                new GrammarAction<VirtualListViewRequestContainer>( "Set VLV Request contentCount" )
                {
                    @Override
                    public void action( VirtualListViewRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();
                        try
                        {
                            // Check that the value is into the allowed interval
                            int contentCount = IntegerDecoder.parse( value, 0, Integer.MAX_VALUE );

                            if ( IS_DEBUG )
                            {
                                LOG.debug( "contentCount = " + contentCount );
                            }

                            container.getDecorator().setContentCount( contentCount );
                        }
                        catch ( IntegerDecoderException e )
                        {
                            String msg = I18n.err( I18n.ERR_04050 );
                            LOG.error( msg, e );
                            throw new DecoderException( msg );
                        }
                        
                    }
                } );
        
        super.transitions[VirtualListViewRequestStates.CONTENT_COUNT_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<VirtualListViewRequestContainer>( 
                VirtualListViewRequestStates.CONTENT_COUNT_STATE,
                VirtualListViewRequestStates.CONTEXT_ID_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<VirtualListViewRequestContainer>( "Set VLV Request contextID" )
                {
                    @Override
                    public void action( VirtualListViewRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        if ( container.getCurrentTLV().getLength() == 0 )
                        {
                            container.getDecorator().setContextId( StringConstants.EMPTY_BYTES );

                            if ( IS_DEBUG )
                            {
                                LOG.debug( "contextID = []" );
                            }
                        }
                        else
                        {
                            container.getDecorator().setContextId( value.getData() );
                            
                            if ( IS_DEBUG )
                            {
                                LOG.debug( "contextID = " + Arrays.toString( value.getData() ) );
                            }
                        }

                        container.setGrammarEndAllowed( true );
                        
                    }
                } );
    }
    
    public static Grammar<?> getInstance()
    {
        return instance;
    }
}
