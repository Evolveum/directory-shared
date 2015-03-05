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

import java.util.Arrays;

import org.apache.directory.api.util.Strings;

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
public class VirtualListViewRequestImpl extends AbstractControl implements VirtualListViewRequest
{
    private int beforeCount;
    private int afterCount;
    private int offset;
    private int contentCount;
    private byte[] contextId;

    /**
     * Creates a new instance of VirtualListViewRequestImpl.
     */
    public VirtualListViewRequestImpl()
    {
        super( OID );
    }
    
    
    @Override
    public int getBeforeCount()
    {
        return beforeCount;
    }


    @Override
    public void setBeforeCount( int beforeCount )
    {
        this.beforeCount = beforeCount;
    }


    @Override
    public int getAfterCount()
    {
        return afterCount;
    }


    @Override
    public void setAfterCount( int afterCount )
    {
        this.afterCount = afterCount;
    }


    @Override
    public int getOffset()
    {
        return offset;
    }


    @Override
    public void setOffset( int offset )
    {
        this.offset = offset;
    }

    @Override
    public int getContentCount()
    {
        return contentCount;
    }


    @Override
    public void setContentCount( int contentCount )
    {
        this.contentCount = contentCount;
    }


    @Override
    public byte[] getContextId()
    {
        return contextId;
    }


    @Override
    public void setContextId( byte[] contextId )
    {
        this.contextId = contextId;
    }
    
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = super.hashCode();

        h = h * 37 + beforeCount;
        h = h * 37 + afterCount;
        h = h * 37 + offset;
        h = h * 37 + contentCount;

        if ( contextId != null )
        {
            for ( byte b : contextId )
            {
                h = h * 17 + b;
            }
        }

        return h;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        VirtualListViewRequestImpl otherControl = ( VirtualListViewRequestImpl ) o;

        return ( beforeCount == otherControl.getBeforeCount() ) &&
            ( afterCount == otherControl.getAfterCount() ) &&
            ( offset == otherControl.getOffset() ) &&
            ( contentCount == otherControl.getContentCount() ) &&
            Arrays.equals( contextId, otherControl.getContextId() );
    }


    /**
     * Return a String representing this VirtualListViewRequestImpl.
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer();

        sb.append( "    Virtual List View Request Control\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        sb.append( "        beforeCount   : '" ).append( beforeCount ).append( "'\n" );
        sb.append( "        afterCount   : '" ).append( afterCount ).append( "'\n" );
        sb.append( "        offset   : '" ).append( offset ).append( "'\n" );
        sb.append( "        contentCount   : '" ).append( contentCount ).append( "'\n" );
        sb.append( "        contextID   : '" ).append( Strings.dumpBytes( contextId ) ).append( "'\n" );

        return sb.toString();
    }

}