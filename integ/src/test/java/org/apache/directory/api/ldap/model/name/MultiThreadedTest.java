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
package org.apache.directory.api.ldap.model.name;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.model.name.Ava;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.junit.tools.MultiThreadedMultiInvoker;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Multi-threaded 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class MultiThreadedTest
{
    @Rule
    public MultiThreadedMultiInvoker i = new MultiThreadedMultiInvoker( 100, 1000 );

    private static Dn referenceDn;
    private static Dn sharedDn;
    private static Rdn referenceRdn;
    private static Rdn sharedRdn;
    private static Ava referenceAva;
    private static Ava sharedAva;

    private static SchemaManager schemaManager;


    @BeforeClass
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();

        referenceDn = new Dn( "dc=example,dc=com" );
        referenceDn.apply( schemaManager );
        sharedDn = new Dn( "dc=example,dc=com" );
        sharedDn.apply( schemaManager );

        referenceRdn = new Rdn( "ou=system" );
        referenceRdn.apply( schemaManager );
        sharedRdn = new Rdn( "ou=system" );
        sharedRdn.apply( schemaManager );

        referenceAva = new Ava( schemaManager, "ou", "System" );
        sharedAva = new Ava( schemaManager, "ou", "System" );
    }


    @Test
    public void testNormalize() throws Exception
    {
        sharedAva.normalize();

        sharedRdn.apply( schemaManager );
        assertTrue( sharedRdn.isSchemaAware() );

        sharedDn.apply( schemaManager );
        assertTrue( sharedDn.isSchemaAware() );
    }


    @Test
    public void testNormalizeHashCode() throws Exception
    {
        assertEquals( referenceAva.hashCode(), sharedAva.hashCode() );

        sharedRdn.apply( schemaManager );
        assertEquals( referenceRdn.hashCode(), sharedRdn.hashCode() );

        sharedDn.apply( schemaManager );
        assertEquals( referenceDn.hashCode(), sharedDn.hashCode() );
    }


    @Test
    public void testNormalizeEquals() throws Exception
    {
        assertEquals( referenceAva, sharedAva );
        assertTrue( referenceAva.equals( sharedAva ) );
        assertTrue( sharedAva.equals( referenceAva ) );

        sharedRdn.apply( schemaManager );
        assertEquals( referenceRdn, sharedRdn );
        assertTrue( referenceRdn.equals( sharedRdn ) );
        assertTrue( sharedRdn.equals( referenceRdn ) );

        sharedDn.apply( schemaManager );
        assertEquals( referenceDn, sharedDn );
        assertTrue( referenceDn.equals( sharedDn ) );
        assertTrue( sharedDn.equals( referenceDn ) );
    }


    @Test
    public void testNormalizeCompare() throws Exception
    {
        assertTrue( sharedAva.equals( referenceAva ) );
        assertTrue( referenceAva.equals( sharedAva ) );

        assertTrue( referenceRdn.equals( sharedRdn ) );
        assertTrue( sharedRdn.equals( referenceRdn ) );

        assertEquals( referenceDn, sharedDn );
        assertEquals( sharedDn, referenceDn );
    }

}
