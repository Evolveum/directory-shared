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
package org.apache.directory.api.ldap.model.schema.syntaxes.parser;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.text.ParseException;

import org.apache.directory.api.ldap.model.schema.DitStructureRule;
import org.apache.directory.api.ldap.model.schema.parsers.DitStructureRuleDescriptionSchemaParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Tests the DitStructureRuleDescriptionSchemaParser class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DitStructureRuleDescriptionSchemaParserTest
{
    /** the parser instance */
    private DitStructureRuleDescriptionSchemaParser parser;


    @Before
    public void setUp() throws Exception
    {
        parser = new DitStructureRuleDescriptionSchemaParser();
    }


    @After
    public void tearDown() throws Exception
    {
        parser = null;
    }


    /**
     * Test ruleid
     * 
     * @throws ParseException
     */
    @Test
    public void testNumericRuleId() throws ParseException
    {
        String value = null;
        DitStructureRule ditStructureRule = null;

        // null test
        value = null;
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, null" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no ruleid
        value = "( )";
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, no ruleid" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // simple
        value = "( 1 FORM 1.1 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 1, ditStructureRule.getRuleId() );

        // simple
        value = "( 1234567890 FORM 1.1 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 1234567890, ditStructureRule.getRuleId() );

        // simple with spaces
        value = "(      1234567890   FORM   1.1     )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 1234567890, ditStructureRule.getRuleId() );

        // non-numeric not allowed
        value = "( test FORM 1.1 )";
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, invalid ruleid test (non-numeric)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // oid not allowed
        value = "( 1.2.3.4 FORM 1.1 )";
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, invalid ruleid 1.2.3.4 (oid)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // quotes not allowed
        value = "( '1234567890' FORM 1.1 )";
        try
        {
            parser.parse( value );
            fail( "Exception expected, invalid ruleid '1234567890' (quoted)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

    }


    /**
     * Tests NAME and its values
     * 
     * @throws ParseException
     */
    @Test
    public void testNames() throws ParseException
    {
        SchemaParserTestUtils.testNames( parser, "1", "FORM 1.1" );
    }


    /**
     * Tests DESC
     * 
     * @throws ParseException
     */
    @Test
    public void testDescription() throws ParseException
    {
        SchemaParserTestUtils.testDescription( parser, "1", "FORM 1.1" );
    }


    /**
     * Tests OBSOLETE
     * 
     * @throws ParseException
     */
    @Test
    public void testObsolete() throws ParseException
    {
        SchemaParserTestUtils.testObsolete( parser, "1", "FORM 1.1" );
    }


    /**
     * Tests FORM
     * 
     * @throws ParseException
     */
    @Test
    public void testForm() throws ParseException
    {
        String value = null;
        DitStructureRule ditStructureRule = null;

        // numeric oid
        value = "( 1 FORM 1.2.3.4.5.6.7.8.9.0 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "1.2.3.4.5.6.7.8.9.0", ditStructureRule.getForm() );

        // numeric oid
        value = "(   1    FORM    123.4567.890    )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "123.4567.890", ditStructureRule.getForm() );

        // descr
        value = "( 1 FORM abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditStructureRule.getForm() );

        // descr, no space
        value = "(1 FORMabc)";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "abc", ditStructureRule.getForm() );

        // descr, tab
        value = "\t(\t1\tFORM\tabc\t)\t";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "abc", ditStructureRule.getForm() );

        // quoted value
        value = "( 1 FORM '1.2.3.4.5.6.7.8.9.0' )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "1.2.3.4.5.6.7.8.9.0", ditStructureRule.getForm() );

        // no quote allowed
        value = "( 1 FORM ('test') )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( "test", ditStructureRule.getForm() );

        // invalid character
        value = "( 1 FORM 1.2.3.4.A )";
        try
        {
            ditStructureRule = parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, invalid FORM 1.2.3.4.A (invalid character)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no multiple values
        value = "( 1 FORM ( test1 test2 ) )";
        try
        {
            ditStructureRule = parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, FORM must be single valued" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        if ( !parser.isQuirksMode() )
        {
            // invalid start
            value = "( 1 FORM -test ) )";
            try
            {
                ditStructureRule = parser.parseDITStructureRuleDescription( value );
                fail( "Exception expected, invalid FORM '-test' (starts with hypen)" );
            }
            catch ( ParseException pe )
            {
                // expected
            }
        }
    }


    /**
     * Tests SUP
     * 
     * @throws ParseException
     */
    @Test
    public void testSup() throws ParseException
    {
        String value = null;
        DitStructureRule ditStructureRule = null;

        // no SUP
        value = "( 1 FORM 1.1 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 0, ditStructureRule.getSuperRules().size() );

        // SUP simple number
        value = "( 1 FORM 1.1 SUP 1 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 1, ditStructureRule.getSuperRules().size() );
        assertEquals( Integer.valueOf( 1 ), ditStructureRule.getSuperRules().get( 0 ) );

        // SUP single number
        value = "( 1 FORM 1.1 SUP ( 1 ) )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 1, ditStructureRule.getSuperRules().size() );
        assertEquals( Integer.valueOf( 1 ), ditStructureRule.getSuperRules().get( 0 ) );

        // SUP multi number
        value = "( 1 FORM 1.1 SUP(12345 67890))";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertEquals( 2, ditStructureRule.getSuperRules().size() );
        assertEquals( Integer.valueOf( 12345 ), ditStructureRule.getSuperRules().get( 0 ) );
        assertEquals( Integer.valueOf( 67890 ), ditStructureRule.getSuperRules().get( 1 ) );

        // non-numeric not allowed
        value = "( 1 FORM 1.1 SUP test )";
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, invalid SUP test (non-numeric)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // oid not allowed
        value = "( 1 FORM 1.1 SUP 1.2.3.4 )";
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, invalid SUP 1.2.3.4 (oid)" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

    }


    /**
     * Test extensions.
     * 
     * @throws ParseException
     */
    @Test
    public void testExtensions() throws ParseException
    {
        SchemaParserTestUtils.testExtensions( parser, "1", "FORM 1.1" );

    }


    /**
     * Test full object class description.
     * 
     * @throws ParseException
     */
    @Test
    public void testFull() throws ParseException
    {
        String value = null;
        DitStructureRule ditStructureRule = null;

        value = "( 1234567890 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE FORM 2.3.4.5.6.7.8.9.0.1 SUP ( 1 1234567890 5 ) X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );

        assertEquals( 1234567890, ditStructureRule.getRuleId() );
        assertEquals( 2, ditStructureRule.getNames().size() );
        assertEquals( "abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", ditStructureRule.getNames()
            .get( 0 ) );
        assertEquals( "test", ditStructureRule.getNames().get( 1 ) );
        assertEquals( "Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577", ditStructureRule.getDescription() );
        assertTrue( ditStructureRule.isObsolete() );
        assertEquals( "2.3.4.5.6.7.8.9.0.1", ditStructureRule.getForm() );
        assertEquals( 3, ditStructureRule.getSuperRules().size() );
        assertEquals( Integer.valueOf( 1 ), ditStructureRule.getSuperRules().get( 0 ) );
        assertEquals( Integer.valueOf( 1234567890 ), ditStructureRule.getSuperRules().get( 1 ) );
        assertEquals( Integer.valueOf( 5 ), ditStructureRule.getSuperRules().get( 2 ) );
        assertEquals( 2, ditStructureRule.getExtensions().size() );
        assertNotNull( ditStructureRule.getExtension( "X-TEST-a" ) );
        assertEquals( 2, ditStructureRule.getExtension( "X-TEST-a" ).size() );
        assertEquals( "test1-1", ditStructureRule.getExtension( "X-TEST-a" ).get( 0 ) );
        assertEquals( "test1-2", ditStructureRule.getExtension( "X-TEST-a" ).get( 1 ) );
        assertNotNull( ditStructureRule.getExtension( "X-TEST-b" ) );
        assertEquals( 2, ditStructureRule.getExtension( "X-TEST-b" ).size() );
        assertEquals( "test2-1", ditStructureRule.getExtension( "X-TEST-b" ).get( 0 ) );
        assertEquals( "test2-2", ditStructureRule.getExtension( "X-TEST-b" ).get( 1 ) );
    }


    /**
     * Test unique elements.
     * 
     * @throws ParseException
     */
    @Test
    public void testUniqueElements()
    {
        String[] testValues = new String[]
            { "( 1 FORM 1.1 NAME 'test1' NAME 'test2' )", "( 1 FORM 1.1 DESC 'test1' DESC 'test2' )",
                "( 1 FORM 1.1 OBSOLETE OBSOLETE )", "( 1 FORM 1.1 FORM test1 FORM test2 )",
                "( 1 FORM 1.1 SUP 1 SUP 2 )", "( 1 FORM 1.1 X-TEST 'test1' X-TEST 'test2' )" };
        SchemaParserTestUtils.testUnique( parser, testValues );
    }


    /**
     * Test required elements.
     * 
     * @throws ParseException
     */
    @Test
    public void testRequiredElements() throws ParseException
    {
        String value = null;
        DitStructureRule ditStructureRule = null;

        value = "( 1 FORM 1.1 )";
        ditStructureRule = parser.parseDITStructureRuleDescription( value );
        assertNotNull( ditStructureRule.getForm() );

        value = "( 1 )";
        try
        {
            parser.parseDITStructureRuleDescription( value );
            fail( "Exception expected, FORM is required" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

    }


    /**
     * Tests the multithreaded use of a single parser.
     */
    @Test
    public void testMultiThreaded() throws ParseException
    {
        String[] testValues = new String[]
            {
                "( 1 FORM 1.1 )",
                "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )",
                "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )",
                "( 1234567890 NAME ( 'abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789' 'test' ) DESC 'Descripton \u00E4\u00F6\u00FC\u00DF \u90E8\u9577' OBSOLETE FORM 2.3.4.5.6.7.8.9.0.1 SUP ( 1 1234567890 5 ) X-TEST-a ('test1-1' 'test1-2') X-TEST-b ('test2-1' 'test2-2') )" };
        SchemaParserTestUtils.testMultiThreaded( parser, testValues );

    }


    /**
     * Tests quirks mode.
     */
    @Test
    public void testQuirksMode() throws ParseException
    {
        try
        {
            parser.setQuirksMode( true );

            // ensure all other test pass in quirks mode
            testNumericRuleId();
            testNames();
            testDescription();
            testObsolete();
            testForm();
            testSup();
            testExtensions();
            testFull();
            testUniqueElements();
            testMultiThreaded();
        }
        finally
        {
            parser.setQuirksMode( false );
        }
    }

}
