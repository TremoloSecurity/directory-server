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
package org.apache.directory.mitosis.service.protocol.codec;


import org.apache.directory.mitosis.common.CSNFactory;
import org.apache.directory.mitosis.common.CSNVector;
import org.apache.directory.mitosis.service.protocol.Constants;
import org.apache.directory.mitosis.service.protocol.codec.BeginLogEntriesAckMessageDecoder;
import org.apache.directory.mitosis.service.protocol.codec.BeginLogEntriesAckMessageEncoder;
import org.apache.directory.mitosis.service.protocol.message.BeginLogEntriesAckMessage;


public class BeginLogEntriesAckMessageCodecTest extends AbstractMessageCodecTest
{

    private static final CSNVector PURGE_VECTOR = new CSNVector();
    private static final CSNVector UPDATE_VECTOR = new CSNVector();
    private static CSNFactory csnFactory = new CSNFactory();

    static
    {
        PURGE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() - 400, "replica0", 3456 ) );
        PURGE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() - 300, "replica1", 9012 ) );
        PURGE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() - 200, "replica2", 5678 ) );
        PURGE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() - 100, "replica3", 1234 ) );

        UPDATE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() + 000, "replica0", 1234 ) );
        UPDATE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() + 100, "replica1", 5678 ) );
        UPDATE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() + 200, "replica2", 9012 ) );
        UPDATE_VECTOR.setCSN( csnFactory.newInstance( System.currentTimeMillis() + 300, "replica3", 3456 ) );
    }


    public BeginLogEntriesAckMessageCodecTest()
    {
        super( new BeginLogEntriesAckMessage( 1234, Constants.OK, PURGE_VECTOR, UPDATE_VECTOR ),
            new BeginLogEntriesAckMessageEncoder(), new BeginLogEntriesAckMessageDecoder() );
    }
}
