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
package org.apache.directory.mitosis.service.protocol.handler;


import org.apache.directory.mitosis.common.CSNFactory;
import org.apache.directory.mitosis.common.CSNVector;
import org.apache.directory.mitosis.common.Replica;
import org.apache.directory.mitosis.operation.Operation;
import org.apache.directory.mitosis.service.ReplicationContext;
import org.apache.directory.mitosis.service.ReplicationInterceptor;
import org.apache.directory.mitosis.service.ReplicationContext.State;
import org.apache.directory.mitosis.service.protocol.Constants;
import org.apache.directory.mitosis.service.protocol.message.BeginLogEntriesAckMessage;
import org.apache.directory.mitosis.service.protocol.message.BeginLogEntriesMessage;
import org.apache.directory.mitosis.service.protocol.message.EndLogEntriesAckMessage;
import org.apache.directory.mitosis.service.protocol.message.EndLogEntriesMessage;
import org.apache.directory.mitosis.service.protocol.message.LogEntryAckMessage;
import org.apache.directory.mitosis.service.protocol.message.LogEntryMessage;
import org.apache.directory.mitosis.service.protocol.message.LoginAckMessage;
import org.apache.directory.mitosis.service.protocol.message.LoginMessage;
import org.apache.directory.mitosis.store.ReplicationStore;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.mina.core.session.IdleStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;


/**
 * {@link ReplicationContextHandler} that implements server-side replication logic
 * which retrieves any changes occurred in remote replicas.  Please refer to
 * {@link ReplicationClientContextHandler} for the detailed protocol flow and
 * the description of the replication logic execution.
 *
 * @author The Apache Directory Project (dev@directory.apache.org)
 * @version $Rev: 116 $, $Date: 2006-09-18 13:47:53Z $
 */
public class ReplicationServerContextHandler implements ReplicationContextHandler
{
    /** A logger for this class */
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private Replica replicaInTransaction;


    public void contextBegin( ReplicationContext ctx ) throws Exception
    {
        // Set login timeout
        ctx.getSession().getConfig().setIdleTime( IdleStatus.BOTH_IDLE, ctx.getConfiguration().getResponseTimeout() );

        // Set write timeout
        ctx.getSession().getConfig().setWriteTimeout( ctx.getConfiguration().getResponseTimeout() );
    }


    public synchronized void contextEnd( ReplicationContext ctx ) throws Exception
    {
        // Reset the mark if the context has the unfinished transaction.
        if ( ctx.getPeer() != null && ctx.getPeer().equals( replicaInTransaction ) )
        {
            replicaInTransaction = null;
        }
    }


    public void messageReceived( ReplicationContext ctx, Object message ) throws Exception
    {
        if ( ctx.getState() == State.READY )
        {
            if ( message instanceof LogEntryMessage )
            {
                onLogEntry( ctx, ( LogEntryMessage ) message );
            }
            else if ( message instanceof BeginLogEntriesMessage )
            {
                onBeginLogEntries( ctx, ( BeginLogEntriesMessage ) message );
            }
            else if ( message instanceof EndLogEntriesMessage )
            {
                onEndLogEntries( ctx, ( EndLogEntriesMessage ) message );
            }
            else
            {
                onUnexpectedMessage( ctx, message );
            }
        }
        else
        {
            if ( message instanceof LoginMessage )
            {
                onLogin( ctx, ( LoginMessage ) message );
            }
            else
            {
                onUnexpectedMessage( ctx, message );
            }
        }
    }


    public void messageSent( ReplicationContext ctx, Object message ) throws Exception
    {
    }


    public void exceptionCaught( ReplicationContext ctx, Throwable cause ) throws Exception
    {
        logger.warn( "[Replica-" + ctx.getConfiguration().getReplicaId()
                + "] Unexpected exception.", cause );
        ctx.getSession().close( true );
    }


    public void contextIdle( ReplicationContext ctx, IdleStatus status ) throws Exception
    {
        if ( ctx.getState() == State.INIT )
        {
            logger.warn( "[Replica-" + ctx.getConfiguration().getReplicaId()
                + "] No login attempt in " + ctx.getConfiguration().getResponseTimeout()
                + " second(s)." );
            ctx.getSession().close( true );
        }
    }


    private void onLogin( ReplicationContext ctx, LoginMessage message )
    {
        for ( Replica replica : ctx.getConfiguration().getPeerReplicas() )
        {
            if ( replica.getId().equals( message.getReplicaId() ) )
            {
                if ( replica.getAddress().getAddress().equals(
                        ( ( InetSocketAddress ) ctx.getSession().getRemoteAddress() ).getAddress() ) )
                {
                    ctx.getSession()
                            .write(
                                    new LoginAckMessage( message.getSequence(), Constants.OK, ctx.getConfiguration()
                                            .getReplicaId() ) );
                    ctx.setPeer( replica );
                    ctx.setState( State.READY );

                    // Clear login timeout.
                    ctx.getSession().getConfig().setIdleTime( IdleStatus.BOTH_IDLE, 0 );
                    return;
                }
                else
                {
                    logger.warn( "[Replica-" + ctx.getConfiguration().getReplicaId()
                            + "] Peer address mismatches: "
                            + ctx.getSession().getRemoteAddress() + " (expected: " + replica.getAddress() );
                    ctx.getSession().write(
                            new LoginAckMessage( message.getSequence(), Constants.NOT_OK, ctx.getConfiguration()
                                    .getReplicaId() ) );
                    ctx.getSession().close( true );
                    return;
                }
            }
        }

        logger.warn( "[Replica-" + ctx.getConfiguration().getReplicaId()
                + "] Unknown peer replica ID: " + message.getReplicaId() );
        ctx.getSession().write(
            new LoginAckMessage( message.getSequence(), Constants.NOT_OK, ctx.getConfiguration().getReplicaId() ) );
        ctx.getSession().close( true );
    }

    
    private synchronized void onLogEntry( ReplicationContext ctx, LogEntryMessage message ) throws Exception
    {
        // Return error if other replica than what is in progress sends
        // a log entry
        if ( !ctx.getPeer().equals( replicaInTransaction ) )
        {
            ctx.getSession().write( new LogEntryAckMessage( message.getSequence(), Constants.NOT_OK ) );
            return;
        }

        Operation op = message.getOperation();
        LogEntryAckMessage ack = null;
        
        try
        {
            DirectoryService directoryService = ctx.getDirectoryService();
            Interceptor interceptorInstance = directoryService.getInterceptor( ReplicationInterceptor.class.getName() ); 
            CSNFactory csnFactory = ((ReplicationInterceptor)interceptorInstance).getCsnFactory();
            op.execute( directoryService.getPartitionNexus(), ctx.getConfiguration().getStore(),
                directoryService.getSession(), csnFactory );
            
            ack = new LogEntryAckMessage( message.getSequence(), Constants.OK );
        }
        catch ( Exception e )
        {
            ack = new LogEntryAckMessage( message.getSequence(), Constants.NOT_OK );
            throw e;
        }
        finally
        {
            ctx.getSession().write( ack );
        }
    }


    private synchronized void onBeginLogEntries( ReplicationContext ctx, BeginLogEntriesMessage message )
    {
        // Return error if the transaction is already in progress.
        if ( replicaInTransaction != null )
        {
            ctx.getSession()
                .write( new BeginLogEntriesAckMessage( message.getSequence(), Constants.NOT_OK, null, null ) );
            return;
        }

        ReplicationStore store = ctx.getConfiguration().getStore();
        try
        {
            CSNVector pv = store.getPurgeVector();
            CSNVector uv = store.getUpdateVector();
            replicaInTransaction = ctx.getPeer(); // Mark as replica in transaction
            ctx.getSession().write( new BeginLogEntriesAckMessage( message.getSequence(), Constants.OK, pv, uv ) );
        }
        catch ( Exception e )
        {
            logger.warn( "Failed to get update vector.", e );
            ctx.getSession()
                .write( new BeginLogEntriesAckMessage( message.getSequence(), Constants.NOT_OK, null, null ) );
        }
    }


    private synchronized void onEndLogEntries( ReplicationContext ctx, EndLogEntriesMessage message )
    {
        // Return error if other replica than what is in progress sends
        // a flow control message
        if ( !ctx.getPeer().equals( replicaInTransaction ) )
        {
            ctx.getSession().write( new EndLogEntriesAckMessage( message.getSequence(), Constants.NOT_OK ) );
            return;
        }

        ctx.getSession().write( new EndLogEntriesAckMessage( message.getSequence(), Constants.OK ) );
        replicaInTransaction = null; // Reset the mark.
    }


    private void onUnexpectedMessage( ReplicationContext ctx, Object message )
    {
        logger.warn( "[Replica-" + ctx.getConfiguration().getReplicaId()
                + "] Unexpected message: " + message );
        ctx.getSession().close( true );
    }
}
