/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package org.apache.eve.processor.impl ;


import org.apache.eve.thread.ThreadPool ;
import org.apache.eve.event.EventRouter ;
import org.apache.eve.seda.DefaultStageConfig ;
import org.apache.eve.seda.StageMonitorAdapter;

import org.apache.eve.processor.RequestProcessor ;

import org.apache.avalon.framework.logger.Logger ;
import org.apache.avalon.framework.logger.LogEnabled ;
import org.apache.avalon.framework.activity.Startable ;
import org.apache.avalon.framework.service.Serviceable ;
import org.apache.avalon.framework.service.ServiceManager ;
import org.apache.avalon.framework.activity.Initializable ;
import org.apache.avalon.framework.service.ServiceException ;
import org.apache.avalon.framework.configuration.Configurable ;
import org.apache.avalon.framework.configuration.Configuration ;
import org.apache.avalon.framework.configuration.ConfigurationException ;

import org.apache.avalon.cornerstone.services.threads.ThreadManager ;


/**
 * A Merlin request processing service. 
 * 
 * @avalon.component name="request-processor" lifestyle="singleton"
 * @avalon.service type="org.apache.eve.processor.RequestProcessor" 
 *      version="1.0"
 *
 * @author <a href="mailto:directory-dev@incubator.apache.org">
 * Apache Directory Project</a>
 * @version $Rev$
 */
public class MerlinRequestProcessor
    implements 
    RequestProcessor, 
    LogEnabled, 
    Initializable, 
    Configurable,
    Serviceable,
    Startable
{
    /** the Avalon logger enabled monitor for the RequestProcessor */
    private AvalonLoggingMonitor monitor = new AvalonLoggingMonitor() ;
    /** underlying wrapped RequestProcessor implementation */
    private DefaultRequestProcessor requestProcessor = null ;
    /** the stage configuration bean for the underlying RequestProcessor */
    private DefaultStageConfig stageConfig = null ;
    /** the event router we depend on to recieve and publish events */
    private EventRouter router = null ;
    /** the thread manager used to access the thread pool used by the stage */
    private ThreadManager tm = null ;
    
    
    // ------------------------------------------------------------------------
    // RequestProcessor Interface Methods
    // ------------------------------------------------------------------------


    // nothing here yet
    
    
    // ------------------------------------------------------------------------
    // Avalon Life Cycle Methods ( in order of occurrence )
    // ------------------------------------------------------------------------

    
    /* (non-Javadoc)
     * @see org.apache.avalon.framework.logger.LogEnabled#
     * enableLogging(org.apache.avalon.framework.logger.Logger)
     */
    public void enableLogging( Logger logger )
    {
        monitor.enableLogging( logger ) ;
    }
    
   
    /**
     * @avalon.dependency type="org.apache.eve.event.EventRouter"
     *      key="event-router" version="1.0"
     * @avalon.dependency key="thread-manager"
     *      type="org.apache.avalon.cornerstone.services.threads.ThreadManager"
     *  
     * @see org.apache.avalon.framework.service.Serviceable#service(
     * org.apache.avalon.framework.service.ServiceManager)
     */
    public void service( ServiceManager manager ) throws ServiceException
    {
        tm = ( ThreadManager ) manager.lookup( "thread-manager" ) ;
        router = ( EventRouter ) manager.lookup( "event-router" ) ;
    }
    

    /* (non-Javadoc)
     * @see org.apache.avalon.framework.configuration.Configurable#configure(
     * org.apache.avalon.framework.configuration.Configuration)
     */
    public void configure( Configuration config ) 
        throws ConfigurationException
    {
        String name = config.getChild( "stage-name" ).getValue() ;
        String pool = config.getChild( "thread-pool" ).getValue() ;
        
        final org.apache.avalon.excalibur.thread.ThreadPool excaliburPool = 
            tm.getThreadPool( pool ) ;
        ThreadPool tp = new ThreadPool()
        {
            public void execute( Runnable runnable )
            {
                excaliburPool.execute( runnable ) ;
            }
        } ;
        
        stageConfig = new DefaultStageConfig( name, tp ) ;
    }

    
    /* (non-Javadoc)
     * @see org.apache.avalon.framework.activity.Initializable#initialize()
     */
    public void initialize() throws Exception
    {
        DefaultHandlerRegistry hooks = new DefaultHandlerRegistry() ;
        requestProcessor = 
            new DefaultRequestProcessor( router, stageConfig, hooks ) ;
        requestProcessor.setMonitor( new StageMonitorAdapter() ) ;
    }
    
    
    /* (non-Javadoc)
     * @see org.apache.avalon.framework.activity.Startable#start()
     */
    public void start() throws Exception
    {
        requestProcessor.start() ;
    }
    
    
    /* (non-Javadoc)
     * @see org.apache.avalon.framework.activity.Startable#stop()
     */
    public void stop() throws Exception
    {
        System.out.println( "stopping ... ") ;
        requestProcessor.stop() ;
    }
}
