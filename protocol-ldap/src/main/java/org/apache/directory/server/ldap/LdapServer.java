package org.apache.directory.server.ldap;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareResponse;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultReference;
import org.apache.directory.api.ldap.model.message.UnbindRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.ldap.handlers.LdapRequestHandler;
import org.apache.directory.server.ldap.handlers.LdapResponseHandler;
import org.apache.directory.server.ldap.handlers.request.ExtendedRequestHandler;
import org.apache.directory.server.ldap.handlers.response.ExtendedResponseHandler;
import org.apache.directory.server.ldap.handlers.sasl.MechanismHandler;
import org.apache.directory.server.ldap.replication.consumer.ReplicationConsumer;
import org.apache.directory.server.ldap.replication.provider.ReplicationRequestHandler;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.handler.demux.MessageHandler;

public interface LdapServer {

	/** Value (0) for configuration where size limit is unlimited. */
	long NO_SIZE_LIMIT = 0;
	/** Value (0) for configuration where time limit is unlimited. */
	int NO_TIME_LIMIT = 0;
	/** the constant service name of this ldap protocol provider **/
	String SERVICE_NAME = "ldap";

	/**
	 * loads the digital certificate either from a keystore file or from the admin entry in DIT
	 */
	void loadKeyStore() throws Exception;

	/**
	 * reloads the SSL context by replacing the existing SslFilter
	 * with a new SslFilter after reloading the keystore.
	 *
	 * Note: should be called to reload the keystore after changing the digital certificate.
	 * @throws Exception If the SSLContext can't be reloaded
	 */
	void reloadSslContext() throws Exception;

	/**
	 * @throws IOException if we cannot bind to the specified port
	 * @throws Exception if the LDAP server cannot be started
	 */
	void start() throws Exception;

	/**
	 * Install the replication handler if we have one
	 */
	void startReplicationProducer();

	/**
	 * {@inheritDoc}
	 */
	void stop();

	/**
	 * Starts the replication consumers
	 *
	 * @throws LdapException If the consumer can't be started
	 */
	void startReplicationConsumers() throws Exception;

	String getName();

	IoHandler getHandler();

	LdapSessionManager getLdapSessionManager();

	ProtocolCodecFactory getProtocolCodecFactory();

	/**
	 * Registers the specified {@link ExtendedOperationHandler} to this
	 * protocol provider to provide a specific LDAP extended operation.
	 *
	 * @param eoh an extended operation handler
	 * @throws Exception on failure to add the handler
	 */
	void addExtendedOperationHandler(
			ExtendedOperationHandler<? extends ExtendedRequest, ? extends ExtendedResponse> eoh) throws LdapException;

	/**
	 * Deregister an {@link ExtendedOperationHandler} with the specified <tt>oid</tt>
	 * from this protocol provider.
	 *
	 * @param oid the numeric identifier for the extended operation associated with
	 * the handler to remove
	 */
	void removeExtendedOperationHandler(String oid);

	/**
	 * Returns an {@link ExtendedOperationHandler} with the specified <tt>oid</tt>
	 * which is registered to this protocol provider.
	 *
	 * @param oid the oid of the extended request of associated with the extended
	 * request handler
	 * @return the exnteded operation handler
	 */
	ExtendedOperationHandler<? extends ExtendedRequest, ? extends ExtendedResponse> getExtendedOperationHandler(
			String oid);

	/**
	 * Sets the mode for this LdapServer to accept requests with or without a
	 * TLS secured connection via either StartTLS extended operations or using
	 * LDAPS.
	 *
	 * @param confidentialityRequired true to require confidentiality
	 */
	void setConfidentialityRequired(boolean confidentialityRequired);

	/**
	 * Gets whether or not TLS secured connections are required to perform
	 * operations on this LdapServer.
	 *
	 * @return true if TLS secured connections are required, false otherwise
	 */
	boolean isConfidentialityRequired();

	/**
	 * Returns <tt>true</tt> if LDAPS is enabled.
	 *
	 * @param transport The LDAP transport
	 * @return <tt>true</tt> if LDAPS is enabled.
	 */
	boolean isEnableLdaps(Transport transport);

	/**
	 * Sets the maximum size limit in number of entries to return for search.
	 *
	 * @param maxSizeLimit the maximum number of entries to return for search
	 */
	void setMaxSizeLimit(long maxSizeLimit);

	/**
	 * Returns the maximum size limit in number of entries to return for search.
	 *
	 * @return The maximum size limit.
	 */
	long getMaxSizeLimit();

	/**
	 * Sets the maximum time limit in milliseconds to conduct a search.
	 *
	 * @param maxTimeLimit the maximum length of time in milliseconds for search
	 */
	void setMaxTimeLimit(int maxTimeLimit);

	/**
	 * Returns the maximum time limit in milliseconds to conduct a search.
	 *
	 * @return The maximum time limit in milliseconds for search
	 */
	int getMaxTimeLimit();

	/**
	 * Gets the {@link ExtendedOperationHandler}s.
	 *
	 * @return A collection of {@link ExtendedOperationHandler}s.
	 */
	Collection<ExtendedOperationHandler<? extends ExtendedRequest, ? extends ExtendedResponse>> getExtendedOperationHandlers();

	/**
	 * Sets the {@link ExtendedOperationHandler}s.
	 *
	 * @param handlers A collection of {@link ExtendedOperationHandler}s.
	 */
	void setExtendedOperationHandlers(Collection<ExtendedOperationHandler<ExtendedRequest, ExtendedResponse>> handlers);

	/**
	 * Returns the FQDN of this SASL host, validated during SASL negotiation.
	 *
	 * @return The FQDN of this SASL host, validated during SASL negotiation.
	 */
	String getSaslHost();

	/**
	 * Sets the FQDN of this SASL host, validated during SASL negotiation.
	 *
	 * @param saslHost The FQDN of this SASL host, validated during SASL negotiation.
	 */
	void setSaslHost(String saslHost);

	/**
	 * Returns the Kerberos principal name for this LDAP service, used by GSSAPI.
	 *
	 * @return The Kerberos principal name for this LDAP service, used by GSSAPI.
	 */
	String getSaslPrincipal();

	/**
	 * Sets the Kerberos principal name for this LDAP service, used by GSSAPI.
	 *
	 * @param saslPrincipal The Kerberos principal name for this LDAP service, used by GSSAPI.
	 */
	void setSaslPrincipal(String saslPrincipal);

	/**
	 * Returns the quality-of-protection, used by DIGEST-MD5 and GSSAPI.
	 *
	 * @return The quality-of-protection, used by DIGEST-MD5 and GSSAPI.
	 */
	String getSaslQopString();

	/**
	 * Returns the Set of quality-of-protection, used by DIGEST-MD5 and GSSAPI.
	 *
	 * @return The quality-of-protection, used by DIGEST-MD5 and GSSAPI.
	 */
	Set<String> getSaslQop();

	/**
	 * Returns the realms serviced by this SASL host, used by DIGEST-MD5 and GSSAPI.
	 *
	 * @return The realms serviced by this SASL host, used by DIGEST-MD5 and GSSAPI.
	 */
	List<String> getSaslRealms();

	/**
	 * Sets the realms serviced by this SASL host, used by DIGEST-MD5 and GSSAPI.
	 *
	* @param saslRealms The realms serviced by this SASL host, used by DIGEST-MD5 and GSSAPI.
	 */
	void setSaslRealms(List<String> saslRealms);

	boolean isAuthRequired();

	void setAuthRequired(boolean authRequired);

	/**
	 * @return the supported SASL mechanisms
	 */
	Map<String, MechanismHandler> getSaslMechanismHandlers();

	void setSaslMechanismHandlers(Map<String, MechanismHandler> saslMechanismHandlers);

	MechanismHandler addSaslMechanismHandler(String mechanism, MechanismHandler handler);

	MechanismHandler removeSaslMechanismHandler(String mechanism);

	MechanismHandler getMechanismHandler(String mechanism);

	Set<String> getSupportedMechanisms();

	void setDirectoryService(DirectoryService directoryService);

	Set<String> getSupportedControls();

	/**
	 * @return The MessageReceived handler for the AbandonRequest
	 */
	MessageHandler<AbandonRequest> getAbandonRequestHandler();

	/**
	 * Inject the MessageReceived handler into the IoHandler
	 *
	 * @param abandonRequestdHandler The AbandonRequest message received handler
	 */
	void setAbandonHandler(LdapRequestHandler<AbandonRequest> abandonRequestdHandler);

	/**
	 * @return The MessageReceived handler for the AddRequest
	 */
	LdapRequestHandler<AddRequest> getAddRequestHandler();

	/**
	 * @return The MessageSent handler for the AddResponse
	 */
	LdapResponseHandler<AddResponse> getAddResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param addRequestHandler The AddRequest message received handler
	 * @param addResponseHandler The AddResponse message sent handler
	 */
	void setAddHandlers(LdapRequestHandler<AddRequest> addRequestHandler,
			LdapResponseHandler<AddResponse> addResponseHandler);

	/**
	 * @return The MessageReceived handler for the BindRequest
	 */
	LdapRequestHandler<BindRequest> getBindRequestHandler();

	/**
	 * @return The MessageSent handler for the BindResponse
	 */
	LdapResponseHandler<BindResponse> getBindResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param bindRequestHandler The BindRequest message received handler
	 * @param bindResponseHandler The BindResponse message sent handler
	 */
	void setBindHandlers(LdapRequestHandler<BindRequest> bindRequestHandler,
			LdapResponseHandler<BindResponse> bindResponseHandler);

	/**
	 * @return The MessageReceived handler for the CompareRequest
	 */
	LdapRequestHandler<CompareRequest> getCompareRequestHandler();

	/**
	 * @return The MessageSent handler for the CompareResponse
	 */
	LdapResponseHandler<CompareResponse> getCompareResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param compareRequestHandler The CompareRequest message received handler
	 * @param compareResponseHandler The CompareResponse message sent handler
	 */
	void setCompareHandlers(LdapRequestHandler<CompareRequest> compareRequestHandler,
			LdapResponseHandler<CompareResponse> compareResponseHandler);

	/**
	 * @return The MessageReceived handler for the DeleteRequest
	 */
	LdapRequestHandler<DeleteRequest> getDeleteRequestHandler();

	/**
	 * @return The MessageSent handler for the DeleteResponse
	 */
	LdapResponseHandler<DeleteResponse> getDeleteResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param deleteRequestHandler The DeleteRequest message received handler
	 * @param deleteResponseHandler The DeleteResponse message sent handler
	 */
	void setDeleteHandlers(LdapRequestHandler<DeleteRequest> deleteRequestHandler,
			LdapResponseHandler<DeleteResponse> deleteResponseHandler);

	/**
	 * @return The MessageReceived handler for the ExtendedRequest
	 */
	LdapRequestHandler<ExtendedRequest> getExtendedRequestHandler();

	/**
	 * @return The MessageSent handler for the ExtendedResponse
	 */
	LdapResponseHandler<ExtendedResponse> getExtendedResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param extendedRequestHandler The ExtendedRequest message received handler
	 * @param extendedResponseHandler The ExtendedResponse message sent handler
	 */
	void setExtendedHandlers(ExtendedRequestHandler extendedRequestHandler,
			ExtendedResponseHandler extendedResponseHandler);

	/**
	 * @return The MessageSent handler for the IntermediateResponse
	 */
	LdapResponseHandler<IntermediateResponse> getIntermediateResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param intermediateResponseHandler The IntermediateResponse message sent handler
	 */
	void setIntermediateHandler(LdapResponseHandler<IntermediateResponse> intermediateResponseHandler);

	/**
	 * @return The MessageReceived handler for the ModifyRequest
	 */
	LdapRequestHandler<ModifyRequest> getModifyRequestHandler();

	/**
	 * @return The MessageSent handler for the ModifyResponse
	 */
	LdapResponseHandler<ModifyResponse> getModifyResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param modifyRequestHandler The ModifyRequest message received handler
	 * @param modifyResponseHandler The ModifyResponse message sent handler
	 */
	void setModifyHandlers(LdapRequestHandler<ModifyRequest> modifyRequestHandler,
			LdapResponseHandler<ModifyResponse> modifyResponseHandler);

	/**
	 * @return The MessageSent handler for the ModifyDnRequest
	 */
	LdapRequestHandler<ModifyDnRequest> getModifyDnRequestHandler();

	/**
	 * @return The MessageSent handler for the ModifyDnResponse
	 */
	LdapResponseHandler<ModifyDnResponse> getModifyDnResponseHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param modifyDnRequestHandler The ModifyDnRequest message received handler
	 * @param modifyDnResponseHandler The ModifyDnResponse message sent handler
	 */
	void setModifyDnHandlers(LdapRequestHandler<ModifyDnRequest> modifyDnRequestHandler,
			LdapResponseHandler<ModifyDnResponse> modifyDnResponseHandler);

	/**
	 * @return The MessageReceived handler for the SearchRequest
	 */
	LdapRequestHandler<SearchRequest> getSearchRequestHandler();

	/**
	 * @return The MessageSent handler for the SearchResultEntry
	 */
	LdapResponseHandler<SearchResultEntry> getSearchResultEntryHandler();

	/**
	 * @return The MessageSent handler for the SearchResultReference
	 */
	LdapResponseHandler<SearchResultReference> getSearchResultReferenceHandler();

	/**
	 * @return The MessageSent handler for the SearchResultDone
	 */
	LdapResponseHandler<SearchResultDone> getSearchResultDoneHandler();

	/**
	 * Inject the MessageReceived and MessageSent handler into the IoHandler
	 *
	 * @param searchRequestHandler The SearchRequest message received handler
	 * @param searchResultEntryHandler The SearchResultEntry message sent handler
	 * @param searchResultReferenceHandler The SearchResultReference message sent handler
	 * @param searchResultDoneHandler The SearchResultDone message sent handler
	 */
	void setSearchHandlers(LdapRequestHandler<SearchRequest> searchRequestHandler,
			LdapResponseHandler<SearchResultEntry> searchResultEntryHandler,
			LdapResponseHandler<SearchResultReference> searchResultReferenceHandler,
			LdapResponseHandler<SearchResultDone> searchResultDoneHandler);

	/**
	 * @return The MessageReceived handler for the UnbindRequest
	 */
	LdapRequestHandler<UnbindRequest> getUnbindRequestHandler();

	/**
	 * Inject the MessageReceived handler into the IoHandler
	 *
	 * @param unbindRequestHandler The UnbindRequest message received handler
	 */
	void setUnbindHandler(LdapRequestHandler<UnbindRequest> unbindRequestHandler);

	/**
	 * @return The underlying TCP transport port, or -1 if no transport has been
	 * initialized
	 */
	int getPort();

	/**
	 * @return The underlying SSL enabled TCP transport port, or -1 if no transport has been
	 * initialized
	 */
	int getPortSSL();

	boolean isStarted();

	/**
	 */
	void setStarted(boolean started);

	/**
	 * @return The keystore path
	 */
	String getKeystoreFile();

	/**
	 * Set the external keystore path
	 * @param keystoreFile The external keystore path
	 */
	void setKeystoreFile(String keystoreFile);

	/**
	 * @return The certificate password
	 */
	String getCertificatePassword();

	/**
	 * Set the certificate password.
	 * @param certificatePassword the certificate password
	 */
	void setCertificatePassword(String certificatePassword);

	void setReplicationReqHandler(ReplicationRequestHandler replicationProvider);

	ReplicationRequestHandler getReplicationReqHandler();

	void setReplConsumers(List<ReplicationConsumer> replConsumers);

	/**
	 * @return the key manager factory of the server keystore
	 */
	KeyManagerFactory getKeyManagerFactory();

	/**
	 * @return the trust managers of the server
	 */
	TrustManager[] getTrustManagers();

	void setTrustManagers(TrustManager[] trustManagers);

	/**
	 * @return The maximum allowed size for an incoming PDU
	 */
	int getMaxPDUSize();

	/**
	 * Set the maximum allowed size for an incoming PDU
	 * @param maxPDUSize A positive number of bytes for the PDU. A negative or
	 * null value will be transformed to {@link Integer#MAX_VALUE}
	 */
	void setMaxPDUSize(int maxPDUSize);

	/**
	 * @return the number of seconds pinger thread sleeps between subsequent pings
	 */
	int getReplPingerSleepTime();

	/**
	 * The number of seconds pinger thread should sleep before pinging the providers
	 *
	 * @param pingerSleepTime The delay between 2 pings
	 */
	void setReplPingerSleepTime(int pingerSleepTime);

	/**
	 * Gives the list of enabled cipher suites
	 * <br>
	 * This method has been deprecated, please set this list in the TcpTransport class
	 * <br>
	 *
	 * @return The list of ciphers that can be used
	 * @deprecated Set this list in the {@link TcpTransport} class
	 */
	List<String> getEnabledCipherSuites();

	/**
	 * Sets the list of cipher suites to be used in LDAPS and StartTLS
	 * <br>
	 * This method has been deprecated, please set this list in the TcpTransport class
	 * <br>
	 *
	 * @param enabledCipherSuites if null the default cipher suites will be used
	 * @deprecated Get this list from the {@link TcpTransport} class
	 */
	void setEnabledCipherSuites(List<String> enabledCipherSuites);

	/**
	 * @see Object#toString()
	 */
	String toString();

	SSLContext getSSLContext() throws NoSuchAlgorithmException, KeyManagementException;

	void setTlsWantClientAuth(boolean b);

	void setTlsNeedClientAuth(boolean b);

	boolean isTlsWantClientAuth();

	boolean isTlsNeedClientAuth();

	void setTlsAllowedNames(ArrayList<String> allowedNames);

	void setTlsKeyAlias(String tlsKeyAlias);

	String getTlsKeyAlias();

    DirectoryService getDirectoryService();

	Transport[] getTransports();

}