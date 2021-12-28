package org.apache.directory.server.core.shared;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.UnbindRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.changelog.LogChange;
import org.apache.directory.server.core.api.interceptor.context.OperationContext;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.partition.PartitionTxn;
import org.apache.mina.core.session.IoSession;

public interface DefaultCoreSession {

	/**
	 * Gets the IoSession from the CoreSession. This is only useful when the server is not embedded.
	 * 
	 * @return ioSession The IoSession for this CoreSession
	 */
	IoSession getIoSession();

	/**
	 * Stores the IoSession into the CoreSession. This is only useful when the server is not embedded.
	 * 
	 * @param ioSession The IoSession for this CoreSession
	 */
	void setIoSession(IoSession ioSession);

	/**
	 * {@inheritDoc}
	 */
	void add(Entry entry) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void add(Entry entry, boolean ignoreReferral) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void add(Entry entry, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void add(Entry entry, boolean ignoreReferral, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void add(AddRequest addRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void add(AddRequest addRequest, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	boolean compare(Dn dn, String oid, Object value) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	boolean compare(Dn dn, String oid, Object value, boolean ignoreReferral) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void delete(Dn dn) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void delete(Dn dn, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void delete(Dn dn, boolean ignoreReferral) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void delete(Dn dn, boolean ignoreReferral, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	LdapPrincipal getAnonymousPrincipal();

	/**
	 * {@inheritDoc}
	 */
	LdapPrincipal getAuthenticatedPrincipal();

	/**
	 * {@inheritDoc}
	 */
	AuthenticationLevel getAuthenticationLevel();

	/**
	 * {@inheritDoc}
	 */
	SocketAddress getClientAddress();

	/**
	 * {@inheritDoc}
	 */
	Set<Control> getControls();

	/**
	 * {@inheritDoc}
	 */
	DirectoryService getDirectoryService();

	/**
	 * {@inheritDoc}
	 */
	LdapPrincipal getEffectivePrincipal();

	/**
	 * {@inheritDoc}
	 */
	Set<OperationContext> getOutstandingOperations();

	/**
	 * {@inheritDoc}
	 */
	SocketAddress getServiceAddress();

	/**
	 * {@inheritDoc}
	 */
	boolean isConfidential();

	/**
	 * {@inheritDoc}
	 */
	boolean isVirtual();

	/**
	 * TODO - perhaps we should just use a flag that is calculated on creation
	 * of this session
	 * 
	 * @see org.apache.directory.server.core.api.CoreSession#isAdministrator()
	 */
	boolean isAdministrator();

	/**
	 * TODO - this method impl does not check to see if the principal is in
	 * the administrators group - it only returns true of the principal is
	 * the actual admin user.  need to make it check groups.
	 * 
	 * TODO - perhaps we should just use a flag that is calculated on creation
	 * of this session
	 * 
	 * @see org.apache.directory.server.core.api.CoreSession#isAnAdministrator()
	 */
	boolean isAnAdministrator();

	/**
	 * {@inheritDoc}
	 */
	Cursor<Entry> list(Dn dn, AliasDerefMode aliasDerefMode, String... returningAttributes) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	Entry lookup(Dn dn, String... attrIds) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	Entry lookup(Dn dn, Control[] controls, String... attrIds) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(Dn dn, Modification... mods) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(Dn dn, List<Modification> mods) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(Dn dn, List<Modification> mods, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(Dn dn, List<Modification> mods, boolean ignoreReferral) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(Dn dn, List<Modification> mods, boolean ignoreReferral, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void move(Dn dn, Dn newParent) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void move(Dn dn, Dn newParent, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void move(Dn dn, Dn newParent, boolean ignoreReferral) throws Exception;

	/**
	 * {@inheritDoc}
	 */
	void move(Dn dn, Dn newParent, boolean ignoreReferral, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void moveAndRename(Dn dn, Dn newParent, Rdn newRdn, boolean deleteOldRdn) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void moveAndRename(Dn dn, Dn newSuperiorDn, Rdn newRdn, boolean deleteOldRdn, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void moveAndRename(Dn dn, Dn newParent, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral)
			throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void moveAndRename(Dn dn, Dn newParent, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral, LogChange log)
			throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void rename(Dn dn, Rdn newRdn, boolean deleteOldRdn) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void rename(Dn dn, Rdn newRdn, boolean deleteOldRdn, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void rename(Dn dn, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void rename(Dn dn, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	Cursor<Entry> search(Dn dn, String filter) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	Cursor<Entry> search(Dn dn, String filter, boolean ignoreReferrals) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	Cursor<Entry> search(Dn dn, SearchScope scope, ExprNode filter, AliasDerefMode aliasDerefMode,
			String... returningAttributes) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	boolean isAnonymous();

	/**
	 * {@inheritDoc}
	 */
	boolean compare(CompareRequest compareRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void delete(DeleteRequest deleteRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void delete(DeleteRequest deleteRequest, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	boolean exists(String dn) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	boolean exists(Dn dn) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(ModifyRequest modifyRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void modify(ModifyRequest modifyRequest, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void move(ModifyDnRequest modifyDnRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void move(ModifyDnRequest modifyDnRequest, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void moveAndRename(ModifyDnRequest modifyDnRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void moveAndRename(ModifyDnRequest modifyDnRequest, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void rename(ModifyDnRequest modifyDnRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void rename(ModifyDnRequest modifyDnRequest, LogChange log) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	Cursor<Entry> search(SearchRequest searchRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void unbind() throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	void unbind(UnbindRequest unbindRequest) throws LdapException;

	/**
	 * {@inheritDoc}
	 */
	boolean isPwdMustChange();

	/**
	 * {@inheritDoc}
	 */
	void setPwdMustChange(boolean pwdMustChange);

	/**
	 * {@inheritDoc}
	 */
	boolean hasSessionTransaction();

	/**
	 * {@inheritDoc}
	 */
	long beginSessionTransaction();

	/**
	 * {@inheritDoc}
	 */
	void endSessionTransaction(boolean commit) throws IOException;

	/**
	 * {@inheritDoc}
	 */
	PartitionTxn getTransaction(Partition partition);

	/**
	 * {@inheritDoc}
	 */
	void addTransaction(Partition partition, PartitionTxn transaction);

	HashMap<Object, Object> getUserSession();

}