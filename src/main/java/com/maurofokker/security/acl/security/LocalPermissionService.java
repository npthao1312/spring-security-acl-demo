package com.maurofokker.security.acl.security;

import com.maurofokker.security.acl.model.IEntity;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;
import org.springframework.transaction.support.TransactionTemplate;

@Service
@Transactional
public class LocalPermissionService {

    @Autowired
    private MutableAclService aclService;

    private Logger LOGGER = LoggerFactory.getLogger(LocalPermissionService.class);

    @Autowired
    private PlatformTransactionManager transactionManager;

    public void addPermissionForUser(IEntity targetObj, Permission permission, String username) {
        final Sid sid = new PrincipalSid(username);
        addPermissionForSid(targetObj, permission, sid);
        LOGGER.error("Grant {} permission to principal {} on Object {}", 
        		permission, username, targetObj);
    }
    
    public void removeAllPermissionForUser(IEntity targetObj, String username) {
        final Sid sid = new PrincipalSid(username);
        deleteAllPermissionForSid(targetObj, sid);
        LOGGER.error("Remove all permissions to principal {} on Object {}", 
        		username, targetObj);
    }

    public void addPermissionForAuthority(IEntity targetObj, Permission permission, String authority) {
        final Sid sid = new GrantedAuthoritySid(authority);
        addPermissionForSid(targetObj, permission, sid);
        LOGGER.error("Grant {} permission to principal {} on Object {}", 
        		permission, authority, targetObj);
    }
    
    public void removeAllPermissionForAuthority(IEntity targetObj, String authority) {
        final Sid sid = new GrantedAuthoritySid(authority);        
        deleteAllPermissionForSid(targetObj, sid);
        LOGGER.error("Remove all permissions to principal {} on Object {}", 
        		authority, targetObj);
    }
    
    public void removeAcl(IEntity targetObj) {  
    	deleteAcl(targetObj);
        LOGGER.error("Remove ACL on Object {}", targetObj);
    }

    private void addPermissionForSid(IEntity targetObj, Permission permission, Sid sid) {
        final TransactionTemplate tt = new TransactionTemplate(transactionManager);

        tt.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                final ObjectIdentity oi = new ObjectIdentityImpl(targetObj.getClass(), targetObj.getId());

                MutableAcl acl = null;
                try {
                    acl = (MutableAcl) aclService.readAclById(oi);
                } catch (final NotFoundException nfe) {
                    acl = aclService.createAcl(oi);
                }

                acl.insertAce(acl.getEntries().size(), permission, sid, true);
                aclService.updateAcl(acl);
            }
        });
    }
    
    private void deleteAllPermissionForSid(IEntity targetObj, Sid sid) {
        final TransactionTemplate tt = new TransactionTemplate(transactionManager);

        tt.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                final ObjectIdentity oi = new ObjectIdentityImpl(targetObj.getClass(), targetObj.getId());
                try {
                    MutableAcl acl = (MutableAcl) aclService.readAclById(oi);
                    List<AccessControlEntry> aclEntries = acl.getEntries();
                    for (int i = aclEntries.size() - 1; i >= 0; i--) {
                        AccessControlEntry ace = aclEntries.get(i);
                        if (ace.getSid().equals(sid)) {
                            acl.deleteAce(i);
                        }
                    }
                    if (acl.getEntries().isEmpty()) {
                        aclService.deleteAcl(oi, true);
                    }
                    aclService.updateAcl(acl);
                } catch (NotFoundException ignore) {
                }
            }
        });
    }
    
    private void deleteAcl(IEntity targetObj) {
        final TransactionTemplate tt = new TransactionTemplate(transactionManager);

        tt.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                final ObjectIdentity oi = new ObjectIdentityImpl(targetObj.getClass(), targetObj.getId());
                try {
                    MutableAcl acl = (MutableAcl) aclService.readAclById(oi);
                    aclService.deleteAcl(oi, true);
                } catch (NotFoundException ignore) {
                }
            }
        });
    }
}
