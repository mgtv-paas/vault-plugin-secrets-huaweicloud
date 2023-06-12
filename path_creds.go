package huaweicloud

import (
    "context"
    "errors"
    "fmt"
    "github.com/hashicorp/go-uuid"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
    "strings"
    "time"
)

func (b *backend) pathCreds() *framework.Path {
    return &framework.Path{
        Pattern: "creds/" + framework.GenericNameRegex("name"),
        Fields: map[string]*framework.FieldSchema{
            "name": {
                Type:        framework.TypeLowerCaseString,
                Description: "The name of the role.",
            },
        },
        Callbacks: map[logical.Operation]framework.OperationFunc{
            logical.ReadOperation: b.operationCredsRead,
        },
        HelpSynopsis:    pathCredsHelpSyn,
        HelpDescription: pathCredsHelpDesc,
    }
}

func (b *backend) operationCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    roleName := data.Get("name").(string)
    if roleName == "" {
        return nil, errors.New("name is required")
    }

    role, err := readRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, err
    }
    if role == nil {
        // Attempting to read a role that doesn't exist.
        return nil, nil
    }

    creds, err := readCredentials(ctx, req.Storage)
    if err != nil {
        return nil, err
    }
    if creds == nil {
        return nil, errors.New("unable to create secret because no credentials are configured")
    }

    iamClient, err := NewIamClient(creds.AccessKey, creds.SecretKey)
    if err != nil {
        return nil, err
    }
    if iamClient == nil {
        return nil, errors.New("unable to get iam client")
    }
    switch role.CredentialType {
    case IAM_USER:
        isSucess := false
        userName := generateName(roleName, 32)
        createUserResponse, err := CreateUser(iamClient, userName, creds.DomainId)
        if err != nil {
            return nil, err
        }
        defer func() {
            if isSucess {
                return
            }
            _, err := DeleteUser(iamClient, createUserResponse.User.Id)
            if err != nil {
                b.Logger().Error(err.Error())
            }
        }()
        groupName := generateName(roleName, 32)
        createUserGroupResponse, err := CreateUserGroup(iamClient, groupName)
        if err != nil {
            return nil, err
        }
        defer func() {
            if isSucess {
                return
            }
            _, err := DeleteUserGroup(iamClient, createUserGroupResponse.Group.Id)
            if err != nil {
                b.Logger().Error(err.Error())
            }
        }()
        custom_policy_id := ""
        // create policy
        if role.PolicyDocuments != nil && len(role.PolicyDocuments) > 0 {
            policyName := generateName(roleName, 32)
            createPolicyResponse, err := CreatePolicy(iamClient, policyName, role.PolicyDocuments)
            if err != nil {
                return nil, err
            }
            custom_policy_id = createPolicyResponse.Role.Id
            defer func() {
                if isSucess {
                    return
                }
                _, err := DeletePolicy(iamClient, createPolicyResponse.Role.Id)
                if err != nil {
                    b.Logger().Error(err.Error())
                }
            }()
            // bind custom policy(policyDocuments) to user group
            _, err = BindPolicyToUserGroup(iamClient, creds.DomainId, createUserGroupResponse.Group.Id, createPolicyResponse.Role.Id)
            if err != nil {
                return nil, err
            }
            defer func() {
                if isSucess {
                    return
                }
                _, err := RemovePolicyFromUserGroup(iamClient, creds.DomainId, createUserGroupResponse.Group.Id, createPolicyResponse.Role.Id)
                if err != nil {
                    b.Logger().Error(err.Error())
                }
            }()
        }
        // bind policies existing on the cloud console to user groups
        if role.Policies != nil && len(role.Policies) > 0 {
            for _, policy := range role.Policies {
                permissionsResponse, err := ListPolicy(iamClient, policy)
                if err != nil {
                    return nil, err
                }
                if len(*permissionsResponse.Roles) > 0 {
                    policyId := (*permissionsResponse.Roles)[0].Id
                    _, err := BindPolicyToUserGroup(iamClient, creds.DomainId, createUserGroupResponse.Group.Id, policyId)
                    if err != nil {
                        return nil, err
                    }
                    defer func() {
                        if isSucess {
                            return
                        }
                        _, err := RemovePolicyFromUserGroup(iamClient, creds.DomainId, createUserGroupResponse.Group.Id, policyId)
                        if err != nil {
                            b.Backend.Logger().Error(err.Error())
                        }
                    }()
                }
            }
        }
        // add user to user group
        _, err = AddUserToGroup(iamClient, createUserResponse.User.Id, createUserGroupResponse.Group.Id)
        if err != nil {
            return nil, err
        }
        permanentResponse, err := CreatePermanentAccess(iamClient, createUserResponse.User.Id)
        isSucess = true
        if err != nil {
            return nil, err
        }
        resp := b.Secret(SecretType).Response(map[string]interface{}{
            "access_key": permanentResponse.Credential.Access,
            "secret_key": permanentResponse.Credential.Secret,
        }, map[string]interface{}{
            "role_name":       roleName,
            "credential_type": role.CredentialType,
            "user_id":         createUserResponse.User.Id,
            "domain_id":       creds.DomainId,
            "policy_id":       custom_policy_id,
            "access_key":      permanentResponse.Credential.Access,
            "group_id":        createUserGroupResponse.Group.Id,
        })
        resp.Secret.TTL = role.TTL
        resp.Secret.MaxTTL = role.MaxTTL
        return resp, nil
    case ASSUME_ROLE:
        temporaryResponse, err := CreateTemporaryAccessByAgency(iamClient, creds.DomainId, role.AgencyName, role.PolicyDocuments, role.DurationSeconds)
        if err != nil {
            return nil, err
        }
        resp := b.Secret(SecretType).Response(map[string]interface{}{
            "access_key":     temporaryResponse.Credential.Access,
            "secret_key":     temporaryResponse.Credential.Secret,
            "security_token": temporaryResponse.Credential.Securitytoken,
            "expiration":     temporaryResponse.Credential.ExpiresAt,
        }, map[string]interface{}{
            "credential_type": role.CredentialType,
        })
        resp.Secret.TTL = role.TTL
        resp.Secret.MaxTTL = role.MaxTTL
        return resp, nil
    case TOKEN:
        temporaryResponse, err := CreateTemporaryAccessByToken(iamClient, role.PolicyDocuments, role.DurationSeconds)
        if err != nil {
            return nil, err
        }
        resp := b.Secret(SecretType).Response(map[string]interface{}{
            "access_key":     temporaryResponse.Credential.Access,
            "secret_key":     temporaryResponse.Credential.Secret,
            "security_token": temporaryResponse.Credential.Securitytoken,
            "expiration":     temporaryResponse.Credential.ExpiresAt,
        }, map[string]interface{}{
            "credential_type": role.CredentialType,
        })
        resp.Secret.TTL = role.TTL
        resp.Secret.MaxTTL = role.MaxTTL
        return resp, nil
    }
    return nil, nil
}

func generateName(name string, maxLength int) string {
    // The time and random number take up to 15 more in length, so if the name
    // is too long we need to trim it.
    if len(name) > 24 {
        name = name[:24]
    }
    uid, err := uuid.GenerateUUID()
    if err != nil {
        uid = fmt.Sprint(time.Now().Unix())
    }
    uid = strings.Replace(uid, "-", "", -1)
    if len(uid) > maxLength-len(name) {
        uid = uid[:maxLength-len(name)-1]
    }
    return fmt.Sprintf("%s-%s", name, uid)
}

const pathCredsHelpSyn = `
Generate a permanent or temporary credential using the given role's configuration.'
`
const pathCredsHelpDesc = `
This path will generate a permanent or temporary(create by assume role and token) credential for
accessing Huaweicloud. The policies used to back this key pair will be
configured on the role. For example, if this backend is mounted at "huaweicloud",
then "huaweicloud/creds/deploy" would generate access keys for the "deploy" role.

The permanent or temporary credential will have a ttl associated with it. the permanent credential can
be renewed or revoked as described here: 
https://www.vaultproject.io/docs/concepts/lease.html,
but temporary credentials do not support renewal or revocation.
`
