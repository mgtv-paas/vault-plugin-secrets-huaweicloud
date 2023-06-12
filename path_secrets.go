package huaweicloud

import (
    "context"
    "errors"
    "fmt"
    "github.com/hashicorp/go-multierror"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathSecrets() *framework.Secret {
    return &framework.Secret{
        Type: SecretType,
        Fields: map[string]*framework.FieldSchema{
            "access_key": {
                Type:        framework.TypeString,
                Description: "Access Key",
            },
            "secret_key": {
                Type:        framework.TypeString,
                Description: "Secret Key",
            },
            "domain_id": {
                Type:        framework.TypeString,
                Description: "Domain Id",
            },
        },
        Renew:  b.operationRenew,
        Revoke: b.operationRevoke,
    }
}

func (b *backend) operationRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    roleTypeRaw, ok := req.Secret.InternalData["credential_type"]
    if !ok {
        return nil, errors.New("credential_type missing from secret")
    }

    switch roleTypeRaw {

    case IAM_USER:
        roleName, err := getStringValue(req.Secret.InternalData, "role_name")
        if err != nil {
            return nil, err
        }

        role, err := readRole(ctx, req.Storage, roleName)
        if err != nil {
            return nil, err
        }
        if role == nil {
            // The role has been deleted since the secret was issued or last renewed.
            // The user's expectation is probably that the caller won'nameOfRoleType continue being
            // able to perform renewals.
            return nil, fmt.Errorf("role %s has been deleted so no further renewals are allowed", roleName)
        }

        resp := &logical.Response{Secret: req.Secret}
        if role.TTL != 0 {
            resp.Secret.TTL = role.TTL
        }
        if role.MaxTTL != 0 {
            resp.Secret.MaxTTL = role.MaxTTL
        }
        return resp, nil
    case ASSUME_ROLE:
        return nil, nil
    case TOKEN:
        return nil, nil
    default:
        return nil, fmt.Errorf("unrecognized role_type: %s", roleTypeRaw)
    }
}

func (b *backend) operationRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
    roleTypeRaw, ok := req.Secret.InternalData["credential_type"]
    if !ok {
        return nil, errors.New("credential_type missing from secret")
    }

    switch roleTypeRaw {
    case IAM_USER:
        creds, err := readCredentials(ctx, req.Storage)
        if err != nil {
            return nil, err
        }
        if creds == nil {
            return nil, errors.New("unable to delete access key because no credentials are configured")
        }
        groupId, err := getStringValue(req.Secret.InternalData, "group_id")
        if err != nil {
            return nil, err
        }
        userId, err := getStringValue(req.Secret.InternalData, "user_id")
        if err != nil {
            return nil, err
        }
        policyId, err := getStringValue(req.Secret.InternalData, "policy_id")
        if err != nil {
            return nil, err
        }
        iamClient, err := NewIamClient(creds.AccessKey, creds.SecretKey)
        if err != nil {
            return nil, err
        }
        apiErrs := &multierror.Error{}
        // remove policy from user group
        _, err = RemovePolicyFromUserGroup(iamClient, creds.DomainId, groupId, policyId)
        if err != nil {
            apiErrs = multierror.Append(apiErrs,err)
        }
        // delete user group
        _, err = DeleteUserGroup(iamClient, groupId)
        if err != nil {
            apiErrs = multierror.Append(apiErrs,err)
        }
        // delete user
        _, err = DeleteUser(iamClient, userId)
        if err != nil {
            apiErrs = multierror.Append(apiErrs,err)
        }
        // delete policy
        _, err = DeletePolicy(iamClient, policyId)
        if err != nil {
            apiErrs = multierror.Append(apiErrs,err)
        }
        return nil, apiErrs.ErrorOrNil()
    case ASSUME_ROLE:
        return nil, nil
    case TOKEN:
        return nil, nil
    default:
        return nil, fmt.Errorf("unrecognized role_type: %s", roleTypeRaw)
    }
}

func getStringValue(internalData map[string]interface{}, key string) (string, error) {
    valueRaw, ok := internalData[key]
    if !ok {
        return "", fmt.Errorf("secret is missing %s internal data", key)
    }
    value, ok := valueRaw.(string)
    if !ok {
        return "", fmt.Errorf("secret is missing %s internal data", key)
    }
    return value, nil
}
