package huaweicloud

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/hashicorp/go-uuid"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)


func (b *backend) pathListRoles() *framework.Path {
    return &framework.Path{
        Pattern: "role/?$",
        Callbacks: map[logical.Operation]framework.OperationFunc{
            logical.ListOperation: b.operationRolesList,
        },
        HelpSynopsis:    pathListRolesHelpSyn,
        HelpDescription: pathListRolesHelpDesc,
    }
}

func (b *backend) pathRole() *framework.Path {
    return &framework.Path{
        Pattern: "role/" + framework.GenericNameRegex("name"),
        Fields: map[string]*framework.FieldSchema{
            "name": {
                Type:        framework.TypeLowerCaseString,
                Description: "The name of the role.",
            },
            "credential_type": {
                Type: framework.TypeString,
                Description: `CredentialType provides iam_user、assume_role and token authentication modes. 
policy not blank when credentialType is assume_role mode and userId not blank when credentialType 
is temporary mode`,
            },
            "policy_documents": {
                Type:        framework.TypeString,
                Description: "JSON of policies to be dynamically applied to users of this role.",
            },
            "policies": {
                Type: framework.TypeStringSlice,
                Description: `The name of each remote policy to be applied. 
Example: "OBS ReadOnlyAccess".`,
            },
            "agency_name": {
                Type:        framework.TypeString,
                Description: `The name of agency assume_role to be applied.`,
            },
            "duration_seconds": {
                Type: framework.TypeDurationSecond,
                Description: `Duration in seconds after which the huaweicloud securitytoken should expire.
range 900s to 86400s,Defaults to 900s.`,
            },
            "ttl": {
                Type: framework.TypeDurationSecond,
                Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
            },
            "max_ttl": {
                Type:        framework.TypeDurationSecond,
                Description: "The maximum allowed lifetime of tokens issued using this role.",
            },
        },
        ExistenceCheck: b.operationRoleExistenceCheck,
        Callbacks: map[logical.Operation]framework.OperationFunc{
            logical.CreateOperation: b.operationRoleCreateUpdate,
            logical.UpdateOperation: b.operationRoleCreateUpdate,
            logical.ReadOperation:   b.operationRoleRead,
            logical.DeleteOperation: b.operationRoleDelete,
        },
        HelpSynopsis:    pathRolesHelpSyn,
        HelpDescription: pathRolesHelpDesc,
    }
}

func (b *backend) operationRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
    entry, err := readRole(ctx, req.Storage, data.Get("name").(string))
    if err != nil {
        return false, err
    }
    return entry != nil, nil
}

func (b *backend) operationRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    roleName := data.Get("name").(string)
    if roleName == "" {
        return nil, errors.New("name is required")
    }
    role, err := readRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, err
    }
    if role == nil && req.Operation == logical.UpdateOperation {
        return nil, fmt.Errorf("no role found to update for %s", roleName)
    } else if role == nil {
        role = &RoleEntry{}
    }

    if raw, ok := data.GetOk("credential_type"); ok {
        credentialType := raw.(string)
        role.CredentialType = credentialType
    }

    if raw, ok := data.GetOk("user_id"); ok {
        role.UserId = raw.(string)
    }
    if raw, ok := data.GetOk("policy_documents"); ok {
        policyDocsStr := raw.(string)

        var policyDocs []map[string]interface{}
        if err := json.Unmarshal([]byte(policyDocsStr), &policyDocs); err != nil {
            return nil, err
        }

        // If any policy documents were set before, we need to clear them and consider
        // these the new ones.
        role.PolicyDocuments = make([]*policyDoc, len(policyDocs))

        for i, policyDocument := range policyDocs {
            uid, err := uuid.GenerateUUID()
            if err != nil {
                return nil, err
            }
            uid = strings.Replace(uid, "-", "", -1)
            policyName := fmt.Sprintf("vault-%s-%s", roleName, uid)
            role.PolicyDocuments[i] = &policyDoc{
                PolicyName:     policyName,
                PolicyDocument: policyDocument,
            }
        }
    }
    if raw, ok := data.GetOk("policies"); ok {
        strPolicies := raw.([]string)
        role.Policies = make([]string, len(strPolicies))
        for index, strPolicy := range strPolicies {
            role.Policies[index] = strPolicy
        }
    }
    if raw, ok := data.GetOk("agency_name"); ok {
        role.AgencyName = raw.(string)
    }
    if raw, ok := data.GetOk("duration_seconds"); ok {
        role.DurationSeconds = time.Duration(raw.(int)) * time.Second
    }
    if raw, ok := data.GetOk("ttl"); ok {
        role.TTL = time.Duration(raw.(int)) * time.Second
    }
    if raw, ok := data.GetOk("max_ttl"); ok {
        role.MaxTTL = time.Duration(raw.(int)) * time.Second
    }

    // Now that the role is built, validate it.
    if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
        return nil, errors.New("ttl exceeds max_ttl")
    }

    if role.CredentialType==IAM_USER  && len(role.Policies)+len(role.PolicyDocuments) == 0 {
        return nil, errors.New("must include policies or policyDocuments when CredentialType is iam_user")
    }

    if role.CredentialType==ASSUME_ROLE  && len(role.AgencyName)==0 {
        return nil, errors.New("must include agency name when CredentialType is assume_role")
    }

    entry, err := logical.StorageEntryJSON("role/"+roleName, role)
    if err != nil {
        return nil, err
    }
    if err := req.Storage.Put(ctx, entry); err != nil {
        return nil, err
    }

    // Let's create a response that we're only going to return if there are warnings.
    resp := &logical.Response{}
    if (role.CredentialType == "assume_role" || role.CredentialType == "token") &&
        (role.TTL > 0 || role.MaxTTL > 0) {
        resp.AddWarning("credential_type is assume_role or token, so ttl and max_ttl will be ignored because they're not editable")
    }
    if role.TTL > b.System().MaxLeaseTTL() {
        resp.AddWarning(fmt.Sprintf("ttl of %d exceeds the system max ttl of %d, the latter will be used during login", role.TTL, b.System().MaxLeaseTTL()))
    }
    if len(resp.Warnings) > 0 {
        return resp, nil
    }
    // No warnings, let's return a 204.
    return nil, nil
}

func (b *backend) operationRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    roleName := data.Get("name").(string)
    if roleName == "" {
        return nil, errors.New("name is required")
    }

    role, err := readRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, err
    }
    if role == nil {
        return nil, nil
    }
    return &logical.Response{
        Data: map[string]interface{}{
            "credential_type":  role.CredentialType,
            "user_id":          role.UserId,
            "policies":         role.Policies,
            "policy_documents": role.PolicyDocuments,
            "agency_name":      role.AgencyName,
            "duration_seconds": role.DurationSeconds / time.Second,
            "ttl":              role.TTL / time.Second,
            "max_ttl":          role.MaxTTL / time.Second,
        },
    }, nil
}

func (b *backend) operationRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    if err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string)); err != nil {
        return nil, err
    }
    return nil, nil
}

func (b *backend) operationRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
    entries, err := req.Storage.List(ctx, "role/")
    if err != nil {
        return nil, err
    }
    return logical.ListResponse(entries), nil
}

func readRole(ctx context.Context, s logical.Storage, roleName string) (*RoleEntry, error) {
    role, err := s.Get(ctx, "role/"+roleName)
    if err != nil {
        return nil, err
    }
    if role == nil {
        return nil, nil
    }
    result := &RoleEntry{}
    if err := role.DecodeJSON(result); err != nil {
        return nil, err
    }
    return result, nil
}

type RoleEntry struct {
    CredentialType  string        `json:"credential_type"`
    UserId          string        `json:"user_id"`
    Policies        []string      `json:"policies"`
    PolicyDocuments []*policyDoc  `json:"policy_documents"`
    AgencyName      string        `json:"agency_name"`
    DurationSeconds time.Duration `json:"duration_seconds"`
    TTL             time.Duration `json:"ttl"`
    MaxTTL          time.Duration `json:"max_ttl"`
}

const (
    IAM_USER    ="iam_user"
    ASSUME_ROLE ="assume_role"
    TOKEN       ="token"
    SecretType  = "huaweicloud"
)

type policyDoc struct {
    PolicyName     string                 `json:"policy_name"`
    PolicyDocument map[string]interface{} `json:"policy_document"`
}

const pathListRolesHelpSyn = "List the existing roles in this backend."

const pathListRolesHelpDesc = "Roles will be listed by the role name."

const pathRolesHelpSyn = `
Read, write and reference policies and roles that permanent or temporary(create by assume role and token) credentials can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create a permanent or temporary(create by assume role and token) credentials.

If you supply an agency name, that role must have been created to allow trusted actors,
and the access key and secret that will be used to call AssumeRole (configured at
the /config path) must qualify as a trusted actor.

If you instead supply policy_documents and/or policies to be applied, a user and API
key will be dynamically created. The policies will be applied to that user,
and the policy_documents will also be dynamically created and applied.

To obtain a permanent or temporary credential after the role is created, if the
backend is mounted at "huaweicloud" and you create a role at "huaweicloud/roles/deploy",
then a user could request access credentials at "huaweicloud/creds/deploy".

To validate the keys, attempt to read an access key after writing the policy.
`
