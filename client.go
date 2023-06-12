package huaweicloud

import (
    "encoding/json"
    "errors"
    "fmt"
    "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
    iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
    . "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
    "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/region"
    "time"
)


func NewIamClient(access_key, secret_key string) (*iam.IamClient, error) {
    auth := global.NewCredentialsBuilder().
        WithAk(access_key).
        WithSk(secret_key).
        Build()
    iamclient := iam.NewIamClient(
        iam.IamClientBuilder().
            WithRegion(region.ValueOf("cn-north-4")).
            WithCredential(auth).
            Build())
    return iamclient, nil
}

func CreateTemporaryAccessByToken(iamClient *iam.IamClient,policyDocuments []*policyDoc,accessDuration time.Duration)(*CreateTemporaryAccessKeyByTokenResponse,error){
    tokenDurationSeconds := int32(accessDuration.Seconds())
    request := &CreateTemporaryAccessKeyByTokenRequest{
        Body: &CreateTemporaryAccessKeyByTokenRequestBody{
            Auth: &TokenAuth{
                Identity: &TokenAuthIdentity{
                    Methods: []TokenAuthIdentityMethods{
                        GetTokenAuthIdentityMethodsEnum().TOKEN,
                    },
                    Token: &IdentityToken{
                        DurationSeconds: &tokenDurationSeconds,
                    },
                },
            },
        },
    }
    if len(policyDocuments) > 0 {
        policies, err := parsePolicyDocuments(policyDocuments)
        if err != nil {
            return nil,err
        }
        request.Body.Auth.Identity.Policy = &ServicePolicy{
            Version:   "1.1",
            Statement: policies,
        }
    }
    temporaryResponse, err := iamClient.CreateTemporaryAccessKeyByToken(request)
    if err != nil {
        return nil, err
    }
    if temporaryResponse == nil || temporaryResponse.Credential == nil {
        return nil, errors.New("create temporary credential failed ")
    }
    return temporaryResponse,nil
}

func CreateTemporaryAccessByAgency(iamClient *iam.IamClient,domainId,agencyName string,policyDocuments []*policyDoc,accessDuration time.Duration)(*CreateTemporaryAccessKeyByAgencyResponse,error)  {
    tokenDurationSeconds := int32(accessDuration.Seconds())
    request := &CreateTemporaryAccessKeyByAgencyRequest{
        Body: &CreateTemporaryAccessKeyByAgencyRequestBody{
            Auth: &AgencyAuth{
                Identity: &AgencyAuthIdentity{
                    Methods: []AgencyAuthIdentityMethods{
                        GetAgencyAuthIdentityMethodsEnum().ASSUME_ROLE,
                    },
                    AssumeRole: &IdentityAssumerole{
                        AgencyName:      agencyName,
                        DomainId:        &domainId,
                        DurationSeconds: &tokenDurationSeconds,
                    },
                },
            },
        },
    }
    if len(policyDocuments) > 0 {
        statements, e := parsePolicyDocuments(policyDocuments)
        if e != nil {
            return nil,e
        }
        request.Body.Auth.Identity.Policy = &ServicePolicy{
            Version:   "1.1",
            Statement: statements,
        }
    }
    temporaryResponse, err := iamClient.CreateTemporaryAccessKeyByAgency(request)
    if err != nil {
        return nil, err
    }
    if temporaryResponse == nil || temporaryResponse.Credential == nil {
        return nil, errors.New("create credential failed ")
    }
    return temporaryResponse,nil
}

func CreatePermanentAccess(iamClient *iam.IamClient,userId string)(*CreatePermanentAccessKeyResponse,error)  {
    permanentDescription := "create by vault"
    permanentRequest := &CreatePermanentAccessKeyRequest{
        Body: &CreatePermanentAccessKeyRequestBody{
            Credential: &CreateCredentialOption{
                UserId:      userId,
                Description: &permanentDescription,
            },
        },
    }
    permanentResponse, err := iamClient.CreatePermanentAccessKey(permanentRequest)
    if err != nil {
        return nil, err
    }
    if permanentResponse == nil || permanentResponse.Credential == nil {
        return nil, errors.New("create credential failed ")
    }
    return permanentResponse,nil
}

func CreateUser(iamClient *iam.IamClient, userName, domainId string) (*CreateUserResponse, error) {
    description := "create by vault"
    createUserRequest := &CreateUserRequest{
        Body: &CreateUserRequestBody{
            User: &CreateUserOption{
                Name:        userName,
                DomainId:    domainId,
                Description: &description,
            },
        },
    }
    createUserResponse, err := iamClient.CreateUser(createUserRequest)
    if err != nil {
        return nil, err
    }
    if createUserResponse != nil && createUserResponse.HttpStatusCode != 201 {
        return nil, errors.New(fmt.Sprintf("unable to create user, userName: %s, httpcode:%d", createUserRequest.Body.User.Name, createUserResponse.HttpStatusCode))
    }
    return createUserResponse, nil
}

func DeleteUser(iamClient *iam.IamClient, userId string) (*KeystoneDeleteUserResponse, error) {
    deleteUserRequest := &KeystoneDeleteUserRequest{
        UserId: userId,
    }
    deleteUserResponse, err := iamClient.KeystoneDeleteUser(deleteUserRequest)
    if err != nil {
        return nil, err
    }
    if deleteUserResponse != nil && deleteUserResponse.HttpStatusCode != 204 {
        return nil, errors.New(fmt.Sprintf("unable to delete user, userId: %s, httpcode:%d", deleteUserRequest.UserId, deleteUserResponse.HttpStatusCode))
    }
    return deleteUserResponse, nil
}

func CreateUserGroup(iamClient *iam.IamClient, groupName string) (*KeystoneCreateGroupResponse, error) {
    description := "create by vault"
    createGroupRequest := &KeystoneCreateGroupRequest{
        Body: &KeystoneCreateGroupRequestBody{
            Group: &KeystoneCreateGroupOption{
                Name:        groupName,
                Description: &description,
            },
        },
    }
    // create user group
    createGroupResponse, err := iamClient.KeystoneCreateGroup(createGroupRequest)
    if err != nil {
        return nil, err
    }
    if createGroupResponse != nil && createGroupResponse.HttpStatusCode != 201 {
        return nil, errors.New(fmt.Sprintf("unable to create user group, groupName: %s, httpcode:%d", createGroupRequest.Body.Group.Name, createGroupResponse.HttpStatusCode))
    }
    return createGroupResponse, nil
}

func DeleteUserGroup(iamClient *iam.IamClient, userGroupId string) (*KeystoneDeleteGroupResponse, error) {
    deleteGroupRequest := &KeystoneDeleteGroupRequest{
        GroupId: userGroupId,
    }
    deleteGroupResponse, e := iamClient.KeystoneDeleteGroup(deleteGroupRequest)
    if e != nil {
        return nil, e
    }
    if deleteGroupResponse != nil && deleteGroupResponse.HttpStatusCode != 204 {
        return nil, errors.New(fmt.Sprintf("unable to delete user group, groupId: %s, httpcode:%d", userGroupId, deleteGroupResponse.HttpStatusCode))
    }
    return deleteGroupResponse, e
}

func AddUserToGroup(iamClient *iam.IamClient,userId,groupId string)(*KeystoneAddUserToGroupResponse,error)  {
    addUserToGroupRequest := &KeystoneAddUserToGroupRequest{
        GroupId: groupId,
        UserId:  userId,
    }
    addUserToGroupResponse, err := iamClient.KeystoneAddUserToGroup(addUserToGroupRequest)
    if err != nil {
        return nil, err
    }
    if addUserToGroupResponse == nil || addUserToGroupResponse.HttpStatusCode != 204 {
        err := errors.New(fmt.Sprintf("unable to add user to group, userId:%s, groupId:%s", userId, groupId))
        return nil, err
    }
    return addUserToGroupResponse,nil
}

func CreatePolicy(iamClient *iam.IamClient,policyName string,policyDocuments []*policyDoc) (*CreateCloudServiceCustomPolicyResponse,error) {
    // create policy
    policies, err := parsePolicyDocuments(policyDocuments)
    createPolicyRequest := &CreateCloudServiceCustomPolicyRequest{
        Body: &CreateCloudServiceCustomPolicyRequestBody{
            Role: &ServicePolicyRoleOption{
                DisplayName: policyName,
                Type:        "XA",
                Description: "create policy by vault",
                Policy: &ServicePolicy{
                    Version: "1.1",
                    Statement: policies,
                },
            },
        },
    }
    createPolicyResponse, err := iamClient.CreateCloudServiceCustomPolicy(createPolicyRequest)
    if err != nil {
        return nil, err
    }
    if createPolicyResponse != nil && createPolicyResponse.HttpStatusCode != 201 {
        return nil,errors.New(fmt.Sprintf("unable to create custom policy, roleName: %s, httpcode:%d", createPolicyRequest.Body.Role.DisplayName, createPolicyResponse.HttpStatusCode))
    }
    return createPolicyResponse, nil
}

func DeletePolicy(iamClient *iam.IamClient,policyId string) (*DeleteCustomPolicyResponse,error) {
    deletePolicyRequest := &DeleteCustomPolicyRequest{
        RoleId: policyId,
    }
    deletePolicyResponse, err := iamClient.DeleteCustomPolicy(deletePolicyRequest)
    if err != nil {
        return nil, err
    }
    if deletePolicyResponse != nil && deletePolicyResponse.HttpStatusCode != 200 {
        return nil, errors.New(fmt.Sprintf("unable to delete custom policy, roleId: %s, httpcode:%d", deletePolicyRequest.RoleId, deletePolicyResponse.HttpStatusCode))
    }
    return deletePolicyResponse,nil
}

func ListPolicy(iamClient *iam.IamClient,policyName string)(*KeystoneListPermissionsResponse,error)  {
    permissionsResponse, err := iamClient.KeystoneListPermissions(&KeystoneListPermissionsRequest{
        DisplayName: &policyName,
    })
    if err != nil {
        return nil, err
    }
    if permissionsResponse != nil && permissionsResponse.HttpStatusCode != 200 {
        return nil, fmt.Errorf("unable to find policy: %s,httpcode: %d", policyName, permissionsResponse.HttpStatusCode)
    }
    return permissionsResponse,nil
}

func BindPolicyToUserGroup(iamClient *iam.IamClient,domain,groupId,policyId string)(*UpdateDomainGroupInheritRoleResponse,error){
    bindPolicyRequest := &UpdateDomainGroupInheritRoleRequest{
        DomainId: domain,
        GroupId:  groupId,
        RoleId:   policyId,
    }
    bindPolicyResponse, err := iamClient.UpdateDomainGroupInheritRole(bindPolicyRequest)
    if err != nil {
        return nil, err
    }
    if bindPolicyResponse != nil && bindPolicyResponse.HttpStatusCode != 204 {
        return nil,errors.New(fmt.Sprintf("unable to bind policy, policyId:%s, userGroupId:%s", policyId,groupId))
    }
    return bindPolicyResponse,nil
}

func RemovePolicyFromUserGroup(iamClient *iam.IamClient,domainId,userGroupId,policyId string)(*DeleteDomainGroupInheritedRoleResponse,error)  {
    unBindPolicyRequest := &DeleteDomainGroupInheritedRoleRequest{
        DomainId: domainId,
        GroupId:  userGroupId,
        RoleId:   policyId,
    }
    unBindPolicyResponse, e := iamClient.DeleteDomainGroupInheritedRole(unBindPolicyRequest)
    if e != nil {
        return nil,e
    }
    if unBindPolicyResponse != nil && unBindPolicyResponse.HttpStatusCode != 204 {
        return nil,errors.New(fmt.Sprintf("unable to delete bind policy, roleId: %s, groupId：%s, domainId: %s, httpcode: %d", unBindPolicyRequest.RoleId, unBindPolicyRequest.GroupId, unBindPolicyRequest.DomainId, unBindPolicyResponse.HttpStatusCode))
    }
    return unBindPolicyResponse,e
}

func parsePolicyDocuments(policyDocuments []*policyDoc) ([]ServiceStatement, error) {
    serviceStatements := make([]ServiceStatement, len(policyDocuments))
    for index, policyDocument := range policyDocuments {
        if statements := policyDocument.PolicyDocument["Statement"]; statements != nil {
            var statements_inputs []ServiceStatement
            statements_bytes, err := json.Marshal(statements)
            if err != nil {
                return nil, err
            }
            err = json.Unmarshal(statements_bytes, &statements_inputs)
            if err != nil {
                return nil, err
            }
            serviceStatements[index] = statements_inputs[0]
        }
    }
    return serviceStatements, nil
}