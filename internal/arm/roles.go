package arm

// The built-in role definitions the family needs, with their real
// role-definition GUIDs and documented data actions. Real code identifies
// roles by these GUIDs (`az role assignment create --role <guid>`) or by
// display name, so both resolve here.
//
// Grounding: Microsoft's published Azure built-in role definitions
// (learn.microsoft.com/azure/role-based-access-control/built-in-roles).

import "strings"

// Permission is one ARM permission block.
type Permission struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

// RoleDefinition is the Microsoft.Authorization/roleDefinitions resource.
type RoleDefinition struct {
	GUID        string
	RoleName    string
	Description string
	Permissions []Permission
}

const (
	kvSecretsPrefix = "Microsoft.KeyVault/vaults/secrets/"
	kvKeysPrefix    = "Microsoft.KeyVault/vaults/keys/"
	kvCertsPrefix   = "Microsoft.KeyVault/vaults/certificates/"
)

// builtInRoles is keyed by GUID. The Key Vault data-plane roles carry their
// documented dataActions; the management roles carry the actions the family
// needs (control-plane writes), not an exhaustive transcription.
var builtInRoles = []RoleDefinition{
	{
		GUID: "00482a5a-887f-4fb3-b363-3b7fe8e74483", RoleName: "Key Vault Administrator",
		Description: "Perform all data plane operations on a key vault and all objects in it.",
		Permissions: []Permission{{
			Actions:     []string{},
			DataActions: []string{"Microsoft.KeyVault/vaults/*"},
		}},
	},
	{
		GUID: "21090545-7ca7-4776-b22c-e363652d74d2", RoleName: "Key Vault Reader",
		Description: "Read metadata of key vaults and its certificates, keys, and secrets. Cannot read sensitive values.",
		Permissions: []Permission{{
			Actions: []string{"Microsoft.KeyVault/vaults/*/read"},
			DataActions: []string{
				kvKeysPrefix + "read", kvSecretsPrefix + "readMetadata/action",
				kvCertsPrefix + "read",
			},
		}},
	},
	{
		GUID: "4633458b-17de-408a-b874-0445c86b69e6", RoleName: "Key Vault Secrets User",
		Description: "Read secret contents.",
		Permissions: []Permission{{
			DataActions: []string{kvSecretsPrefix + "getSecret/action", kvSecretsPrefix + "readMetadata/action"},
		}},
	},
	{
		GUID: "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", RoleName: "Key Vault Secrets Officer",
		Description: "Perform any action on the secrets of a key vault, except manage permissions.",
		Permissions: []Permission{{DataActions: []string{kvSecretsPrefix + "*"}}},
	},
	{
		GUID: "12338af0-0e69-4776-bea7-57ae8d297424", RoleName: "Key Vault Crypto User",
		Description: "Perform cryptographic operations using keys.",
		Permissions: []Permission{{DataActions: []string{
			kvKeysPrefix + "read", kvKeysPrefix + "update/action", kvKeysPrefix + "backup/action",
			kvKeysPrefix + "encrypt/action", kvKeysPrefix + "decrypt/action",
			kvKeysPrefix + "wrap/action", kvKeysPrefix + "unwrap/action",
			kvKeysPrefix + "sign/action", kvKeysPrefix + "verify/action",
		}}},
	},
	{
		GUID: "14b46e9e-c2b7-41b4-b07b-48a6ebf60603", RoleName: "Key Vault Crypto Officer",
		Description: "Perform any action on the keys of a key vault, except manage permissions.",
		Permissions: []Permission{{DataActions: []string{kvKeysPrefix + "*"}}},
	},
	{
		GUID: "e147488a-f6f5-4113-8e2d-b22465e65bf6", RoleName: "Key Vault Crypto Service Encryption User",
		Description: "Read metadata of keys and perform wrap/unwrap operations.",
		Permissions: []Permission{{DataActions: []string{
			kvKeysPrefix + "read", kvKeysPrefix + "wrap/action", kvKeysPrefix + "unwrap/action",
		}}},
	},
	{
		GUID: "db79e9a7-68ee-4b58-9aeb-b90e7c24fcba", RoleName: "Key Vault Certificate User",
		Description: "Read certificate contents.",
		Permissions: []Permission{{DataActions: []string{
			kvCertsPrefix + "read", kvSecretsPrefix + "getSecret/action",
		}}},
	},
	{
		GUID: "a4417e6f-fecd-4de8-b567-7b0420556985", RoleName: "Key Vault Certificates Officer",
		Description: "Perform any action on the certificates of a key vault, except manage permissions.",
		Permissions: []Permission{{DataActions: []string{kvCertsPrefix + "*"}}},
	},
	{
		GUID: "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", RoleName: "Owner",
		Description: "Grants full access to manage all resources, including the ability to assign roles.",
		Permissions: []Permission{{Actions: []string{"*"}, DataActions: []string{"Microsoft.KeyVault/vaults/*"}}},
	},
	{
		GUID: "b24988ac-6180-42a0-ab88-20f7382dd24c", RoleName: "Contributor",
		Description: "Grants full access to manage all resources, but does not allow you to assign roles.",
		Permissions: []Permission{{
			Actions:    []string{"*"},
			NotActions: []string{"Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write"},
		}},
	},
	{
		GUID: "acdd72a7-3385-48ef-bd42-f606fba81ae7", RoleName: "Reader",
		Description: "View all resources, but does not allow you to make any changes.",
		Permissions: []Permission{{Actions: []string{"*/read"}}},
	},
}

// RoleByGUID returns the built-in role with that definition GUID.
func RoleByGUID(guid string) (RoleDefinition, bool) {
	for _, r := range builtInRoles {
		if strings.EqualFold(r.GUID, guid) {
			return r, true
		}
	}
	return RoleDefinition{}, false
}

// RoleByName returns the built-in role with that display name.
func RoleByName(name string) (RoleDefinition, bool) {
	for _, r := range builtInRoles {
		if strings.EqualFold(r.RoleName, name) {
			return r, true
		}
	}
	return RoleDefinition{}, false
}

// RoleFromDefinitionID resolves the trailing GUID of a roleDefinitionId
// ("/subscriptions/{s}/providers/Microsoft.Authorization/roleDefinitions/{guid}"
// or a bare GUID).
func RoleFromDefinitionID(id string) (RoleDefinition, bool) {
	trimmed := strings.TrimSuffix(id, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	return RoleByGUID(trimmed)
}

// BuiltInRoles returns every seeded definition.
func BuiltInRoles() []RoleDefinition { return builtInRoles }
