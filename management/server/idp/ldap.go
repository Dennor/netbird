package idp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

// LdapManager LDAP manager client instance
type LdapManager struct {
	config     LdapClientConfig
	helper     ManagerHelper
	appMetrics telemetry.AppMetrics
	connector  ldapConnector
}

// LdapClientConfig LDAP manager client configurations
type LdapClientConfig struct {
	Host              string
	DN                string
	Passwd            string
	PasswdFile        string
	BaseDN            string
	UserSearchDN      string
	NetbirdMetadataDN string
	Filter            string
	NameAttr          string
	IDAttr            string
	EmailAttr         string
}

// ldapConnection interface for LDAP operations (allows mocking)
type ldapConnection interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(addRequest *ldap.AddRequest) error
	Modify(modifyRequest *ldap.ModifyRequest) error
	Del(delRequest *ldap.DelRequest) error
	Close() error
}

// ldapConnector interface for creating LDAP connections (allows mocking)
type ldapConnector interface {
	Connect(ctx context.Context, config LdapClientConfig) (ldapConnection, error)
}

// defaultLdapConnector implements ldapConnector using real LDAP library
type defaultLdapConnector struct{}

func (d *defaultLdapConnector) Connect(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
	conn, err := ldap.DialURL(config.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	if config.DN != "" {
		if err := conn.Bind(config.DN, config.Passwd); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind to LDAP server: %w", err)
		}
	}

	return conn, nil
}

// readPasswordFromFile reads password from a file and trims whitespace
func readPasswordFromFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// NewLdapManager creates a new instance of the LdapManager
func NewLdapManager(config LdapClientConfig, appMetrics telemetry.AppMetrics) (*LdapManager, error) {
	helper := JsonParser{}

	if config.Host == "" {
		return nil, fmt.Errorf("LDAP IdP configuration is incomplete, Host is missing")
	}

	// Read password from file if PasswdFile is set (takes priority over Passwd)
	if config.PasswdFile != "" {
		passwd, err := readPasswordFromFile(config.PasswdFile)
		if err != nil {
			return nil, fmt.Errorf("LDAP IdP configuration error: %w", err)
		}
		config.Passwd = passwd
	}

	// Validate DN requirements
	if config.BaseDN == "" && config.UserSearchDN == "" {
		return nil, fmt.Errorf("LDAP IdP configuration is incomplete, at least one of BaseDN or UserSearchDN is required")
	}

	if config.BaseDN == "" && config.NetbirdMetadataDN == "" {
		return nil, fmt.Errorf("LDAP IdP configuration is incomplete, at least one of BaseDN or NetbirdMetadataDN is required")
	}

	// Apply defaults
	if config.UserSearchDN == "" {
		config.UserSearchDN = fmt.Sprintf("ou=users,%s", config.BaseDN)
	}

	if config.NetbirdMetadataDN == "" {
		config.NetbirdMetadataDN = fmt.Sprintf("ou=netbirdMetadata,%s", config.BaseDN)
	}

	if config.Filter == "" {
		config.Filter = "(objectclass=person)"
	}

	if config.NameAttr == "" {
		config.NameAttr = "uid"
	}

	if config.IDAttr == "" {
		config.IDAttr = "uid"
	}

	if config.EmailAttr == "" {
		config.EmailAttr = "mail"
	}

	return &LdapManager{
		config:     config,
		helper:     helper,
		appMetrics: appMetrics,
		connector:  &defaultLdapConnector{},
	}, nil
}

// connect creates an LDAP connection
func (lm *LdapManager) connect(ctx context.Context) (ldapConnection, error) {
	return lm.connector.Connect(ctx, lm.config)
}

// getUserMetadataDN returns the DN for a user's metadata entry
func (lm *LdapManager) getUserMetadataDN(userID string) string {
	return fmt.Sprintf("uid=%s,%s", ldap.EscapeDN(userID), lm.config.NetbirdMetadataDN)
}

// getMetadataKeyDN returns the DN for a specific metadata key entry
func (lm *LdapManager) getMetadataKeyDN(userID, key string) string {
	return fmt.Sprintf("cn=%s,uid=%s,%s", ldap.EscapeDN(key), ldap.EscapeDN(userID), lm.config.NetbirdMetadataDN)
}

// metadataKeyMap defines the mapping between AppMetadata fields and their LDAP cn attribute names
type metadataKeyMap struct {
	WTAccountID      string
	WTPendingInvite  string
	WTInvitedByEmail string
}

var metadataKeys = metadataKeyMap{
	WTAccountID:      "wt_account_id",
	WTPendingInvite:  "wt_pending_invite",
	WTInvitedByEmail: "wt_invited_by_email",
}

// getMetadataEntries converts AppMetadata to a map of cn keys to values
func getMetadataEntries(metadata AppMetadata) map[string]string {
	entries := make(map[string]string)

	if metadata.WTAccountID != "" {
		entries[metadataKeys.WTAccountID] = metadata.WTAccountID
	}
	if metadata.WTPendingInvite != nil {
		if *metadata.WTPendingInvite {
			entries[metadataKeys.WTPendingInvite] = "true"
		} else {
			entries[metadataKeys.WTPendingInvite] = "false"
		}
	}
	if metadata.WTInvitedBy != "" {
		entries[metadataKeys.WTInvitedByEmail] = metadata.WTInvitedBy
	}

	return entries
}

// searchUsers performs an LDAP search for users
func (lm *LdapManager) searchUsers(ctx context.Context, conn ldapConnection, filter string) ([]*UserData, error) {
	searchRequest := ldap.NewSearchRequest(
		lm.config.UserSearchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{lm.config.IDAttr, lm.config.NameAttr, lm.config.EmailAttr},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP users: %w", err)
	}

	users := make([]*UserData, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		userData := &UserData{
			ID:          entry.GetAttributeValue(lm.config.IDAttr),
			Name:        entry.GetAttributeValue(lm.config.NameAttr),
			Email:       entry.GetAttributeValue(lm.config.EmailAttr),
			AppMetadata: AppMetadata{},
		}
		users = append(users, userData)
	}

	return users, nil
}

// getMetadata retrieves metadata for a user from LDAP by searching for all cn entries
func (lm *LdapManager) getMetadata(ctx context.Context, conn ldapConnection, userID string) (AppMetadata, error) {
	userMetadataDN := lm.getUserMetadataDN(userID)

	// Search for all metadata entries under the user's metadata DN
	searchRequest := ldap.NewSearchRequest(
		userMetadataDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "description"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		// If metadata entry doesn't exist, return empty metadata
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return AppMetadata{}, nil
		}
		return AppMetadata{}, fmt.Errorf("failed to get metadata: %w", err)
	}

	// Reconstruct AppMetadata from individual entries
	metadata := AppMetadata{}
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		value := entry.GetAttributeValue("description")

		switch cn {
		case metadataKeys.WTAccountID:
			metadata.WTAccountID = value
		case metadataKeys.WTPendingInvite:
			if value == "true" {
				boolVal := true
				metadata.WTPendingInvite = &boolVal
			} else if value == "false" {
				boolVal := false
				metadata.WTPendingInvite = &boolVal
			}
		case metadataKeys.WTInvitedByEmail:
			metadata.WTInvitedBy = value
		}
	}

	return metadata, nil
}

// UpdateUserAppMetadata updates user app metadata in LDAP
// Creates or updates separate LDAP entries for each metadata key
func (lm *LdapManager) UpdateUserAppMetadata(ctx context.Context, userID string, appMetadata AppMetadata) error {
	conn, err := lm.connect(ctx)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	defer conn.Close()

	// Ensure the user's metadata container exists
	userMetadataDN := lm.getUserMetadataDN(userID)
	if err := lm.ensureMetadataContainer(conn, userMetadataDN, userID); err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return fmt.Errorf("failed to ensure metadata container: %w", err)
	}

	// Get metadata entries to create/update
	entries := getMetadataEntries(appMetadata)

	// Create or update each metadata key as a separate entry
	for key, value := range entries {
		keyDN := lm.getMetadataKeyDN(userID, key)

		// Try to modify existing entry first
		modifyRequest := ldap.NewModifyRequest(keyDN, nil)
		modifyRequest.Replace("description", []string{value})

		err := conn.Modify(modifyRequest)
		if err != nil {
			// If entry doesn't exist, create it
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				addRequest := ldap.NewAddRequest(keyDN, nil)
				addRequest.Attribute("objectClass", []string{"top", "applicationProcess"})
				addRequest.Attribute("cn", []string{key})
				addRequest.Attribute("description", []string{value})

				if err := conn.Add(addRequest); err != nil {
					if lm.appMetrics != nil {
						lm.appMetrics.IDPMetrics().CountRequestError()
					}
					return fmt.Errorf("failed to create metadata entry for key %s: %w", key, err)
				}
			} else {
				if lm.appMetrics != nil {
					lm.appMetrics.IDPMetrics().CountRequestError()
				}
				return fmt.Errorf("failed to update metadata for key %s: %w", key, err)
			}
		}
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	return nil
}

// ensureMetadataContainer ensures the user's metadata container exists
func (lm *LdapManager) ensureMetadataContainer(conn ldapConnection, metadataDN, userID string) error {
	// Try to search for the container
	searchRequest := ldap.NewSearchRequest(
		metadataDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	)

	_, err := conn.Search(searchRequest)
	if err == nil {
		// Container exists
		return nil
	}

	// If container doesn't exist, create it
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		addRequest := ldap.NewAddRequest(metadataDN, nil)
		addRequest.Attribute("objectClass", []string{"top", "organizationalUnit", "uidObject"})
		addRequest.Attribute("ou", []string{userID})
		addRequest.Attribute("uid", []string{userID})

		if err := conn.Add(addRequest); err != nil {
			return fmt.Errorf("failed to create metadata container: %w", err)
		}
		return nil
	}

	return fmt.Errorf("failed to check metadata container: %w", err)
}

// GetUserDataByID retrieves user data by user ID from LDAP
func (lm *LdapManager) GetUserDataByID(ctx context.Context, userID string, appMetadata AppMetadata) (*UserData, error) {
	conn, err := lm.connect(ctx)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}
	defer conn.Close()

	// Build filter combining base filter and ID filter
	filter := fmt.Sprintf("(&%s(%s=%s))", lm.config.Filter, lm.config.IDAttr, ldap.EscapeFilter(userID))

	users, err := lm.searchUsers(ctx, conn, filter)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user with ID %s not found", userID)
	}

	userData := users[0]
	userData.AppMetadata = appMetadata

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	return userData, nil
}

// GetAccount retrieves all users for a given account ID
func (lm *LdapManager) GetAccount(ctx context.Context, accountID string) ([]*UserData, error) {
	conn, err := lm.connect(ctx)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}
	defer conn.Close()

	// Search for all metadata entries with the specified account ID
	// This is much more efficient than fetching all users and filtering
	filter := fmt.Sprintf("(&(cn=%s)(description=%s))", metadataKeys.WTAccountID, ldap.EscapeFilter(accountID))
	searchRequest := ldap.NewSearchRequest(
		lm.config.NetbirdMetadataDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"cn", "description"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, fmt.Errorf("failed to search account metadata: %w", err)
	}

	// Extract user IDs from the metadata entry DNs
	// DN format: cn=wt_account_id,uid={userID},ou=netbirdMetadata,...
	userIDs := make([]string, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		// Parse the DN to extract the uid
		dn, err := ldap.ParseDN(entry.DN)
		if err != nil {
			continue
		}
		// The uid is in the second RDN (first is cn=wt_account_id)
		if len(dn.RDNs) >= 2 {
			for _, attr := range dn.RDNs[1].Attributes {
				if attr.Type == "uid" {
					userIDs = append(userIDs, attr.Value)
					break
				}
			}
		}
	}

	// Fetch user data for each user ID
	accountUsers := make([]*UserData, 0, len(userIDs))
	for _, userID := range userIDs {
		// Build filter to get specific user by ID
		userFilter := fmt.Sprintf("(&%s(%s=%s))", lm.config.Filter, lm.config.IDAttr, ldap.EscapeFilter(userID))
		users, err := lm.searchUsers(ctx, conn, userFilter)
		if err != nil || len(users) == 0 {
			// Skip users that can't be found or have errors
			continue
		}

		user := users[0]
		// Get full metadata for this user
		metadata, err := lm.getMetadata(ctx, conn, userID)
		if err == nil {
			user.AppMetadata = metadata
		}
		accountUsers = append(accountUsers, user)
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetAccount()
	}

	return accountUsers, nil
}

// GetAllAccounts retrieves all users grouped by account ID
func (lm *LdapManager) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	conn, err := lm.connect(ctx)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}
	defer conn.Close()

	// Get all users
	users, err := lm.searchUsers(ctx, conn, lm.config.Filter)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	// Group users by account ID
	accounts := make(map[string][]*UserData)
	for _, user := range users {
		metadata, err := lm.getMetadata(ctx, conn, user.ID)
		if err != nil {
			// Skip users with metadata errors
			continue
		}

		user.AppMetadata = metadata
		accountID := metadata.WTAccountID
		if accountID == "" {
			accountID = UnsetAccountID
		}

		accounts[accountID] = append(accounts[accountID], user)
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetAllAccounts()
	}

	return accounts, nil
}

// CreateUser creates a new user in LDAP
func (lm *LdapManager) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	return nil, fmt.Errorf("method CreateUser not implemented for LDAP IdP")
}

// GetUserByEmail searches users by email
func (lm *LdapManager) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	conn, err := lm.connect(ctx)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}
	defer conn.Close()

	// Build filter combining base filter and email filter
	filter := fmt.Sprintf("(&%s(%s=%s))", lm.config.Filter, lm.config.EmailAttr, ldap.EscapeFilter(email))

	users, err := lm.searchUsers(ctx, conn, filter)
	if err != nil {
		if lm.appMetrics != nil {
			lm.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	// Load metadata for each user
	for _, user := range users {
		metadata, err := lm.getMetadata(ctx, conn, user.ID)
		if err != nil {
			// Set empty metadata on error
			user.AppMetadata = AppMetadata{}
		} else {
			user.AppMetadata = metadata
		}
	}

	if lm.appMetrics != nil {
		lm.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	return users, nil
}

// InviteUserByID invites a user by ID (not implemented for LDAP)
func (lm *LdapManager) InviteUserByID(ctx context.Context, userID string) error {
	return fmt.Errorf("method InviteUserByID not implemented for LDAP IdP")
}

// DeleteUser deletes a user from LDAP
func (lm *LdapManager) DeleteUser(ctx context.Context, userID string) error {
	return fmt.Errorf("method DeleteUser not implemented for LDAP IdP")
}
