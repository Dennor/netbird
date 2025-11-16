package idp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// mockLdapConnection implements ldapConnection interface for testing
type mockLdapConnection struct {
	bindFunc   func(username, password string) error
	searchFunc func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	addFunc    func(addRequest *ldap.AddRequest) error
	modifyFunc func(modifyRequest *ldap.ModifyRequest) error
	delFunc    func(delRequest *ldap.DelRequest) error
	closed     bool
}

func (m *mockLdapConnection) Bind(username, password string) error {
	if m.bindFunc != nil {
		return m.bindFunc(username, password)
	}
	return nil
}

func (m *mockLdapConnection) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.searchFunc != nil {
		return m.searchFunc(searchRequest)
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
}

func (m *mockLdapConnection) Add(addRequest *ldap.AddRequest) error {
	if m.addFunc != nil {
		return m.addFunc(addRequest)
	}
	return nil
}

func (m *mockLdapConnection) Modify(modifyRequest *ldap.ModifyRequest) error {
	if m.modifyFunc != nil {
		return m.modifyFunc(modifyRequest)
	}
	return nil
}

func (m *mockLdapConnection) Del(delRequest *ldap.DelRequest) error {
	if m.delFunc != nil {
		return m.delFunc(delRequest)
	}
	return nil
}

func (m *mockLdapConnection) Close() error {
	m.closed = true
	return nil
}

// mockLdapConnector implements ldapConnector interface for testing
type mockLdapConnector struct {
	connectFunc func(ctx context.Context, config LdapClientConfig) (ldapConnection, error)
}

func (m *mockLdapConnector) Connect(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
	if m.connectFunc != nil {
		return m.connectFunc(ctx, config)
	}
	return &mockLdapConnection{}, nil
}

func TestNewLdapManager(t *testing.T) {
	type test struct {
		name                 string
		inputConfig          LdapClientConfig
		assertErrFunc        require.ErrorAssertionFunc
		assertErrFuncMessage string
		expectedUserSearchDN string
		expectedMetadataDN   string
		expectedFilter       string
	}

	defaultTestConfig := LdapClientConfig{
		Host:   "ldap://localhost:389",
		DN:     "cn=admin,dc=example,dc=com",
		Passwd: "password",
		BaseDN: "dc=example,dc=com",
	}

	tests := []test{
		{
			name:                 "Good Configuration with BaseDN",
			inputConfig:          defaultTestConfig,
			assertErrFunc:        require.NoError,
			assertErrFuncMessage: "shouldn't return error",
			expectedUserSearchDN: "ou=users,dc=example,dc=com",
			expectedMetadataDN:   "ou=netbirdMetadata,dc=example,dc=com",
			expectedFilter:       "(objectclass=person)",
		},
		{
			name: "Missing Host",
			inputConfig: LdapClientConfig{
				BaseDN: defaultTestConfig.BaseDN,
			},
			assertErrFunc:        require.Error,
			assertErrFuncMessage: "should return error when Host is empty",
		},
		{
			name: "Missing BaseDN and UserSearchDN",
			inputConfig: LdapClientConfig{
				Host:              defaultTestConfig.Host,
				NetbirdMetadataDN: "ou=netbirdMetadata,dc=example,dc=com",
			},
			assertErrFunc:        require.Error,
			assertErrFuncMessage: "should return error when both BaseDN and UserSearchDN are empty",
		},
		{
			name: "Missing BaseDN and NetbirdMetadataDN",
			inputConfig: LdapClientConfig{
				Host:         defaultTestConfig.Host,
				UserSearchDN: "ou=users,dc=example,dc=com",
			},
			assertErrFunc:        require.Error,
			assertErrFuncMessage: "should return error when both BaseDN and NetbirdMetadataDN are empty",
		},
		{
			name: "Custom UserSearchDN",
			inputConfig: LdapClientConfig{
				Host:         defaultTestConfig.Host,
				BaseDN:       defaultTestConfig.BaseDN,
				UserSearchDN: "ou=people,dc=example,dc=com",
			},
			assertErrFunc:        require.NoError,
			assertErrFuncMessage: "shouldn't return error",
			expectedUserSearchDN: "ou=people,dc=example,dc=com",
			expectedMetadataDN:   "ou=netbirdMetadata,dc=example,dc=com",
			expectedFilter:       "(objectclass=person)",
		},
		{
			name: "Custom NetbirdMetadataDN",
			inputConfig: LdapClientConfig{
				Host:              defaultTestConfig.Host,
				BaseDN:            defaultTestConfig.BaseDN,
				NetbirdMetadataDN: "ou=metadata,dc=example,dc=com",
			},
			assertErrFunc:        require.NoError,
			assertErrFuncMessage: "shouldn't return error",
			expectedUserSearchDN: "ou=users,dc=example,dc=com",
			expectedMetadataDN:   "ou=metadata,dc=example,dc=com",
			expectedFilter:       "(objectclass=person)",
		},
		{
			name: "Custom Filter",
			inputConfig: LdapClientConfig{
				Host:   defaultTestConfig.Host,
				BaseDN: defaultTestConfig.BaseDN,
				Filter: "(&(objectclass=inetOrgPerson)(status=active))",
			},
			assertErrFunc:        require.NoError,
			assertErrFuncMessage: "shouldn't return error",
			expectedUserSearchDN: "ou=users,dc=example,dc=com",
			expectedMetadataDN:   "ou=netbirdMetadata,dc=example,dc=com",
			expectedFilter:       "(&(objectclass=inetOrgPerson)(status=active))",
		},
		{
			name: "Custom Attributes",
			inputConfig: LdapClientConfig{
				Host:      defaultTestConfig.Host,
				BaseDN:    defaultTestConfig.BaseDN,
				NameAttr:  "cn",
				IDAttr:    "employeeId",
				EmailAttr: "mail",
			},
			assertErrFunc:        require.NoError,
			assertErrFuncMessage: "shouldn't return error",
			expectedUserSearchDN: "ou=users,dc=example,dc=com",
			expectedMetadataDN:   "ou=netbirdMetadata,dc=example,dc=com",
			expectedFilter:       "(objectclass=person)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager, err := NewLdapManager(tc.inputConfig, &telemetry.MockAppMetrics{})
			tc.assertErrFunc(t, err, tc.assertErrFuncMessage)

			if err == nil {
				assert.Equal(t, tc.expectedUserSearchDN, manager.config.UserSearchDN)
				assert.Equal(t, tc.expectedMetadataDN, manager.config.NetbirdMetadataDN)
				assert.Equal(t, tc.expectedFilter, manager.config.Filter)

				// Check attribute defaults
				if tc.inputConfig.NameAttr == "" {
					assert.Equal(t, "uid", manager.config.NameAttr)
				}
				if tc.inputConfig.IDAttr == "" {
					assert.Equal(t, "uid", manager.config.IDAttr)
				}
				if tc.inputConfig.EmailAttr == "" {
					assert.Equal(t, "mail", manager.config.EmailAttr)
				}
			}
		})
	}
}

func TestNewLdapManager_PasswdFile(t *testing.T) {
	// Create a temporary password file
	tmpFile := t.TempDir() + "/passwd"
	passwordContent := "secretpassword123\n"
	err := os.WriteFile(tmpFile, []byte(passwordContent), 0600)
	require.NoError(t, err, "should create temp password file")

	defaultTestConfig := LdapClientConfig{
		Host:   "ldap://localhost:389",
		DN:     "cn=admin,dc=example,dc=com",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("Password from file", func(t *testing.T) {
		config := defaultTestConfig
		config.PasswdFile = tmpFile

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err, "should create manager with password file")
		assert.Equal(t, "secretpassword123", manager.config.Passwd, "password should be read from file and trimmed")
	})

	t.Run("Password file takes priority over Passwd field", func(t *testing.T) {
		config := defaultTestConfig
		config.Passwd = "wrongpassword"
		config.PasswdFile = tmpFile

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err, "should create manager with password file")
		assert.Equal(t, "secretpassword123", manager.config.Passwd, "password file should take priority")
	})

	t.Run("Password file with whitespace", func(t *testing.T) {
		tmpFileWhitespace := t.TempDir() + "/passwd_whitespace"
		err := os.WriteFile(tmpFileWhitespace, []byte("  password456  \n\n"), 0600)
		require.NoError(t, err, "should create temp password file with whitespace")

		config := defaultTestConfig
		config.PasswdFile = tmpFileWhitespace

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err, "should create manager with password file")
		assert.Equal(t, "password456", manager.config.Passwd, "password should be trimmed")
	})

	t.Run("Password file does not exist", func(t *testing.T) {
		config := defaultTestConfig
		config.PasswdFile = "/nonexistent/passwd"

		_, err := NewLdapManager(config, nil)
		require.Error(t, err, "should return error when password file does not exist")
		assert.Contains(t, err.Error(), "failed to read password file", "error should mention password file")
	})

	t.Run("Empty password file", func(t *testing.T) {
		tmpFileEmpty := t.TempDir() + "/passwd_empty"
		err := os.WriteFile(tmpFileEmpty, []byte(""), 0600)
		require.NoError(t, err, "should create empty temp password file")

		config := defaultTestConfig
		config.PasswdFile = tmpFileEmpty

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err, "should create manager with empty password file")
		assert.Equal(t, "", manager.config.Passwd, "password should be empty string")
	})

	t.Run("No password file specified uses Passwd field", func(t *testing.T) {
		config := defaultTestConfig
		config.Passwd = "directpassword"

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err, "should create manager with direct password")
		assert.Equal(t, "directpassword", manager.config.Passwd, "should use direct password field")
	})
}

func TestLdapManager_UpdateUserAppMetadata(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("Update existing metadata", func(t *testing.T) {
		modifyCalled := false
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Container exists
				if searchRequest.BaseDN == "uid=user1,ou=netbirdMetadata,dc=example,dc=com" {
					entry := ldap.NewEntry(searchRequest.BaseDN, nil)
					entry.Attributes = []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"user1"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			},
			modifyFunc: func(modifyRequest *ldap.ModifyRequest) error {
				modifyCalled = true
				// Should be updating the cn-based entry
				assert.Equal(t, "cn=wt_account_id,uid=user1,ou=netbirdMetadata,dc=example,dc=com", modifyRequest.DN)
				return nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		// Override connector to return mock connection
		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		metadata := AppMetadata{WTAccountID: "acc1"}
		err = manager.UpdateUserAppMetadata(context.Background(), "user1", metadata)
		require.NoError(t, err)
		assert.True(t, modifyCalled)
		assert.True(t, mockConn.closed)
	})

	t.Run("Create new metadata entry", func(t *testing.T) {
		addCalled := 0
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Container doesn't exist
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
			},
			modifyFunc: func(modifyRequest *ldap.ModifyRequest) error {
				// Entry doesn't exist, will trigger add
				return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
			},
			addFunc: func(addRequest *ldap.AddRequest) error {
				addCalled++

				// First add should be the container
				if addRequest.DN == "uid=user1,ou=netbirdMetadata,dc=example,dc=com" {
					// Verify container attributes
					var foundObjectClass, foundOU, foundUID bool
					for _, attr := range addRequest.Attributes {
						if attr.Type == "objectClass" {
							foundObjectClass = true
							assert.Contains(t, attr.Vals, "organizationalUnit")
							assert.Contains(t, attr.Vals, "uidObject")
						}
						if attr.Type == "ou" {
							foundOU = true
							assert.Equal(t, []string{"user1"}, attr.Vals)
						}
						if attr.Type == "uid" {
							foundUID = true
							assert.Equal(t, []string{"user1"}, attr.Vals)
						}
					}
					assert.True(t, foundObjectClass)
					assert.True(t, foundOU)
					assert.True(t, foundUID)
					return nil
				}

				// Second add should be the metadata key entry
				if addRequest.DN == "cn=wt_account_id,uid=user1,ou=netbirdMetadata,dc=example,dc=com" {
					var foundObjectClass, foundCN, foundDescription bool
					for _, attr := range addRequest.Attributes {
						if attr.Type == "objectClass" {
							foundObjectClass = true
							assert.Contains(t, attr.Vals, "applicationProcess")
						}
						if attr.Type == "cn" {
							foundCN = true
							assert.Equal(t, []string{"wt_account_id"}, attr.Vals)
						}
						if attr.Type == "description" {
							foundDescription = true
							assert.Equal(t, []string{"acc1"}, attr.Vals)
						}
					}
					assert.True(t, foundObjectClass, "objectClass attribute should be present")
					assert.True(t, foundCN, "cn attribute should be present")
					assert.True(t, foundDescription, "description attribute should be present")
					return nil
				}

				return fmt.Errorf("unexpected DN: %s", addRequest.DN)
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		metadata := AppMetadata{WTAccountID: "acc1"}
		err = manager.UpdateUserAppMetadata(context.Background(), "user1", metadata)
		require.NoError(t, err)
		assert.Equal(t, 2, addCalled, "should create container and metadata entry")
	})

	t.Run("Connection error", func(t *testing.T) {
		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return nil, errors.New("connection failed")
			},
		}

		metadata := AppMetadata{WTAccountID: "acc1"}
		err = manager.UpdateUserAppMetadata(context.Background(), "user1", metadata)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection failed")
	})
}

func TestLdapManager_GetUserDataByID(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("User found", func(t *testing.T) {
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				entry := ldap.NewEntry("uid=user1,ou=users,dc=example,dc=com", nil)
				entry.Attributes = []*ldap.EntryAttribute{
					{Name: "uid", Values: []string{"user1"}},
					{Name: "uid", Values: []string{"User One"}},
					{Name: "mail", Values: []string{"user1@example.com"}},
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		metadata := AppMetadata{WTAccountID: "acc1"}
		userData, err := manager.GetUserDataByID(context.Background(), "user1", metadata)
		require.NoError(t, err)
		assert.Equal(t, "user1", userData.ID)
		assert.Equal(t, "acc1", userData.AppMetadata.WTAccountID)
	})

	t.Run("User not found", func(t *testing.T) {
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		metadata := AppMetadata{WTAccountID: "acc1"}
		_, err = manager.GetUserDataByID(context.Background(), "nonexistent", metadata)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestLdapManager_GetAccount(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("Get users for account", func(t *testing.T) {
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// First search: Find all metadata entries for the account ID
				if searchRequest.BaseDN == "ou=netbirdMetadata,dc=example,dc=com" {
					assert.Contains(t, searchRequest.Filter, "cn=wt_account_id")
					assert.Contains(t, searchRequest.Filter, "description=acc1")
					// Return metadata entries for user1 and user2
					entry1 := ldap.NewEntry("cn=wt_account_id,uid=user1,ou=netbirdMetadata,dc=example,dc=com", nil)
					entry1.Attributes = []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"wt_account_id"}},
						{Name: "description", Values: []string{"acc1"}},
					}
					entry2 := ldap.NewEntry("cn=wt_account_id,uid=user2,ou=netbirdMetadata,dc=example,dc=com", nil)
					entry2.Attributes = []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"wt_account_id"}},
						{Name: "description", Values: []string{"acc1"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry1, entry2}}, nil
				}
				// Subsequent searches: Fetch individual users by ID
				if searchRequest.BaseDN == "ou=users,dc=example,dc=com" {
					if strings.Contains(searchRequest.Filter, "uid=user1") {
						entry := ldap.NewEntry("uid=user1,ou=users,dc=example,dc=com", nil)
						entry.Attributes = []*ldap.EntryAttribute{
							{Name: "uid", Values: []string{"user1"}},
							{Name: "mail", Values: []string{"user1@example.com"}},
						}
						return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
					}
					if strings.Contains(searchRequest.Filter, "uid=user2") {
						entry := ldap.NewEntry("uid=user2,ou=users,dc=example,dc=com", nil)
						entry.Attributes = []*ldap.EntryAttribute{
							{Name: "uid", Values: []string{"user2"}},
							{Name: "mail", Values: []string{"user2@example.com"}},
						}
						return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
					}
				}
				// Individual metadata searches for each user
				if strings.HasPrefix(searchRequest.BaseDN, "uid=user") {
					entry := ldap.NewEntry("cn=wt_account_id,"+searchRequest.BaseDN, nil)
					entry.Attributes = []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"wt_account_id"}},
						{Name: "description", Values: []string{"acc1"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		users, err := manager.GetAccount(context.Background(), "acc1")
		require.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, "acc1", users[0].AppMetadata.WTAccountID)
	})
}

func TestLdapManager_GetAllAccounts(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("Get all accounts", func(t *testing.T) {
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Check if it's a user search or metadata search
				if searchRequest.BaseDN == "ou=users,dc=example,dc=com" {
					// Return three users
					entry1 := ldap.NewEntry("uid=user1,ou=users,dc=example,dc=com", nil)
					entry1.Attributes = []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"user1"}},
						{Name: "mail", Values: []string{"user1@example.com"}},
					}
					entry2 := ldap.NewEntry("uid=user2,ou=users,dc=example,dc=com", nil)
					entry2.Attributes = []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"user2"}},
						{Name: "mail", Values: []string{"user2@example.com"}},
					}
					entry3 := ldap.NewEntry("uid=user3,ou=users,dc=example,dc=com", nil)
					entry3.Attributes = []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"user3"}},
						{Name: "mail", Values: []string{"user3@example.com"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry1, entry2, entry3}}, nil
				}
				// Metadata search - return cn-based entries for different users
				if searchRequest.BaseDN == "uid=user1,ou=netbirdMetadata,dc=example,dc=com" {
					entry := ldap.NewEntry("cn=wt_account_id,"+searchRequest.BaseDN, nil)
					entry.Attributes = []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"wt_account_id"}},
						{Name: "description", Values: []string{"acc1"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
				} else if searchRequest.BaseDN == "uid=user2,ou=netbirdMetadata,dc=example,dc=com" {
					entry := ldap.NewEntry("cn=wt_account_id,"+searchRequest.BaseDN, nil)
					entry.Attributes = []*ldap.EntryAttribute{
						{Name: "cn", Values: []string{"wt_account_id"}},
						{Name: "description", Values: []string{"acc1"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
				} else if searchRequest.BaseDN == "uid=user3,ou=netbirdMetadata,dc=example,dc=com" {
					// No metadata for user3
					return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		accounts, err := manager.GetAllAccounts(context.Background())
		require.NoError(t, err)

		// Should have acc1 with 2 users and UnsetAccountID with 1 user
		assert.Len(t, accounts, 2)
		assert.Len(t, accounts["acc1"], 2)
		assert.Len(t, accounts[UnsetAccountID], 1)
	})
}

func TestLdapManager_GetUserByEmail(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("User found by email", func(t *testing.T) {
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Check if it's a user search or metadata search
				if searchRequest.BaseDN == "ou=users,dc=example,dc=com" {
					assert.Contains(t, searchRequest.Filter, "mail=user1@example.com")
					entry := ldap.NewEntry("uid=user1,ou=users,dc=example,dc=com", nil)
					entry.Attributes = []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{"user1"}},
						{Name: "mail", Values: []string{"user1@example.com"}},
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
				}
				// Metadata search - return cn-based entries
				entry := ldap.NewEntry("cn=wt_account_id,"+searchRequest.BaseDN, nil)
				entry.Attributes = []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"wt_account_id"}},
					{Name: "description", Values: []string{"acc1"}},
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		users, err := manager.GetUserByEmail(context.Background(), "user1@example.com")
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, "user1@example.com", users[0].Email)
		assert.Equal(t, "acc1", users[0].AppMetadata.WTAccountID)
	})
}

func TestLdapManager_CreateUser(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	manager, err := NewLdapManager(config, nil)
	require.NoError(t, err)

	_, err = manager.CreateUser(context.Background(), "user@example.com", "User", "acc1", "inviter@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestLdapManager_InviteUserByID(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	manager, err := NewLdapManager(config, nil)
	require.NoError(t, err)

	err = manager.InviteUserByID(context.Background(), "user1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestLdapManager_DeleteUser(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	manager, err := NewLdapManager(config, nil)
	require.NoError(t, err)

	err = manager.DeleteUser(context.Background(), "user1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestLdapManager_GetUserMetadataDN(t *testing.T) {
	config := LdapClientConfig{
		Host:              "ldap://localhost:389",
		BaseDN:            "dc=example,dc=com",
		NetbirdMetadataDN: "ou=metadata,dc=example,dc=com",
	}

	manager, err := NewLdapManager(config, nil)
	require.NoError(t, err)

	dn := manager.getUserMetadataDN("user1")
	assert.Equal(t, "uid=user1,ou=metadata,dc=example,dc=com", dn)
}

func TestLdapManager_LDAPFilterEscaping(t *testing.T) {
	config := LdapClientConfig{
		Host:   "ldap://localhost:389",
		BaseDN: "dc=example,dc=com",
	}

	t.Run("Special characters in user ID are escaped", func(t *testing.T) {
		var capturedFilter string
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				capturedFilter = searchRequest.Filter
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		// Use a user ID with special LDAP characters
		_, _ = manager.GetUserDataByID(context.Background(), "user*(test)", AppMetadata{})

		// Verify that special characters are escaped in the filter
		assert.NotContains(t, capturedFilter, "user*(test)", "Special characters should be escaped")
		assert.Contains(t, capturedFilter, fmt.Sprintf("uid=%s", ldap.EscapeFilter("user*(test)")))
	})

	t.Run("Special characters in account ID are escaped", func(t *testing.T) {
		var capturedFilter string
		mockConn := &mockLdapConnection{
			searchFunc: func(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Capture the filter from the metadata search
				if searchRequest.BaseDN == "ou=netbirdMetadata,dc=example,dc=com" {
					capturedFilter = searchRequest.Filter
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
			},
		}

		manager, err := NewLdapManager(config, nil)
		require.NoError(t, err)

		manager.connector = &mockLdapConnector{
			connectFunc: func(ctx context.Context, config LdapClientConfig) (ldapConnection, error) {
				return mockConn, nil
			},
		}

		// Use an account ID with special LDAP characters that could be used for injection
		accountIDWithSpecialChars := "acc123*()|&"
		_, _ = manager.GetAccount(context.Background(), accountIDWithSpecialChars)

		// Verify that special characters are escaped in the filter
		assert.NotContains(t, capturedFilter, accountIDWithSpecialChars, "Special characters should be escaped")
		assert.Contains(t, capturedFilter, ldap.EscapeFilter(accountIDWithSpecialChars), "Filter should contain escaped account ID")
	})
}
