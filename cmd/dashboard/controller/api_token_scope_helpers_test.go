package controller

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/i18n"
	"github.com/nezhahq/nezha/service/singleton"
)

func ensureLocalizerForStreamTests(t *testing.T) {
	t.Helper()
	if singleton.Localizer == nil {
		singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	}
}

func decodeCommonResponseError(t *testing.T, body []byte) (bool, string) {
	t.Helper()
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, string(body))
	}
	return resp.Success, resp.Error
}

func setAuthUser(c *gin.Context, userID uint64, role model.Role) {
	c.Set(model.CtxKeyAuthorizedUser, &model.User{
		Common: model.Common{ID: userID},
		Role:   role,
	})
}

// setupMCPTest keeps its historical name so API token and REST scope tests
// share one deterministic environment, but it no longer initializes any MCP
// state. The hardened Dashboard has no MCP subsystem.
func setupMCPTest(t *testing.T) (func(), uint64) {
	t.Helper()
	originalDB := singleton.DB
	originalServer := singleton.ServerShared
	originalConf := singleton.Conf
	originalLocalizer := singleton.Localizer
	originalPATRegistry := patConnectionRegistryShared
	singleton.Localizer = i18n.NewLocalizer("en_US", "nezha", "translations", i18n.Translations)
	// Fresh per test: the DB resets token IDs to 1 each run, so a stale
	// revoke tombstone from a prior test would otherwise cancel a reused id.
	patConnectionRegistryShared = newPATConnectionRegistry()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.APIToken{}, &model.Server{}, &model.WAF{}))
	singleton.DB = db
	singleton.Conf = &singleton.ConfigClass{Config: &model.Config{JWTTimeout: 1}}

	user := model.User{Common: model.Common{ID: 100}, Username: "alice", Role: model.RoleMember}
	require.NoError(t, db.Create(&user).Error)

	sc := singleton.NewEmptyServerClassForTest()
	srv := &model.Server{}
	srv.ID = 7
	srv.Name = "alpha"
	srv.SetUserID(100)
	sc.InsertForTest(srv)
	singleton.ServerShared = sc

	cleanup := func() {
		_ = sqlDB.Close()
		singleton.DB = originalDB
		singleton.ServerShared = originalServer
		singleton.Conf = originalConf
		singleton.Localizer = originalLocalizer
		patConnectionRegistryShared = originalPATRegistry
	}
	return cleanup, user.ID
}

func mkToken(t *testing.T, uid uint64, scopes []string, serverIDs []uint64) (*model.APIToken, string) {
	t.Helper()
	plain := "nzp_" + strings.Repeat("a", 32) + "_" + strconv.FormatUint(uid, 10)
	tok := model.APIToken{UserID: uid, Name: "t", TokenHash: model.HashAPIToken(plain)}
	tok.SetScopes(scopes)
	if len(serverIDs) > 0 {
		tok.SetServerIDs(serverIDs)
	}
	require.NoError(t, singleton.DB.Create(&tok).Error)
	return &tok, plain
}
