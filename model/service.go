package model

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"

	pb "github.com/nezhahq/nezha/proto"
)

const (
	_ = iota
	TaskTypeHTTPGet
	TaskTypeICMPPing
	TaskTypeTCPPing
	// Reserved: legacy arbitrary command execution is disabled.
	TaskTypeCommand
	// Reserved: legacy terminal sessions are disabled.
	TaskTypeTerminal
	TaskTypeUpgrade
	TaskTypeKeepalive
	// Reserved: legacy gRPC terminal sessions are disabled.
	TaskTypeTerminalGRPC
	TaskTypeNAT
	TaskTypeReportHostInfoDeprecated
	// Reserved: legacy file manager sessions are disabled.
	TaskTypeFM
	TaskTypeReportConfig
	TaskTypeApplyConfig
	// TaskTypeServerTransferApply: per-transfer credential rotation.
	// Pre-transfer agents do not recognise this type — dashboard MUST gate
	// transfers on agent capability before pushing.
	TaskTypeServerTransferApply
	// Reserved: MCP remote command execution is disabled.
	TaskTypeExec
	// Reserved: MCP filesystem operations are disabled.
	TaskTypeFsList
	TaskTypeFsRead
	TaskTypeFsWrite
	TaskTypeFsDelete
	// Reserved: MCP file transfer is disabled.
	TaskTypeFsTransfer
)

// IsServiceMonitorType reports whether t is a passive service probe. Service
// monitors and privileged Agent-control tasks share the protobuf Task.Type
// namespace, so every path that persists, schedules, or dispatches a Service
// must use this allowlist instead of accepting an arbitrary task integer.
func IsServiceMonitorType(t uint64) bool {
	switch t {
	case TaskTypeHTTPGet, TaskTypeICMPPing, TaskTypeTCPPing:
		return true
	default:
		return false
	}
}

// ValidateServiceMonitorType returns an actionable error at API, model, and
// scheduler boundaries. Keeping the check in model avoids a future caller
// accidentally turning a monitor-only capability into Agent command/config
// execution by copying Service.Type into pb.Task.Type.
func ValidateServiceMonitorType(t uint64) error {
	if !IsServiceMonitorType(t) {
		return fmt.Errorf("invalid service monitor type %d: allowed types are 1 (HTTP GET), 2 (ICMP ping), and 3 (TCP ping)", t)
	}
	return nil
}

type TaskNAT struct {
	StreamID string
	Host     string
}

const (
	ServiceCoverAll = iota
	ServiceCoverIgnoreAll
)

type Service struct {
	Common
	Name                string `json:"name"`
	Type                uint8  `json:"type"`
	Target              string `json:"target"`
	SkipServersRaw      string `json:"-"`
	Duration            uint64 `json:"duration"`
	DisplayIndex        int    `json:"display_index"` // 展示排序，越大越靠前
	Notify              bool   `json:"notify,omitempty"`
	NotificationGroupID uint64 `json:"notification_group_id"` // 当前服务监控所属的通知组 ID
	Cover               uint8  `json:"cover"`

	EnableTriggerTask      bool   `gorm:"default: false" json:"enable_trigger_task,omitempty"`
	HideForGuest           bool   `json:"hide_for_guest,omitempty"` // 对游客隐藏
	FailTriggerTasksRaw    string `gorm:"default:'[]'" json:"-"`
	RecoverTriggerTasksRaw string `gorm:"default:'[]'" json:"-"`

	FailTriggerTasks    []uint64 `gorm:"-" json:"fail_trigger_tasks"`    // 失败时执行的触发任务id
	RecoverTriggerTasks []uint64 `gorm:"-" json:"recover_trigger_tasks"` // 恢复时执行的触发任务id

	MinLatency    float32 `json:"min_latency"`
	MaxLatency    float32 `json:"max_latency"`
	LatencyNotify bool    `json:"latency_notify,omitempty"`

	SkipServers map[uint64]bool `gorm:"-" json:"skip_servers"`
	CronJobID   cron.EntryID    `gorm:"-" json:"-"`
}

func (m *Service) PB() *pb.Task {
	if m == nil || !IsServiceMonitorType(uint64(m.Type)) {
		return nil
	}
	return &pb.Task{
		Id:   m.ID,
		Type: uint64(m.Type),
		Data: m.Target,
	}
}

// HasPermission 扩展默认的 owner/admin 检查，让 PAT 的 server_ids 白名单
// 同样能收窄 service monitor 的列出/删除/更新路径，语义与 Cron.HasPermission
// 对齐：
//   - ServiceCoverAll：SkipServers 是 deny-set。DispatchTask 会探测 owner 在
//     deny-set 之外的所有 server，所以受限 PAT 必须保证 deny-set 已经覆盖
//     白名单外的全部 owner servers。判定与 controller 的
//     enforcePATServiceDispatchScope / rejectImplicitServiceCoverForLimitedPAT
//     共用 denyListSafeForLimitedPAT。
//   - ServiceCoverIgnoreAll：SkipServers 是 allow-set，要求每个被覆盖的
//     server 都在 PAT 白名单内。
//   - 其它情况保留旧的“PAT 按 owner 关系判定”行为。
func (m *Service) HasPermission(ctx *gin.Context) bool {
	if !m.Common.HasPermission(ctx) {
		return false
	}
	v, ok := ctx.Get(CtxKeyAPIToken)
	if !ok {
		return true
	}
	tok, _ := v.(APITokenAccessor)
	if tok == nil {
		return true
	}
	switch m.Cover {
	case ServiceCoverAll:
		return DenyListSafeForLimitedPAT(tok, m.GetUserID(), skipServersTrueIDs(m.SkipServers))
	case ServiceCoverIgnoreAll:
		for _, id := range skipServersTrueIDs(m.SkipServers) {
			if !tok.CanAccessServer(id) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

func skipServersTrueIDs(skip map[uint64]bool) []uint64 {
	if len(skip) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(skip))
	for id, mark := range skip {
		if mark {
			out = append(out, id)
		}
	}
	return out
}

// CronSpec 返回服务监控请求间隔对应的 cron 表达式
func (m *Service) CronSpec() string {
	if m.Duration == 0 {
		// 默认间隔 30 秒
		m.Duration = 30
	}
	return fmt.Sprintf("@every %ds", m.Duration)
}

func (m *Service) BeforeSave(tx *gorm.DB) error {
	if err := ValidateServiceMonitorType(uint64(m.Type)); err != nil {
		return err
	}
	if data, err := json.Marshal(m.SkipServers); err != nil {
		return err
	} else {
		m.SkipServersRaw = string(data)
	}
	if data, err := json.Marshal(m.FailTriggerTasks); err != nil {
		return err
	} else {
		m.FailTriggerTasksRaw = string(data)
	}
	if data, err := json.Marshal(m.RecoverTriggerTasks); err != nil {
		return err
	} else {
		m.RecoverTriggerTasksRaw = string(data)
	}
	return nil
}

func (m *Service) AfterFind(tx *gorm.DB) error {
	m.SkipServers = make(map[uint64]bool)
	if err := json.Unmarshal([]byte(m.SkipServersRaw), &m.SkipServers); err != nil {
		log.Println("NEZHA>> Service.AfterFind:", err)
		return nil
	}

	// 加载触发任务列表
	if err := json.Unmarshal([]byte(m.FailTriggerTasksRaw), &m.FailTriggerTasks); err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(m.RecoverTriggerTasksRaw), &m.RecoverTriggerTasks); err != nil {
		return err
	}

	return nil
}

// IsServiceSentinelNeeded accepts results only for the three probe types. An
// unknown or privileged task type must never enter ServiceSentinel merely
// because it was not listed in a denylist.
func IsServiceSentinelNeeded(t uint64) bool {
	return IsServiceMonitorType(t)
}
