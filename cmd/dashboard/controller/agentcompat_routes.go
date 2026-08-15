//go:build agentcompat

package controller

import (
	"errors"
	"fmt"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/nezhahq/nezha/service/rpc"
)

func registerAgentcompatRoutes(router *gin.Engine) {
	patAuth := requiredAgentcompatPAT(apiTokenAuthMiddleware())
	router.GET("/agentcompat/io-stream-state", patAuth, commonHandler(agentcompatIOStreamSnapshot))
	router.POST("/agentcompat/io-stream-state", patAuth, commonHandler(agentcompatIOStreamWait))
	router.POST("/agentcompat/io-stream-quota-probe", patAuth, commonHandler(agentcompatIOStreamQuotaProbeRoute))
}

type agentcompatIOStreamQuotaProbeResponse struct {
	UserAccepted   int  `json:"user_accepted"`
	UserRejected   int  `json:"user_rejected"`
	ServerAccepted int  `json:"server_accepted"`
	ServerRejected int  `json:"server_rejected"`
	Clean          bool `json:"clean"`
}

func agentcompatIOStreamQuotaProbeRoute(context *gin.Context) (agentcompatIOStreamQuotaProbeResponse, error) {
	if rpc.NezhaHandlerSingleton == nil {
		return agentcompatIOStreamQuotaProbeResponse{}, errors.New("IOStream handler is unavailable")
	}
	result := rpc.RunIOStreamQuotaProbe(context.Request.Context())
	if result.Err != nil {
		return agentcompatIOStreamQuotaProbeResponse{}, result.Err
	}
	return agentcompatIOStreamQuotaProbeResponse{UserAccepted: result.UserAccepted, UserRejected: result.UserRejected, ServerAccepted: result.ServerAccepted, ServerRejected: result.ServerRejected, Clean: result.TrackedStreams == 0}, nil
}

func requiredAgentcompatPAT(auth gin.HandlerFunc) gin.HandlerFunc {
	return func(context *gin.Context) {
		auth(context)
		if context.IsAborted() {
			return
		}
		if APITokenFromContext(context) == nil {
			abortAPITokenUnauthorized(context, "api token required")
		}
	}
}

func agentcompatIOStreamSnapshot(*gin.Context) (rpc.IOStreamState, error) {
	if rpc.NezhaHandlerSingleton == nil {
		return rpc.IOStreamState{}, errors.New("IOStream handler is unavailable")
	}
	return rpc.NezhaHandlerSingleton.SnapshotIOStreamState(), nil
}

func agentcompatIOStreamWait(context *gin.Context) (rpc.IOStreamState, error) {
	if rpc.NezhaHandlerSingleton == nil {
		return rpc.IOStreamState{}, errors.New("IOStream handler is unavailable")
	}
	var expectation rpc.IOStreamStateExpectation
	if err := context.ShouldBindJSON(&expectation); err != nil {
		return rpc.IOStreamState{}, err
	}
	return rpc.NezhaHandlerSingleton.WaitForIOStreamState(context.Request.Context(), expectation)
}

func decodeAgentcompatJSON(context *gin.Context, value any) error {
	decoder := json.NewDecoder(context.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON values are not allowed")
		}
		return err
	}
	return nil
}
