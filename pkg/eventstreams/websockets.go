// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eventstreams

import (
	"context"
	"crypto/tls"
	"database/sql/driver"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/wsserver"
)

type DistributionMode = fftypes.FFEnum

var (
	DistributionModeBroadcast   = fftypes.FFEnumValue("distmode", "broadcast")
	DistributionModeLoadBalance = fftypes.FFEnumValue("distmode", "load_balance")
)

type WebSocketConfig struct {
	DistributionMode *DistributionMode `ffstruct:"wsconfig" json:"distributionMode,omitempty"`
}

type webSocketDispatcherFactory[CT any, DT any] struct {
	esm *esManager[CT, DT]
}

// Store in DB as JSON
func (wc *WebSocketConfig) Scan(src interface{}) error {
	return fftypes.JSONScan(src, wc)
}

// Store in DB as JSON
func (wc *WebSocketConfig) Value() (driver.Value, error) {
	if wc == nil {
		return nil, nil
	}
	return fftypes.JSONValue(wc)
}

func (wsf *webSocketDispatcherFactory[CT, DT]) Validate(ctx context.Context, conf *Config[CT, DT], spec *EventStreamSpec[CT], _ map[string]*tls.Config, phase LifecyclePhase) error {
	if spec.WebSocket == nil {
		spec.WebSocket = &WebSocketConfig{}
	}
	setDefaults := phase == LifecyclePhaseStarting
	return checkSet(ctx, setDefaults, "distributionMode", &spec.WebSocket.DistributionMode, conf.Defaults.WebSocketDefaults.DefaultDistributionMode, func(v fftypes.FFEnum) bool { return fftypes.FFEnumValid(ctx, "distmode", v) })
}

type webSocketAction[DT any] struct {
	topic      string
	spec       *WebSocketConfig
	wsChannels wsserver.WebSocketChannels
}

func (wsf *webSocketDispatcherFactory[CT, DT]) NewDispatcher(_ context.Context, _ *Config[CT, DT], spec *EventStreamSpec[CT]) EventBatchDispatcher[DT] {
	return &webSocketAction[DT]{
		spec:       spec.WebSocket,
		wsChannels: wsf.esm.wsChannels,
		topic:      *spec.Name,
	}
}

func (w *webSocketAction[DT]) AttemptDispatch(ctx context.Context, attempt int, batch *EventBatch[DT]) error {
	var err error

	// Get a blocking channel to send and receive on our chosen namespace
	sender, broadcaster, receiver := w.wsChannels.GetChannels(w.topic)

	var channel chan<- interface{}
	isBroadcast := *w.spec.DistributionMode == DistributionModeBroadcast
	if isBroadcast {
		channel = broadcaster
	} else {
		channel = sender
	}

	// Send the batch of events
	select {
	case channel <- batch:
		break
	case <-ctx.Done():
		err = i18n.NewError(ctx, i18n.MsgWebSocketInterruptedSend)
	}

	if err == nil && !isBroadcast {
		log.L(ctx).Infof("Batch %d dispatched (len=%d,attempt=%d)", batch.BatchNumber, len(batch.Events), attempt)
		err = w.waitForAck(ctx, receiver, batch.BatchNumber)
	}

	// Pass back any exception due
	if err != nil {
		log.L(ctx).Infof("WebSocket event batch %d delivery failed (len=%d,attempt=%d): %s", batch.BatchNumber, len(batch.Events), attempt, err)
		return err
	}
	log.L(ctx).Infof("WebSocket event batch %d complete (len=%d,attempt=%d)", batch.BatchNumber, len(batch.Events), attempt)
	return nil
}

func (w *webSocketAction[DT]) waitForAck(ctx context.Context, receiver <-chan *wsserver.WebSocketCommandMessageOrError, batchNumber int64) error {
	// Wait for the next ack or exception
	for {
		select {
		case msgOrErr := <-receiver:
			if msgOrErr.Err != nil {
				// If we get an error, we have to assume the other side did not receive this batch, and send it again
				return msgOrErr.Err
			}
			if msgOrErr.Msg.BatchNumber != batchNumber {
				log.L(ctx).Infof("Discarding ack for batch %d (awaiting %d)", msgOrErr.Msg.BatchNumber, batchNumber)
				continue
			}
			log.L(ctx).Infof("Batch %d acknowledged", batchNumber)
			return nil
		case <-ctx.Done():
			return i18n.NewError(ctx, i18n.MsgWebSocketInterruptedReceive)
		}
	}
}
