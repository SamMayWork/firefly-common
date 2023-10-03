// Copyright © 2023 Kaleido, Inc.
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

	"github.com/hyperledger/firefly-common/pkg/fftls"
	"github.com/hyperledger/firefly-common/pkg/i18n"
)

type Manager interface{}

type esManager struct {
	config     Config
	tlsConfigs map[string]*tls.Config
}

func NewEventStreamManager(ctx context.Context, config *Config) (es Manager, err error) {
	if config.WebhookDefaults == nil || config.WebSocketDefaults == nil {
		// We require you to specify defaults.
		// Use GenerateConfig() for this if you're using the standard FF Common config library
		return nil, i18n.NewError(ctx, i18n.MsgESManagerConfigInvalid)
	}
	// Parse the TLS configs up front
	tlsConfigs := make(map[string]*tls.Config)
	for name, tlsJSONConf := range config.TLSConfigs {
		tlsConfigs[name], err = fftls.NewTLSConfig(ctx, tlsJSONConf, fftls.ClientType)
		if err != nil {
			return nil, err
		}
	}
	return &esManager{
		config:     *config,
		tlsConfigs: tlsConfigs,
	}, nil
}
