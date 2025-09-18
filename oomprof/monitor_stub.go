// Copyright 2022-2025 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !linux

package oomprof

import (
	"context"
	"errors"

	"github.com/google/pprof/profile"
)

var ErrNotLinux = errors.New("oomprof requires Linux kernel with eBPF support")

func Setup() error {
	return ErrNotLinux
}

func Monitor(ctx context.Context) error {
	return ErrNotLinux
}

func GetCurrentState() *State {
	return nil
}

func GetProfileForVictim(pid int) *profile.Profile {
	return nil
}

func GetProfile(pid int) *profile.Profile {
	return nil
}

func GetOOMChannel() <-chan int {
	return nil
}

func Shutdown() error {
	return ErrNotLinux
}

type State struct{}

func (s *State) Stop() error {
	return ErrNotLinux
}

func (s *State) GetProfile(pid int) *profile.Profile {
	return nil
}

func (s *State) GetProfileForVictim(pid int) *profile.Profile {
	return nil
}

func (s *State) GetOOMChannel() <-chan int {
	return nil
}

func (s *State) GetDebugInfo() string {
	return "oomprof not available on non-Linux platforms"
}

func (s *State) Start() error {
	return ErrNotLinux
}