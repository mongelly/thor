// Copyright (c) 2020 The VeChainThor developers

// Distributed under the GNU Lesser General Public License v3.0 software license, see the accompanying
// file LICENSE or <https://www.gnu.org/licenses/lgpl-3.0.html>

package netpermission

import (
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/vechain/thor/state"
	"github.com/vechain/thor/thor"
)

var (
	headKey = thor.Blake2b([]byte("head"))
	tailKey = thor.Blake2b([]byte("tail"))
)

// NetPermission implements native methods of 'NetPermission' contract.
type NetPermission struct {
	addr  thor.Address
	state *state.State
}

// Create a new instance.
func New(addr thor.Address, state *state.State) *NetPermission {
	return &NetPermission{addr, state}
}

// Get netpermission info by nodeAddr(convert from node publickey)
func (p *NetPermission) Get(nodeAddr thor.Address) (listed bool, prev thor.Address, next thor.Address, err error) {
	listed, err = p.inList(nodeAddr)

	if err != nil {
		return
	}

	entry, err := p.getEntry(nodeAddr)

	if err != nil {
		return
	}

	return listed, *entry.Prev, *entry.Next, nil
}

// Add a new netpermission
func (p *NetPermission) Add(nodeAddr thor.Address) (bool, error) {
	listed, err := p.inList(nodeAddr)
	if err != nil {
		return false, err
	}

	if listed {
		return false, nil
	}

	var tailPtr *thor.Address
	if tailPtr, err = p.getNodeAddrPtr(tailKey); err != nil {
		return false, err
	}

	var newEntry *Permissionentry
	newEntry.Prev = tailPtr

	p.setNodeAddrPtr(tailKey, &nodeAddr)
	if tailPtr == nil {
		p.setNodeAddrPtr(headKey, &nodeAddr)
	} else {
		var tailEntry *Permissionentry
		if tailEntry, err = p.getEntry(*tailPtr); err != nil {
			return false, err
		}
		tailEntry.Next = &nodeAddr
		p.setEntry(tailEntry)
	}
	p.setEntry(newEntry)
	return true, nil
}

// Revoke nodeAddr from netpermission list
// The entry is not removed, but set unlisted.
func (p *NetPermission) Revoke(nodeAddr thor.Address) (bool, error) {
	listed, err := p.inList(nodeAddr)
	if err != nil {
		return false, err
	}

	if listed {
		return false, nil
	}

	entry, err := p.getEntry(nodeAddr)
	if err != nil {
		return false, err
	}

	if entry.Prev == nil {
		if err := p.setNodeAddrPtr(headKey, entry.Next); err != nil {
			return false, err
		}
	} else {
		prevEntry, err := p.getEntry(*entry.Prev)
		if err != nil {
			return false, err
		}
		prevEntry.Next = entry.Next
		if err := p.setEntry(prevEntry); err != nil {
			return false, err
		}
	}

	if entry.Next == nil {
		if err := p.setNodeAddrPtr(tailKey, entry.Prev); err != nil {
			return false, err
		}
	} else {
		nextEntry, err := p.getEntry(*entry.Next)
		if err != nil {
			return false, err
		}
		nextEntry.Prev = entry.Prev
		if err := p.setEntry(nextEntry); err != nil {
			return false, err
		}
	}

	entry.Prev = nil
	entry.Next = nil

	if err := p.setEntry(entry); err != nil {
		return false, err
	}
	return true, nil
}

// Get the first nodeAddr info.
func (p *NetPermission) First() (nodeAddr *thor.Address, prev *thor.Address, next *thor.Address, err error) {
	if nodeAddr, err = p.getNodeAddrPtr(headKey); err != nil {
		return nil, nil, nil, err
	}
	var entry *Permissionentry
	if entry, err = p.getEntry(*nodeAddr); err != nil {
		return nil, nil, nil, err
	}
	return &entry.NodeAddr, entry.Prev, entry.Next, nil
}

func (p *NetPermission) getEntry(nodeAddr thor.Address) (*Permissionentry, error) {
	var entry Permissionentry
	if err := p.state.DecodeStorage(p.addr, thor.BytesToBytes32(nodeAddr[:]), func(raw []byte) error {
		if raw == nil || len(raw) == 0 {
			return nil
		}
		return rlp.DecodeBytes(raw, &entry)
	}); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (p *NetPermission) setEntry(entry *Permissionentry) error {
	return p.state.EncodeStorage(p.addr, thor.BytesToBytes32(entry.NodeAddr[:]), func() ([]byte, error) {
		if entry.IsEmpty() {
			return nil, nil
		}
		return rlp.EncodeToBytes(entry)
	})
}

func (p *NetPermission) getNodeAddrPtr(key thor.Bytes32) (nodeAddr *thor.Address, err error) {
	err = p.state.DecodeStorage(p.addr, key, func(raw []byte) error {
		if raw == nil || len(raw) == 0 {
			return nil
		}
		return rlp.DecodeBytes(raw, &nodeAddr)
	})
	return
}

func (p *NetPermission) setNodeAddrPtr(key thor.Bytes32, nodeAddr *thor.Address) error {
	return p.state.EncodeStorage(p.addr, key, func() ([]byte, error) {
		if nodeAddr == nil {
			return nil, nil
		}
		return rlp.EncodeToBytes(nodeAddr)
	})
}

func (p *NetPermission) inList(nodeAddr thor.Address) (listed bool, err error) {
	var entry *Permissionentry
	if entry, err = p.getEntry(nodeAddr); err != nil {
		return false, err
	}

	if entry.IsLinked() {
		return true, nil
	}

	// if it's the only node, IsLinked will be false.
	// check whether it's the head.
	var ptr *thor.Address
	if ptr, err = p.getNodeAddrPtr(headKey); err != nil {
		return false, err
	}

	if ptr != nil && *ptr == nodeAddr {
		return true, nil
	}

	return false, nil
}
