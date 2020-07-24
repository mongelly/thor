// Copyright (c) 2020 The VeChainThor developers

// Distributed under the GNU Lesser General Public License v3.0 software license, see the accompanying
// file LICENSE or <https://www.gnu.org/licenses/lgpl-3.0.html>

package netpermission

import (
	"github.com/vechain/thor/thor"
)

type Permissionentry struct {
	NodeAddr thor.Address
	Prev     *thor.Address `rlp:"nil"`
	Next     *thor.Address `rlp:"nil"`
}

func (p *Permissionentry) IsEmpty() bool {
	return p.NodeAddr.IsZero() && p.Prev == nil && p.Next == nil
}

func (p *Permissionentry) IsLinked() bool {
	return p.Prev != nil || p.Next != nil
}
