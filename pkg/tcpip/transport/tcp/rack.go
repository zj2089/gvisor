// Copyright 2020 The gVisor Authors.
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

package tcp

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// RACK is a loss detection algorithm used in TCP to detect packet loss and
// reordering using transmission timestamp of the packets instead of packet or
// sequence counts. To use RACK, SACK should be enabled on the connection.

// rackControl stores the rack related fields.
// +stateify savable
type rackControl struct {
	// TODO: Store the pointer to the segment instead of xmitTime and
	// endSequence after creating a new list.
	// xmitTime is the transmission timestamp of a packet which has been
	// acknowledged most recently including retransmissions.
	xmitTime int64

	// endSequence is the sequence number of the packet which has been
	// acknowledged most recently including retransmissions.
	endSequence seqnum.Value

	// fack is the highest sequence number of the packet which has been
	// acknowledged till now.
	fack seqnum.Value

	// rtt is the round trip time of the packet.
	rtt time.Duration

	// reord indicates if packet reordering is detected.
	reord bool
}

// Update will update the RACK related fields when an ACK has been received.
func (rc *rackControl) Update(seg *segment, srtt time.Duration, tsEnabled bool) {
	rtt := time.Now().Sub(seg.xmitTime)
	segXmit := seg.xmitTime.Unix()

	// If the ACK is for a retransmitted packet, do not update if it is a
	// spurious inference which is determined by below checks:
	// 1. When TSecr option is avaliable, if the TSVal is less than the
	// transmit time of the most recent retransmitted packet.
	// 2. When rtt calculated for the packet is less than the smoothed rtt
	// for the connection.
	if seg.xmitCount > 1 {
		if tsEnabled && seg.parsedOptions.TSEcr != 0 {
			// TSVal/Ecr values sent by Netstack are at a millisecond
			// granularity.
			if int64(seg.parsedOptions.TSVal) < segXmit {
				return
			}
		}
		if rtt < srtt {
			return
		}
	}

	rc.rtt = rtt
	// Update rc.xmitTime and sequence number to the trasmit time and
	// sequence number of the packet which has been acknowledged most
	// recently.
	if segXmit > rc.xmitTime || (segXmit == rc.xmitTime && seg.sequenceNumber > rc.endSequence) {
		rc.xmitTime = segXmit
		rc.endSequence = seg.sequenceNumber
	}
}

// DetectReorder will set rc.reord if reordering is detected when an ACK has
// been received.
func (rc *rackControl) DetectReorder(seg *segment) {
	if seg.sequenceNumber > rc.fack {
		rc.fack = seg.sequenceNumber
	} else if seg.sequenceNumber < rc.fack && seg.xmitCount > 1 {
		rc.reord = true
	}

	// TODO: Check if the segment is retransmitted and covered by DSACK
	// option to set the reord to true.
}
