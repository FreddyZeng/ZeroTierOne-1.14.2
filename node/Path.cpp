/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#include "Path.hpp"
#include "RuntimeEnvironment.hpp"
#include "Node.hpp"
#include "Topology.hpp"
#include "Peer.hpp"


namespace ZeroTier {

bool Path::send(const RuntimeEnvironment *RR,void *tPtr,const void *data,unsigned int len,int64_t now,Packet::Verb verb)
{
	const SharedPtr<Peer> peer(RR->topology->getPeerNoCache(peerAddress()));

	if (peer) {
		if (needsHeartbeat(now) && alive(now)) {
			if ((now - _lastOut > 3000) || _lastOut == 0) {
				_lastOut = now;
				peer->attemptToContactAt(tPtr,_localSocket,_addr,now,false);
			}
		} else if (!alive(now)) {
			if ((now - _lastOut > 3000) || _lastOut == 0) {
				_lastOut = now;
				peer->sendHELLO(tPtr,_localSocket,_addr,now);
			}
		}
	}
	
	// 根据这个path是否是tcp ok创建的,如果是就需要强制执行tcp的路径转发
	if (RR->node->putPacket(tPtr,_localSocket,_addr,data,len,0,verb)) {
		_lastOut = now;
		return true;
	}
	return false;
}

} // namespace ZeroTier
