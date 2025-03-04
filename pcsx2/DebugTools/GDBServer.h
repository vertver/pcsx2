/*  PCSX2 - PS2 Emulator for PCs
 *  Copyright (C) 2002-2023  PCSX2 Dev Team
 *
 *  PCSX2 is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU Lesser General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  PCSX2 is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE.  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with PCSX2.
 *  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once 
#include "DebugServer.h"

class GDBServer final : public DebugServerInterface
{
public:
	GDBServer(DebugInterface* debugInterface);
	~GDBServer();

	bool replyPacket(void* outData, std::size_t& outSize) override;
	std::size_t processPacket(const char* inData, std::size_t inSize, void* outData, std::size_t& outSize) override;

private:
	void resumeExecution();
	void stopExecution();
	void singleStep();
	bool addBreakpoint(u32 address);
	bool removeBreakpoint(u32 address);
	void updateThreadList();
	void generateThreadListString();

private:
	u32 getRegisterSize(int id);
	bool readRegister(int threadId, int id, u32& value);
	bool writeRegister(int threadId, int id, u32 value);

private:
	bool readMemory(u32 address, u32 size);
	bool writeMemory(u32 address, u32 size);

private:
	bool writePacketBegin();
	bool writePacketEnd();
	bool writePacketData(const char* data, std::size_t size);

	bool writeBaseResponse(std::string_view data);
	bool writeThreadId(int threadId, int processId = 1);
	bool writeRegisterValue(int threadId, int registerNumber);
	bool writeAllRegisterValues(int threadId);
	bool writePaged(std::size_t offset, std::size_t length, const std::string_view& string);

private:
	bool processXferPacket(std::string_view data);
	bool processQueryPacket(std::string_view data);
	bool processGeneralQueryPacket(std::string_view data);
	bool processMultiletterPacket(std::string_view data);
	bool processThreadPacket(std::string_view data);

private:
	int m_stateThreadCounter = -1;
	std::vector<std::unique_ptr<BiosThread>> m_stateThreads;
	std::string m_threadListString;

	void* m_outData;
	std::size_t* m_outSize;

	bool m_waitingForTrap = false;
	bool m_multiprocess = false;
	bool m_eventsEnabled = false;
	bool m_dontReplyAck = false;
};