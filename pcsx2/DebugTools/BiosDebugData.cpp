// SPDX-FileCopyrightText: 2002-2023 PCSX2 Dev Team
// SPDX-License-Identifier: LGPL-3.0+

#include "BiosDebugData.h"
#include "IopMem.h"
#include "Memory.h"


std::vector<BiosThread> getEEThreads()
{
	std::vector<BiosThread> threads;

	if (CurrentBiosInformation.eeThreadListAddr <= 0)
		return threads;

	const u32 start = CurrentBiosInformation.eeThreadListAddr & 0x3fffff;

	for (int tid = 0; tid < 256; tid++)
	{
		EEInternalThread* internal = static_cast<EEInternalThread*>(PSM(start + tid * sizeof(EEInternalThread)));
		if (internal->status != (int)ThreadStatus::THS_BAD)
		{
			threads.emplace_back(EEThread(tid, *internal));
		}
	}

	return threads;
}

std::vector<BiosThread> getIOPThreads()
{
	std::vector<BiosThread> threads;

	if (CurrentBiosInformation.iopThreadListAddr <= 0)
		return threads;

	u32 item = iopMemRead32(CurrentBiosInformation.iopThreadListAddr);

	while (item != 0)
	{
		IOPInternalThread data{};

		u16 tag = iopMemRead16(item + 0x8);
		if (tag != 0x7f01)
		{
			// something went wrong
			return {};
		}

		data.stackTop = iopMemRead32(item + 0x3c);
		data.status = iopMemRead8(item + 0xc);
		data.tid = iopMemRead16(item + 0xa);
		data.entrypoint = iopMemRead32(item + 0x38);
		data.waitstate = iopMemRead16(item + 0xe);
		data.initPriority = iopMemRead16(item + 0x2e);

		data.SavedSP = iopMemRead32(item + 0x10);

		data.PC = iopMemRead32(data.SavedSP + 0x8c);
		threads.emplace_back(IOPThread(data));

		item = iopMemRead32(item + 0x24);
	}


	return threads;
}
