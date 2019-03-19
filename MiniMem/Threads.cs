using System;
using System.Runtime.InteropServices;
using System.Threading;
using Binarysharp.Assemblers.Fasm;
using Mem = MiniMem.MiniMem;

namespace MiniMem
{
	public static class Threads
	{
		public static IntPtr ExecuteCode(string[] mnemonics)
		{
			if (Mem.AttachedProcess.ProcessHandle == IntPtr.Zero) return IntPtr.Zero;
			if (mnemonics.Length < 1) return IntPtr.Zero;

			byte[] assembled = Mem.Assemble(mnemonics);
			Constants.RemoteAllocatedMemory alloc = Mem.AllocateMemory(assembled.Length, Constants.MemoryProtection.ExecuteReadWrite, Constants.AllocationType.Commit);
			Constants.RemoteAllocatedMemory returnvalue = Mem.AllocateMemory(4, Constants.MemoryProtection.ExecuteReadWrite, Constants.AllocationType.Commit);
			Mem.WriteBytes(alloc.Pointer.ToInt32(), assembled);
			IntPtr hThread = Native.CreateRemoteThread(MiniMem.AttachedProcess.ProcessHandle,
				IntPtr.Zero,
				IntPtr.Zero,
				alloc.Pointer,
				IntPtr.Zero /* LP PARAMETER  */,
				(uint)Constants.ThreadCreationFlags.Run,
				IntPtr.Zero);
			Native.WaitForSingleObject(hThread, 0xFFFFFFFF);

			Native.CloseHandle(hThread);
			Mem.FreeMemory(alloc);

			return Mem.ReadMemory<IntPtr>(returnvalue.Pointer.ToInt64());
		}

		public static void ExecuteCode(string[] mnemonics, Constants.RemoteAllocatedMemory region)
		{
			if (Mem.AttachedProcess.ProcessHandle == IntPtr.Zero) return;
			if (mnemonics.Length < 1) return;
			if (region.Pointer == IntPtr.Zero) return;

			Constants.ProcModule pm = Mem.FindProcessModule("game.bin", false);

			// Sit down function
			IntPtr fnAddress = IntPtr.Add(pm.BaseAddress, 0x3A0330);

			byte[] assembled = Mem.Assemble(new []
			{
				"use32",
				"push 00",
				"push 00",
				"push 04",
				$"mov ecx,{fnAddress}",
				"call ecx",
				"add dword esp,0x0C",
				"ret"
			});

			Mem.WriteBytes(region.Pointer.ToInt32(), assembled);
			IntPtr hThread = Native.CreateRemoteThread(MiniMem.AttachedProcess.ProcessHandle,
				IntPtr.Zero,
				IntPtr.Zero,
				region.Pointer,
				IntPtr.Zero /* LP PARAMETER  */,
				(uint)Constants.ThreadCreationFlags.Run,
				IntPtr.Zero);

			if (hThread == IntPtr.Zero) return;
			Native.WaitForSingleObject(hThread, 0xFFFFFFFF);

			Native.CloseHandle(hThread);
			Mem.FreeMemory(region);
		}
	}
}
