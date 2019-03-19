using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MiniMem
{
	public class Constants
	{

		public delegate void CallbackDelegate(object passedObject);

		public const int PROCESS_VM_OPERATION = 0x0008;
		public const int PROCESS_VM_READ = 0x0010;
		public const int PROCESS_VM_WRITE = 0x0020;

		public static int m_iNumberOfBytesRead;
		public static int m_iNumberOfBytesWritten;

		public enum MessageType
		{
			DEFAULT = 0,
			INFO = 1,
			WARNING = 2,
			ERROR = 3,
		}

		[Flags]
		public enum ThreadAccess : int
		{
			TERMINATE = (0x0001),
			SUSPEND_RESUME = (0x0002),
			GET_CONTEXT = (0x0008),
			SET_CONTEXT = (0x0010),
			SET_INFORMATION = (0x0020),
			QUERY_INFORMATION = (0x0040),
			SET_THREAD_TOKEN = (0x0080),
			IMPERSONATE = (0x0100),
			DIRECT_IMPERSONATION = (0x0200)
		}

		[Flags]
		public enum AllocationType : uint
		{
			Commit = 0x1000,
			Reserve = 0x2000,
			Decommit = 0x4000,
			Release = 0x8000,
			Reset = 0x80000,
			Physical = 0x400000,
			TopDown = 0x100000,
			WriteWatch = 0x200000,
			LargePages = 0x20000000
		}

		[Flags]
		public enum MemoryProtection : uint
		{
			Execute = 0x10,
			ExecuteRead = 0x20,
			ExecuteReadWrite = 0x40,
			ExecuteWriteCopy = 0x80,
			NoAccess = 0x01,
			ReadOnly = 0x02,
			ReadWrite = 0x04,
			WriteCopy = 0x08,
			GuardModifierflag = 0x100,
			NoCacheModifierflag = 0x200,
			WriteCombineModifierflag = 0x400
		}

		[Flags]
		public enum ThreadCreationFlags : uint
		{
			StackSizeParamIsAReservation = 65536u,
			Suspended = 4u,
			Run = 0u
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct MEMORY_BASIC_INFORMATION64
		{
			public ulong BaseAddress;
			public ulong AllocationBase;
			public int AllocationProtect;
			public int __alignment1;
			public ulong RegionSize;
			public int State;
			public int Protect;
			public int Type;
			public int __alignment2;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct MEMORY_BASIC_INFORMATION
		{
			public IntPtr BaseAddress;
			public IntPtr AllocationBase;
			public uint AllocationProtect;
			public IntPtr RegionSize;
			public uint State;
			public uint Protect;
			public uint Type;
		}

		public struct SYSTEM_INFO
		{
			public ushort processorArchitecture;
			ushort reserved;
			public int pageSize;
			public IntPtr minimumApplicationAddress;
			public IntPtr maximumApplicationAddress;
			public IntPtr activeProcessorMask;
			public uint numberOfProcessors;
			public uint processorType;
			public int allocationGranularity;
			public ushort processorLevel;
			public ushort processorRevision;
		}

		public class Signature
		{
			public Signature(string name, Byte[] pattern)
			{
				Name = name;
				Pattern = pattern;
				FoundOffset = -1;
			}

			public Signature(string name, string pattern)
			{
				Name = name;
				Pattern = MiniMem.Transform(pattern);
				FoundOffset = -1;
			}

			public string Name { get; private set; }
			public Byte[] Pattern { get; private set; }
			public long FoundOffset;

			public override string ToString()
			{
				return Name;
			}
		}
		public struct Byte
		{
			public struct Nibble
			{
				public bool Wildcard;
				public byte Data;
			}

			public Nibble N1;
			public Nibble N2;
		}

		public class RemoteAllocatedMemory
		{
			private Dictionary<string, int> m_allocated = new Dictionary<string, int>();
			private uint m_currentOffset = 0;

			public IntPtr Pointer;
			public int Size;

			public uint ProtectionFlags;
			public uint AllocationFlags;


			public IntPtr AllocateOfChunk<T>(string name)
			{
				return AllocateOfChunk(name, Helper.MarshalCache<T>.Size);
			}
			public IntPtr AllocateOfChunk(string name, int size)
			{
				uint currentOffset = this.m_currentOffset;
				m_allocated.Add(name, (int)currentOffset);
				int num = size + (int)m_currentOffset;
				m_currentOffset = (uint)num;
				int num2 = num % 4;
				if (num2 != 0)
				{
					m_currentOffset = (uint)num - (uint)num2 + 4;
				}
				return new IntPtr(Pointer.ToInt32() + currentOffset);
			}
		}

		public class CallbackObject
		{
			public IntPtr ptr_HitCounter = IntPtr.Zero;
			public TrampolineInstance class_TrampolineInfo;
			public string str_CallbackIdentifier = "";

			public uint LastValue = 0;
			public CallbackDelegate ObjectCallback;
		}

		public class TrampolineInstance
		{
			public RemoteAllocatedMemory AllocatedMemory;

			public string Identifier = "";

			public long TrampolineOrigin = -1;
			public long TrampolineDestination = -1;

			public IntPtr optionalHitCounterPointer = IntPtr.Zero;
			public IntPtr optionalRegisterStructPointer = IntPtr.Zero;

			public long TrampolineJmpOutAddress = -1;
			public long TrampolineJmpOutDestination = -1;
			public byte[] OriginalBytes = null;
			public byte[] NewBytes = null;

			public bool SuspendNeeded = false;
		}

		public class ProcModule
		{
			public IntPtr BaseAddress;
			public IntPtr EndAddress;
			public IntPtr EntryPointAddress;

			public string BaseName;
			public uint Size;
			public string FileName;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct Registers
		{
			public int EAX; // 0x0
			public int EBX; // 0x4
			public int ECX; // 0x8
			public int EDX; // 0x12
			public int EDI; // 0x16
			public int ESI; // 0x20
			public int EBP; // 0x24
			public int ESP; // 0x28
		}

		//public class FreezeItem<T> where T : struct
		public class FreezeItem
		{
			public long Address = default(long);
			public string Identifier = default(string);

			public string ValueType = null;
			public object Value = null;

			public bool IsValid()
			{
				return Address != default(long) &&
				       Identifier != default(string) &&
				       Value != null &&
				       ValueType != null;
			}
		}
	}
}
