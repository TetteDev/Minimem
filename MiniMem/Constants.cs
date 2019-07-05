using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MiniMem
{
	public class Constants
	{
		public enum MemoryType : uint
		{
			RT_REL_ADDRESS = 0x0,
			RT_ADDRESS = 0x1,
			RT_LOCATION = 0x2,

			RT_READNEXT4_BYTES = 0x3,
			RT_READNEXT4_BYTES_RAW = 0x4,
		}

		public class HandleInformation
		{
			public SYSTEM_HANDLE_INFORMATION Advanced;
			public string HandleName;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct SYSTEM_HANDLE_INFORMATION
		{
			// Information Class 16
			public int ProcessID;

			public byte ObjectTypeNumber;
			public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
			public ushort Handle;
			public int Object_Pointer;
			public uint GrantedAccess;
		}

		[Flags]
		public enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VMOperation = 0x00000008,
			VMRead = 0x00000010,
			VMWrite = 0x00000020,
			DupHandle = 0x00000040,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			Synchronize = 0x00100000
		}

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct UNICODE_STRING
		{
			public ushort Length;
			public ushort MaximumLength;
			public IntPtr Buffer;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct GENERIC_MAPPING
		{
			public int GenericRead;
			public int GenericWrite;
			public int GenericExecute;
			public int GenericAll;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct OBJECT_BASIC_INFORMATION
		{
			// Information Class 0
			public int Attributes;

			public int GrantedAccess;
			public int HandleCount;
			public int PointerCount;
			public int PagedPoolUsage;
			public int NonPagedPoolUsage;
			public int Reserved1;
			public int Reserved2;
			public int Reserved3;
			public int NameInformationLength;
			public int TypeInformationLength;
			public int SecurityDescriptorLength;
			public FILETIME CreateTime;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct OBJECT_NAME_INFORMATION
		{
			// Information Class 1
			public UNICODE_STRING Name;
		}

		public enum ObjectInformationClass
		{
			ObjectBasicInformation = 0,
			ObjectNameInformation = 1,
			ObjectTypeInformation = 2,
			ObjectAllTypesInformation = 3,
			ObjectHandleInformation = 4
		}

		public struct MEMORY_BASIC_INFORMATION32
		{
			public UIntPtr BaseAddress;
			public UIntPtr AllocationBase;
			public uint AllocationProtect;
			public uint RegionSize;
			public uint State;
			public uint Protect;
			public uint Type;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct OBJECT_TYPE_INFORMATION
		{
			// Information Class 2
			public UNICODE_STRING Name;

			public int ObjectCount;
			public int HandleCount;
			public int Reserved1;
			public int Reserved2;
			public int Reserved3;
			public int Reserved4;
			public int PeakObjectCount;
			public int PeakHandleCount;
			public int Reserved5;
			public int Reserved6;
			public int Reserved7;
			public int Reserved8;
			public int InvalidAttributes;
			public GENERIC_MAPPING GenericMapping;
			public int ValidAccess;
			public byte Unknown;
			public byte MaintainHandleDatabase;
			public int PoolType;
			public int PagedPoolUsage;
			public int NonPagedPoolUsage;
		}

		public struct MemoryRegionResult
		{
			public UIntPtr CurrentBaseAddress { get; set; }
			public long RegionSize { get; set; }
			public UIntPtr RegionBase { get; set; }

		}

		public class MultiAobResultItem
		{
			public string Identifier = "NO_IDENTIFIER_PROVIDED";
			public string Pattern = "";
			public long FirstResultAsLong = 0;
			public string FirstResultAsHexString = "";
			public List<long> Results;
		}

		public class MultiAobItem // Used internally for method 'MultiAobScan'
		{
			public string OptionalIdentifier = "NO_IDENTIFIER_PROVIDED";

			public string ArrayOfBytesString;
			public byte[] Pattern;
			public byte[] Mask;
		}

		public const int DUPLICATE_SAME_ACCESS = 0x2;
		public const int DUPLICATE_CLOSE_SOURCE = 0x1;
		public const int MAX_PATH = 260;

		public const int CNST_SYSTEM_HANDLE_INFORMATION = 16;
		public const uint STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

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
			public uint pageSize;
			public UIntPtr minimumApplicationAddress;
			public UIntPtr maximumApplicationAddress;
			public IntPtr activeProcessorMask;
			public uint numberOfProcessors;
			public uint processorType;
			public uint allocationGranularity;
			public ushort processorLevel;
			public ushort processorRevision;
		}

		public enum ReturnType : uint
		{
			ADDRESS = 0x0,
			READ4BYTES = 0x1,
			READ8BYTES = 0x2,
		}

		public class Signature
		{
			public Signature(string name, Byte[] pattern)
			{
				Name = name;
				Pattern = pattern;
			}

			public Signature(string name, string pattern, long optionalOffsetResult = 0, bool optionalResultAbsolute = false, ReturnType returnType = ReturnType.ADDRESS)
			{
				Name = name;
				Pattern = Helper.Transform(pattern);
				FoundResults = new List<long>();

				ResultOffsettedBy = optionalOffsetResult;
				ResultIsAbsoluteToModuleBase = optionalResultAbsolute;
				ReturnType = returnType;
			}

			public string Name { get; private set; }
			public Byte[] Pattern { get; private set; }

			public ReturnType ReturnType { get; private set; } = ReturnType.ADDRESS;
			public List<long> FoundResults;
			public long ResultOffsettedBy = 0;
			public bool ResultIsAbsoluteToModuleBase = false;

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
			public IntPtr Pointer;
			public uint Size;

			public uint ProtectionFlags;
			public uint AllocationFlags;

			/// <summary>
			/// Frees the memory accociated with this object
			/// </summary>
			/// <returns></returns>
			public bool ReleaseMemory()
			{
				return MiniMem.FreeMemory(Pointer, Size);
			}

			/// <summary>
			/// Checks if the allocated memory of this object is valid or not
			/// </summary>
			/// <returns></returns>
			public bool IsValid()
			{
				return Pointer != IntPtr.Zero
				       && Size > 0;
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

			public void Restore()
			{
				if (OriginalBytes != null && OriginalBytes.Length > 0)
				{
					if (SuspendNeeded)
					{
						// Suspend
						try
						{
							MiniMem.SuspendProcess();
							var suspendFlag = true;
							MiniMem.WriteBytes(TrampolineOrigin, OriginalBytes);

							if (suspendFlag && SuspendNeeded)
							{
								MiniMem.ResumeProcess();
							}
						}
						catch
						{
							MiniMem.WriteBytes(TrampolineOrigin, OriginalBytes);
						}
						
					}
					else
					{
						MiniMem.WriteBytes(TrampolineOrigin, OriginalBytes);
					}
				}

					
				AllocatedMemory?.ReleaseMemory();	
			}
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
		public struct RegistersOld
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

			public float XMM0; // 0x32
			public float XMM1; // 0x36
			public float XMM2; // 0x40
			public float XMM3; // 0x44
			public float XMM4; // 0x48
			public float XMM5; // 0x52
			public float XMM6; // 0x56
			public float XMM7; // 0x60
		}
	}
}
