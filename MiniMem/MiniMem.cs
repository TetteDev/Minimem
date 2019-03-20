using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static MiniMem.Native;
using static MiniMem.Constants;
using static MiniMem.Helper;
using Byte = MiniMem.Constants.Byte;
using Binarysharp.Assemblers.Fasm;
using static MiniMem.Threads;

namespace MiniMem
{
    public class MiniMem
    {
	    public class AttachedProcess
	    {
		    public static Process ProcessObject = null;
		    public static IntPtr ProcessHandle = IntPtr.Zero;

		    public static void UpdateInformation()
		    {
			    if (!Process.GetProcesses().ToList().Contains(ProcessObject)) return;
			    Process newObject = Process.GetProcesses().ToList().FirstOrDefault(x => x == ProcessObject);
			    ProcessObject = newObject;
		    }
		    public static bool Is64Bit()
		    {
			    if (ProcessHandle == IntPtr.Zero) return false;
			    return Environment.Is64BitOperatingSystem && (IsWow64Process(ProcessHandle, out bool retVal) && !retVal);
		    }
			public static bool IsAttached()
		    {
			    return ProcessHandle != IntPtr.Zero &&
			           ProcessObject != null;
		    }
		    internal static void Detach()
		    {
			    try
			    {
				    CloseHandle(ProcessHandle);
				    ProcessHandle = IntPtr.Zero;
				    ProcessObject = null;
			    }
			    catch
			    {
				    Debug.WriteLine("[WARNING] Detach might have failed");
			    }
		    }
	    }
		public static List<TrampolineInstance> ActiveTrampolines = new List<TrampolineInstance>();
		public static List<CallbackObject> ActiveCallbacks = new List<CallbackObject>();

		#region Attaching/Detaching
		public static bool Attach(int processId)
	    {
		    AttachedProcess.ProcessHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, processId);
		    Process first = Process.GetProcessById(processId);
		    AttachedProcess.ProcessObject = first;
		    return AttachedProcess.ProcessHandle != IntPtr.Zero;
	    }
	    public static bool Attach(string processName)
	    {
		    try
		    {
			    Process first = Process.GetProcesses().FirstOrDefault(x => x.ProcessName.ToLower().Contains(processName.ToLower()));
			    if (first == default(Process)) return false;
			    AttachedProcess.ProcessObject = first;
			    AttachedProcess.ProcessHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, first.Id);
			    return AttachedProcess.ProcessHandle != IntPtr.Zero;
		    }
		    catch
		    {
			    AttachedProcess.ProcessHandle = IntPtr.Zero;
			    AttachedProcess.ProcessObject = null;
			    return false;
		    }
	    }
	    public static void Detach()
	    {
		    AttachedProcess.Detach();
	    }
		#endregion

		#region ValueFreezer
		public static void StartFreezer()
	    {
		    if (Freezer.flagThreadIsRunning) return;
		    Thread freezeThread = new Thread(Freezer.FreezeLoop);
			freezeThread.Start();
	    }
	    public static void StopFreezer()
	    {
		    if (!Freezer.flagThreadIsRunning) return;

		    Freezer.flagTerminateThread = true;
	    }
	    public static void AddFreezeValue(long address, string identifier, string valuetype, object value)
	    {
		    FreezeItem fr = new FreezeItem()
		    {
			    Address = address,
			    Identifier = identifier,
			    ValueType = valuetype,
			    Value = value
		    };

		    if (!Freezer.FreezeCollection.Contains(fr))
		    {
			    Freezer.FreezeCollection.Add(fr);
		    }
		    else
		    {
			    FreezeItem existing = Freezer.FreezeCollection.FirstOrDefault(x => x.Identifier == identifier);
			    if (existing == null)
			    {
				    Freezer.FreezeCollection.Add(fr);
			    }
			    else
			    {
				    if (existing.Value == value) return;
				    Freezer.FreezeCollection.Remove(existing); // Remove old
				    Freezer.FreezeCollection.Add(fr); // Add new
			    }
		    }
	    }
	    public static async Task RemoveFreezeValue(string identifier, int maxRetries = 5)
	    {
		    FreezeItem found = Freezer.FreezeCollection.FirstOrDefault(x => x.Identifier == identifier);
		    if (found == null) return;

		    int retriesDone = 0;
		    try
		    {
			    while (retriesDone < maxRetries)
			    {
				    if (!Freezer.FreezeCollection.Remove(found))
				    {
					    await Task.Delay(250);
				    }
				    else
				    {
						Debug.WriteLine("Successfully removed item with identifier '" + identifier + "' from freezelist!");
					    break;
				    }
				    retriesDone++;
			    }
		    }
		    catch
		    {
			    Debug.WriteLine("Failed " + maxRetries + " time(s) to remove item from list!");
		    }
	    }
	    #endregion

		#region Pattern Scanner
		private static string Format(string pattern)
		{
			var length = pattern.Length;
			var result = new StringBuilder(length);
			for (var i = 0; i < length; i++)
			{
				var ch = pattern[i];
				if (ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'F' || ch >= 'a' && ch <= 'f' || ch == '?')
					result.Append(ch);
			}
			return result.ToString();
		}
		private static int hexChToInt(char ch)
		{
			if (ch >= '0' && ch <= '9')
				return ch - '0';
			if (ch >= 'A' && ch <= 'F')
				return ch - 'A' + 10;
			if (ch >= 'a' && ch <= 'f')
				return ch - 'a' + 10;
			return -1;
		}
		private static bool matchByte(byte b, ref Byte p)
		{
			if (!p.N1.Wildcard) //if not a wildcard we need to compare the data.
			{
				var n1 = b >> 4;
				if (n1 != p.N1.Data) //if the data is not equal b doesn't match p.
					return false;
			}
			if (!p.N2.Wildcard) //if not a wildcard we need to compare the data.
			{
				var n2 = b & 0xF;
				if (n2 != p.N2.Data) //if the data is not equal b doesn't match p.
					return false;
			}
			return true;
		}

		public static Byte[] Transform(string pattern)
		{
			pattern = Format(pattern);
			var length = pattern.Length;
			if (length == 0)
				return null;
			var result = new List<Byte>((length + 1) / 2);
			if (length % 2 != 0)
			{
				pattern += "?";
				length++;
			}
			var newbyte = new Byte();
			for (int i = 0, j = 0; i < length; i++)
			{
				var ch = pattern[i];
				if (ch == '?') //wildcard
				{
					if (j == 0)
						newbyte.N1.Wildcard = true;
					else
						newbyte.N2.Wildcard = true;
				}
				else //hex
				{
					if (j == 0)
					{
						newbyte.N1.Wildcard = false;
						newbyte.N1.Data = (byte)(hexChToInt(ch) & 0xF);
					}
					else
					{
						newbyte.N2.Wildcard = false;
						newbyte.N2.Data = (byte)(hexChToInt(ch) & 0xF);
					}
				}

				j++;
				if (j == 2)
				{
					j = 0;
					result.Add(newbyte);
				}
			}
			return result.ToArray();
		}
		private static bool Find(byte[] data, Byte[] pattern, out long offsetFound, long offset = 0)
		{
			offsetFound = -1;
			if (data == null || pattern == null)
				return false;
			var patternSize = pattern.LongLength;
			if (data.LongLength == 0 || patternSize == 0)
				return false;

			for (long i = offset, pos = 0; i < data.LongLength; i++)
			{
				if (matchByte(data[i], ref pattern[pos])) //check if the current data byte matches the current pattern byte
				{
					pos++;
					if (pos != patternSize) continue;
					offsetFound = i - patternSize + 1;
					return true;
				}
				else //fix by Computer_Angel
				{
					i -= pos;
					pos = 0; //reset current pattern position
				}
			}

			return false;
		}

		#region Main Methods for scanning multiple patterns
		/*
		* var signatures = new[]
		{
			new Signature("pattern1", "456?89?B"),
			new Signature("pattern2", "1111111111"),
			new Signature("pattern3", "AB??EF"),
		};

		var result = FindPattern(data, signatures);
		OR
		var result = FindPattern("modulename", signatures);
		foreach (var signature in result)
			Console.WriteLine("Found signature {0} at {1}", signature.Name, signature.FoundOffset);
		*/
		public static Signature[] FindPattern(byte[] buffer, Signature[] signatures, bool useParallel = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var found = new ConcurrentBag<Signature>();
			if (useParallel)
			{
				Parallel.ForEach(signatures, signature =>
				{
					if (Find(buffer, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					if (Find(buffer, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				}
			}

			return found.ToArray();
		}
		public static Signature[] FindPattern(string moduleName, Signature[] signatures, bool useParallel = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			ProcessModule pm = null;
			if (moduleName == "base" || moduleName == "main")
			{
				pm = AttachedProcess.ProcessObject.MainModule;
			}
			else
			{
				foreach (ProcessModule procModule in AttachedProcess.ProcessObject.Modules)
				{
					if (procModule.ModuleName != moduleName && !procModule.ModuleName.Contains(moduleName)) continue;
					pm = procModule;
					break;
				}
			}

			if (pm == null) throw new ArgumentException("Cannot find any module with the name '" + moduleName + "'");
			byte[] buffer = new byte[pm.ModuleMemorySize];
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)pm.BaseAddress, buffer, buffer.Length, ref m_iNumberOfBytesRead);

			var found = new ConcurrentBag<Signature>();
			if (useParallel)
			{
				Parallel.ForEach(signatures, signature =>
				{
					if (Find(buffer, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					if (Find(buffer, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				}
			}

			return found.ToArray();
		}
		public static Signature[] FindPattern(long startAddress, long endAddress, Signature[] signatures, bool useParallel = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			byte[] buff = new byte[endAddress - startAddress];
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)startAddress, buff, buff.Length, ref m_iNumberOfBytesRead);

			var found = new ConcurrentBag<Signature>();
			if (useParallel)
			{
				Parallel.ForEach(signatures, signature =>
				{
					if (Find(buff, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					if (Find(buff, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				}
			}

			return found.ToArray();
		}
		#endregion

	    public static IntPtr FindPatternSingle(byte[] buffer, string pattern, int refBufferStartAddress = 0)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
		    if (buffer.Length < 1 || String.IsNullOrEmpty(pattern)) return IntPtr.Zero;
		    var list = new List<byte>();
		    var list2 = new List<bool>();
		    var array = pattern.Split(' ');

		    var num = 0;
		    if (0 < array.Length)
			    do
			    {
				    var text = array[num];
				    if (!String.IsNullOrEmpty(text))
					    if (!(text == "?") && !(text == "??"))
					    {
						    byte b;
						    if (!System.Byte.TryParse(text, NumberStyles.HexNumber, CultureInfo.CurrentCulture, out b))
							    break;
						    list.Add(Convert.ToByte(text, 16));
						    list2.Add(true);
					    }
					    else
					    {
						    list.Add(0);
						    list2.Add(false);
					    }
				    num++;
			    } while (num < array.Length);
		    var count = list.Count;
		    var num2 = buffer.Length - count;
		    var num3 = 0;
		    if (0 < num2)
		    {
			    for (; ; )
			    {
				    var num4 = 0;
				    if (0 >= count)
					    break;
				    while (!list2[num4] || list[num4] == buffer[num4 + num3])
				    {
					    num4++;
					    if (num4 >= count)
						    return new IntPtr(refBufferStartAddress + num3);
				    }
				    num3++;
				    if (num3 >= num2)
					    return IntPtr.Zero;
			    }
			    return new IntPtr(refBufferStartAddress + num3);
		    }
		    return IntPtr.Zero;
	    }
	    public static IntPtr FindPatternSingle(ProcModule processModule, string pattern, bool resultAbsolute = true)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (processModule == null) return IntPtr.Zero;
		    if (resultAbsolute)
		    {
			    return String.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(processModule.BaseAddress.ToInt64(), (int) processModule.Size), pattern, processModule.BaseAddress.ToInt32());
		    }
			return String.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(processModule.BaseAddress.ToInt64(), (int)processModule.Size), pattern, 0);
		}
	    public static IntPtr FindPatternSingle(long startAddress, long endAddress, string pattern, bool resultAbsolute = true)
	    {
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (startAddress > endAddress) return IntPtr.Zero;
		    long size = endAddress - startAddress;

		    if (resultAbsolute)
		    {
			    return String.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(startAddress, (int) size), pattern, (int) startAddress);
		    }
		    return String.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(startAddress, (int)size), pattern, 0);

		}
		#endregion

		#region Byte Array Patching
	    public static bool Patch(long targetInstructionAddress, int targetInstructionByteCount, string[] mnemnoics)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) return false;
		    if (mnemnoics.Length < 1) return false;
		    List<byte> patchBytes = Assemble(mnemnoics).ToList();

		    int nopsNeeded = 0;
		    if (targetInstructionByteCount > patchBytes.Count)
		    {
			    nopsNeeded = targetInstructionByteCount - patchBytes.Count;
		    }
		    else
		    {
			    throw new Exception("Target instruction byte count must be atleast as big as the amount of bytes you inject!");
		    }

		    if (nopsNeeded > 0)
		    {
			    for (int nopCount = 0; nopCount < nopsNeeded; nopCount++)
			    {
				    patchBytes.Add(0x90);
			    }
		    }

			WriteBytes(targetInstructionAddress, patchBytes.ToArray());
		    return ReadBytes(targetInstructionAddress, targetInstructionByteCount) == patchBytes.ToArray();
			// return true;
	    }
	    public static bool Patch(long targetInstructionAddress, int targetInstructionByteCount, byte[] bytes)
	    {
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) return false;
		    if (bytes.Length < 1) return false;

		    int nopsNeeded = 0;
		    if (targetInstructionByteCount > bytes.Length)
		    {
			    nopsNeeded = targetInstructionByteCount - bytes.Length;
		    }
		    else
		    {
			    throw new Exception("Target instruction byte count must be atleast as big as the amount of bytes you inject!");
		    }

		    List<byte> patchBytes = bytes.ToList();
		    if (nopsNeeded > 0)
		    {
			    for (int nopCount = 0; nopCount < nopsNeeded; nopCount++)
			    {
				    patchBytes.Add(0x90);
			    }
		    }

		    WriteBytes(targetInstructionAddress, patchBytes.ToArray());
		    return ReadBytes(targetInstructionAddress, targetInstructionByteCount) == patchBytes.ToArray();
		}
		#endregion

		#region Read Methods
		public static byte[] ReadBytes(long address, int byteCount)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var buffer = new byte[byteCount];
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, byteCount, ref m_iNumberOfBytesRead);
			return buffer;
		}
		public static string ReadString(long address, Encoding defaultEncoding = default(Encoding), int maxLength = 256, bool zeroTerminated = false)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (defaultEncoding == null) defaultEncoding = Encoding.UTF8;
			var buff = new byte[maxLength];
			var numBytesRead = 0;
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buff, buff.Length, ref numBytesRead);
			return zeroTerminated ? defaultEncoding.GetString(buff).Split('\0')[0] : Encoding.UTF8.GetString(buff);
		}
		public static T ReadMultiLevelPointer<T>(long baseAddress, params int[] offsets) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (offsets.Length == 0) return ReadMemory<T>(baseAddress);
			var temp = ReadMemory<IntPtr>(baseAddress);
			for (int i = 0; i < offsets.Length - 1; i++)
			{
				temp = ReadMemory<IntPtr>((int)temp + offsets[i]);
			}
			return ReadMemory<T>((int)temp + (int)offsets[offsets.Length - 1]);
		}
		public static T ReadMemory<T>(long address) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var ByteSize = Marshal.SizeOf(typeof(T));
			var buffer = new byte[ByteSize];
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, ref m_iNumberOfBytesRead);
			return ByteArrayToStructure<T>(buffer);
		}
		public static T ReadMemoryProtected<T>(long address) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(typeof(T)), 0x40, out var oldProtection);
			var buffer = new byte[Marshal.SizeOf(typeof(T))];
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, ref m_iNumberOfBytesRead);
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(typeof(T)), oldProtection, out oldProtection);
			return ByteArrayToStructure<T>(buffer);
		}
		#endregion

		#region Write Methods
		public static void WriteBytes(long address, byte[] buffer)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
		}
		public static void WriteString(long address, string value, Encoding defaultEncoding = default(Encoding))
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (value.Length < 1) return;
			if (defaultEncoding == null) defaultEncoding = Encoding.UTF8;
			var memory = new byte[value.Length];
			memory = defaultEncoding.GetBytes(value);
			WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, memory, memory.Length, out var numBytesRead);
		}
		public static void WriteMemoryProtected<T>(long address, object value) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(value), 0x40, out var oldProtection);
			var buffer = StructureToByteArray(value);
			WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(value), oldProtection, out oldProtection);
		}
		public static void WriteMultiLevelPointer<T>(long baseAddress, object value, params int[] offsets) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (offsets.Length == 0)
			{
				WriteMemory<T>(baseAddress, value);
			}
			else
			{
				IntPtr final = ReadMultiLevelPointer<IntPtr>(baseAddress, offsets);
				WriteMemory<T>((int)final, value);
			}
		}
		public static void WriteMemory<T>(long address, object value) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var buffer = StructureToByteArray(value);
			WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
		}
		#endregion

		#region Detouring 
		// Pass this object to your thread
	    public static CallbackObject CreateCallback(TrampolineInstance trampolineInstance, string identifier = "")
	    {
		    if (trampolineInstance == null) return null;
		    if (trampolineInstance.optionalHitCounterPointer == IntPtr.Zero)
		    {
#if DEBUG
			    Console.WriteLine(
				    "Tried registering a callback on a callback object with a null pointer as the hitcounter pointer!\n");
#endif

			    return new CallbackObject
			    {
				    ptr_HitCounter = IntPtr.Zero,
				    class_TrampolineInfo = trampolineInstance,
				    str_CallbackIdentifier = identifier,
			    };
			}

		    return new CallbackObject
		    {
			    ptr_HitCounter = trampolineInstance.optionalHitCounterPointer,
				class_TrampolineInfo = trampolineInstance,
				str_CallbackIdentifier = identifier,
		    };
	    }
	    public static TrampolineInstance CreateTrampolineInstance(long targetInstructionAddress, int instructionCount/*, string[] mnemonics*/, bool shouldSuspend = true, bool preserveOriginalInstruction = true, bool implementCallback = true)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) return null;
			if (instructionCount < 5)
			{
				throw new Exception("Target Instruction bytes must be atleast 5 bytes!");
			}

			bool IsSuspended = false;
			byte[] nopBytes = new byte[] { };
			if (instructionCount > 5)
			{
				var nopsNeeded = instructionCount - 5; // 5 == E9 XX XX XX XX (JMP instruction to 4byte offset from origin)
				nopBytes = new byte[nopsNeeded];
				for (int iNopIdx = 0; iNopIdx < nopsNeeded; iNopIdx++)
				{
					nopBytes[iNopIdx] = 0x90; // Append NOP
				}
			}

			RemoteAllocatedMemory memoryRegion = AllocateMemory(0x10000, MemoryProtection.ExecuteReadWrite, AllocationType.Commit | AllocationType.Reserve);
			if (memoryRegion.Pointer == IntPtr.Zero) throw new Exception("VirtualAllocEx failed allocating memory for the codecave!");
			TrampolineInstance newInstance = new TrampolineInstance();

			RemoteAllocatedMemory registerStructMemory = AllocateMemory(32, MemoryProtection.ExecuteReadWrite, AllocationType.Commit | AllocationType.Reserve);
			if (memoryRegion.Pointer == IntPtr.Zero) throw new Exception("VirtualAllocEx failed allocating memory for the register struct");
		    RemoteAllocatedMemory hitCounter = null;

			if (implementCallback)
		    {
				hitCounter = AllocateMemory(sizeof(uint), MemoryProtection.ExecuteReadWrite, AllocationType.Commit | AllocationType.Reserve);
			    if (hitCounter.Pointer == IntPtr.Zero) throw new Exception("VirtualAllocEx failed allocating memory for the hitcounter address");
			    WriteMemory<uint>(hitCounter.Pointer.ToInt64(), 0);
			}
				
			
			List<byte> JMPInBytes = new List<byte> { 0xE9 };
			// Relative JMP
			JMPInBytes.AddRange(BitConverter.GetBytes((memoryRegion.Pointer.ToInt32() - (int)targetInstructionAddress) - 5)); // DEST - ORIGIN = Offset to codecave
			if (nopBytes.Length > 0)
			{
				JMPInBytes.AddRange(nopBytes);
			}

			newInstance.AllocatedMemory = memoryRegion;
			newInstance.OriginalBytes = ReadBytes(targetInstructionAddress, instructionCount);
			newInstance.NewBytes = JMPInBytes.ToArray();
			newInstance.TrampolineOrigin = targetInstructionAddress;
			newInstance.TrampolineDestination = memoryRegion.Pointer.ToInt32();
			newInstance.SuspendNeeded = true;

			if (shouldSuspend)
			{
				SuspendProcess();
				IsSuspended = true;
			}

			WriteBytes(targetInstructionAddress, JMPInBytes.ToArray());
		    int jumpOutInstructionLocation = memoryRegion.Pointer.ToInt32();
			byte[] codecaveBytes = { };
			try
			{
				if (implementCallback)
				{
					codecaveBytes = FasmNet.Assemble(new[]
					{
						"use32",
						$"mov [{registerStructMemory.Pointer}],eax",
						$"mov [{registerStructMemory.Pointer + 4}],ebx",
						$"mov [{registerStructMemory.Pointer + 8}],ecx",
						$"mov [{registerStructMemory.Pointer + 12}],edx",
						$"mov [{registerStructMemory.Pointer + 16}],edi",
						$"mov [{registerStructMemory.Pointer + 20}],esi",
						$"mov [{registerStructMemory.Pointer + 24}],ebp",
						$"mov [{registerStructMemory.Pointer + 28}],esp",
						$"inc dword [{hitCounter.Pointer}]", // Increase our hitcounter value by 1
					});
				}
				else
				{
					codecaveBytes = FasmNet.Assemble(new[]
					{
						"use32",
						$"mov [{registerStructMemory.Pointer}],eax",
						$"mov [{registerStructMemory.Pointer + 4}],ebx",
						$"mov [{registerStructMemory.Pointer + 8}],ecx",
						$"mov [{registerStructMemory.Pointer + 12}],edx",
						$"mov [{registerStructMemory.Pointer + 16}],edi",
						$"mov [{registerStructMemory.Pointer + 20}],esi",
						$"mov [{registerStructMemory.Pointer + 24}],ebp",
						$"mov [{registerStructMemory.Pointer + 28}],esp",
					});
				}
				
			}
			catch (FasmAssemblerException fex)
			{
				// We fucked up so lets restore the overwritten bytes
				WriteBytes(targetInstructionAddress, newInstance.OriginalBytes);
				if (IsSuspended)
					ResumeProcess();
				throw new Exception("Invalid mnemonics!");
			}

		    if (preserveOriginalInstruction && newInstance.OriginalBytes.Length > 0)
		    {
			    WriteBytes(memoryRegion.Pointer.ToInt64(), newInstance.OriginalBytes);
			    jumpOutInstructionLocation += newInstance.OriginalBytes.Length;
		    }

			if (codecaveBytes != null && codecaveBytes.Length > 0)
			{
				WriteBytes(jumpOutInstructionLocation, codecaveBytes);
				jumpOutInstructionLocation += codecaveBytes.Length;
			}
			
			newInstance.TrampolineJmpOutAddress = jumpOutInstructionLocation;
			int relativeJumpBackOutAddress = jumpOutInstructionLocation > (int)targetInstructionAddress ? (int)targetInstructionAddress - jumpOutInstructionLocation : jumpOutInstructionLocation - (int)targetInstructionAddress;
			newInstance.TrampolineJmpOutDestination = relativeJumpBackOutAddress + nopBytes.Length;

		    newInstance.optionalHitCounterPointer = implementCallback && hitCounter.Pointer != IntPtr.Zero ? hitCounter.Pointer : IntPtr.Zero;
		    newInstance.optionalRegisterStructPointer = registerStructMemory.Pointer;

			List<byte> JMPOutBytes = new List<byte> { 0xE9 };
			JMPOutBytes.AddRange(BitConverter.GetBytes(relativeJumpBackOutAddress + nopBytes.Length));
			WriteBytes(jumpOutInstructionLocation, JMPOutBytes.ToArray());

			if (IsSuspended)
				ResumeProcess();

		    return newInstance;
	    }
		#endregion

		#region FASM
		public static byte[] Assemble(string mnemonics)
	    {
		    return FasmNet.Assemble(mnemonics);
	    }
	    public static byte[] Assemble(string[] mnemonics)
	    {
		    return FasmNet.Assemble(mnemonics);
	    }
	    public static bool TryAssemble(string[] mnemonics, out byte[] assembled)
	    {
		    try
		    {
			    byte[] t = Assemble(mnemonics);
			    assembled = t;
			    return true;
		    }
		    catch
		    {
			    assembled = null;
			    return false;
		    }
	    }
		#endregion

		#region Suspend Process
		public static void SuspendProcess()
	    {
		    var process = AttachedProcess.ProcessObject;

		    if (process.ProcessName == String.Empty)
			    return;

		    foreach (ProcessThread pT in process.Threads)
		    {
			    IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

			    if (pOpenThread == IntPtr.Zero)
			    {
				    continue;
			    }

			    SuspendThread(pOpenThread);

			    CloseHandle(pOpenThread);
		    }
		}
	    public static void ResumeProcess()
	    {
		    var process = AttachedProcess.ProcessObject;

		    if (process.ProcessName == String.Empty)
			    return;

		    foreach (ProcessThread pT in process.Threads)
		    {
			    IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

			    if (pOpenThread == IntPtr.Zero)
			    {
				    continue;
			    }

			    var suspendCount = 0;
			    do
			    {
				    suspendCount = ResumeThread(pOpenThread);
			    } while (suspendCount > 0);

			    CloseHandle(pOpenThread);
		    }
	    }
		#endregion

		#region Allocate Memory 
	    public static IntPtr AllocateMemory(uint size, uint protectionFlags, uint allocationFlags)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			return VirtualAllocEx(AttachedProcess.ProcessHandle, IntPtr.Zero, new IntPtr(size), allocationFlags, protectionFlags);
		}
	    public static RemoteAllocatedMemory AllocateMemory(int size, MemoryProtection protectionFlags, AllocationType allocationFlags)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			IntPtr alloc = VirtualAllocEx(AttachedProcess.ProcessHandle, IntPtr.Zero, new IntPtr(size), (uint) allocationFlags, (uint) protectionFlags);
		    if (alloc == IntPtr.Zero) return null;
		    RemoteAllocatedMemory ret = new RemoteAllocatedMemory
		    {
			    AllocationFlags = (uint) allocationFlags,
			    ProtectionFlags = (uint) protectionFlags,
			    Pointer = alloc,
			    Size = size
		    };
		    return ret;
	    }

	    public static bool FreeMemory(RemoteAllocatedMemory memoryItem)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			try
		    {
			    return VirtualFreeEx(AttachedProcess.ProcessHandle, memoryItem.Pointer, memoryItem.Size, 0x8000);
		    }
		    catch
		    {
			    return false;
		    }
	    }
	    public static void FreeMemory(IntPtr lpBase, int size)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			VirtualFreeEx(AttachedProcess.ProcessHandle, lpBase, size, 0x8000);
	    }
		#endregion

		#region Modules
	    public static ProcModule FindProcessModule(string name, bool exactMatch = true)
	    {
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
		    if (String.IsNullOrEmpty(name)) return null;
		    AttachedProcess.UpdateInformation();
			foreach (ProcessModule pm in AttachedProcess.ProcessObject.Modules)
		    {
			    if (exactMatch)
			    {
				    if (pm.ModuleName.ToLower() == name)
				    {
						ProcModule ret = new ProcModule();
					    ret.Size = (uint)pm.ModuleMemorySize;
					    ret.BaseAddress = pm.BaseAddress;
					    ret.EndAddress = new IntPtr(ret.BaseAddress.ToInt32() + ret.Size);
					    ret.EntryPointAddress = pm.EntryPointAddress;
					    ret.BaseName = pm.ModuleName;
					    ret.FileName = pm.FileName;

					    return ret;
					}
			    }
			    else
			    {
				    if (pm.ModuleName.ToLower().Contains(name.ToLower()))
				    {
						ProcModule ret = new ProcModule();
					    ret.Size = (uint)pm.ModuleMemorySize;
					    ret.BaseAddress = pm.BaseAddress;
					    ret.EndAddress = new IntPtr(ret.BaseAddress.ToInt32() + ret.Size);
					    ret.EntryPointAddress = pm.EntryPointAddress;
					    ret.BaseName = pm.ModuleName;
					    ret.FileName = pm.FileName;

					    return ret;
					}
			    }
		    }
		    return null;
	    }
		#endregion

		#region Logging
	    public static void Log(string message,MessageType messageType = MessageType.INFO, bool writeToDebug = true, bool writeToFile = false)
	    {
		    if (String.IsNullOrEmpty(message)) return;
		    ConsoleColor clr = ConsoleColor.White;

		    switch (messageType)
		    {
				case MessageType.DEFAULT:
					clr = ConsoleColor.White;
					break;
				case MessageType.INFO:
					clr = ConsoleColor.Green;
					break;
				case MessageType.WARNING:
					clr = ConsoleColor.Yellow;
					break;
				case MessageType.ERROR:
					clr = ConsoleColor.Red;
					break;
		    }

		    string formattedMessage =
			    $"[{messageType.ToString().ToUpper()}][{DateTime.Now.ToShortTimeString()}] {message}";

		    Console.ForegroundColor = clr;
			Console.WriteLine(formattedMessage);
			if (writeToDebug)
				Debug.WriteLine(formattedMessage);
		    if (writeToFile)
		    {
			    try
			    {
				    File.AppendAllLines("logs.txt", new[] { Environment.NewLine + formattedMessage });
			    }
			    catch
			    {
				    Console.ResetColor();
					Log("Failed writing logs to textfile!", MessageType.ERROR);
				    return;
			    }
		    }
			Console.ResetColor();
	    }

		#endregion

		#region Misc
	    public static void PrintProperties<T>(T myObj, bool isAddresses = true)
	    {
		    foreach (var prop in myObj.GetType().GetProperties())
		    {
			    Console.WriteLine(prop.Name + ": " + prop.GetValue(myObj, null));
		    }

		    foreach (var field in myObj.GetType().GetFields())
		    {
			    if (isAddresses)
			    {
				    Console.WriteLine(field.Name + ": 0x" + ((int)field.GetValue(myObj)).ToString("X"));
			    }
			    else
			    {
				    Console.WriteLine(field.Name + ": " + field.GetValue(myObj));
			    }
		    }
	    }
		public static int GetOffset<T>(T structObject, string offsetname)
		{
			if (structObject == null) throw new NullReferenceException(nameof(structObject) + " was null!");

			IntPtr tmp = Marshal.OffsetOf(typeof(T), offsetname);

			return Marshal.OffsetOf(typeof(T), offsetname).ToInt32();
		}
	    #endregion
    }
}
