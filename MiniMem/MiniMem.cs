using Binarysharp.Assemblers.Fasm;
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
using static MiniMem.Constants;
using static MiniMem.Helper;
using static MiniMem.Native;

namespace MiniMem
{
	public class MiniMem
    {
	    public static List<CallbackObject> ActiveCallbacks = new List<CallbackObject>();
	    public static Thread CallbackThread = null;

		public class AttachedProcess
	    {
		    public static Process ProcessObject = null;
		    public static IntPtr ProcessHandle = IntPtr.Zero;

		    public static void UpdateInformation()
		    {
			    if (AttachedProcess.ProcessHandle == IntPtr.Zero || AttachedProcess.ProcessObject == null) return;

			    int id = AttachedProcess.ProcessObject.Id;
			    Process pObject = Process.GetProcesses().FirstOrDefault(x => x.Id == id);
			    ProcessObject = pObject != default(Process) ? pObject : null;

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
		    public static bool IsRunning()
		    {
			    if (ProcessHandle == IntPtr.Zero || ProcessObject == null) return false;
			    //UpdateInformation();
			    return Process.GetProcesses().FirstOrDefault(x => x.Id == ProcessObject.Id) != default(Process);
		    }
		    public static List<ProcessModule> ProcessModules()
		    {
				UpdateInformation();
			    return ProcessObject.Modules.Cast<ProcessModule>().ToList();
		    }
		    public static List<SYSTEM_HANDLE_INFORMATION> GetOpenedHandlesByProcess(string IN_strObjectTypeName = null, string IN_strObjectName = null, bool verbose = false)
		    {
				if (ProcessObject == null) return new List<SYSTEM_HANDLE_INFORMATION>();

			    uint nStatus;
			    var nHandleInfoSize = 0x10000;
			    var ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
			    var nLength = 0;
			    var ipHandle = IntPtr.Zero;

			    while ((nStatus = NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ipHandlePointer,
				           nHandleInfoSize, ref nLength)) ==
			           STATUS_INFO_LENGTH_MISMATCH)
			    {
				    nHandleInfoSize = nLength;
				    Marshal.FreeHGlobal(ipHandlePointer);
				    ipHandlePointer = Marshal.AllocHGlobal(nLength);
			    }

			    var baTemp = new byte[nLength];
			    Marshal.Copy(ipHandlePointer, baTemp, 0, nLength);

			    long lHandleCount = 0;
			    if (Is64Bits())
			    {
				    lHandleCount = Marshal.ReadInt64(ipHandlePointer);
				    ipHandle = new IntPtr(ipHandlePointer.ToInt64() + 8);
			    }
			    else
			    {
				    lHandleCount = Marshal.ReadInt32(ipHandlePointer);
				    ipHandle = new IntPtr(ipHandlePointer.ToInt32() + 4);
			    }

			    SYSTEM_HANDLE_INFORMATION shHandle;
			    var lstHandles = new List<SYSTEM_HANDLE_INFORMATION>();

			    for (long lIndex = 0; lIndex < lHandleCount; lIndex++)
			    {
				    shHandle = new SYSTEM_HANDLE_INFORMATION();
				    if (Is64Bits())
				    {
					    shHandle = (SYSTEM_HANDLE_INFORMATION) Marshal.PtrToStructure(ipHandle, shHandle.GetType());
					    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
				    }
				    else
				    {
					    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
					    shHandle = (SYSTEM_HANDLE_INFORMATION) Marshal.PtrToStructure(ipHandle, shHandle.GetType());
				    }

				    if (ProcessObject != null)
					    if (shHandle.ProcessID != ProcessObject.Id) continue;

				    if (IN_strObjectTypeName != null)
				    {
					    var strObjectTypeName = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
					    if (strObjectTypeName != IN_strObjectTypeName) continue;
				    }

				    var strObjectName = "";
				    if (IN_strObjectName != null)
				    {
					    strObjectName = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
					    if (strObjectName != IN_strObjectName) continue;
				    }
				    else if (IN_strObjectName == null || IN_strObjectName == "")
				    {
					    strObjectName = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
				    }

				    var strObjectTypeName2 = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
				    var strObjectName2 = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
				    if (verbose)
					    Console.WriteLine("{0}   {1}   {2}", shHandle.ProcessID, strObjectTypeName2, strObjectName2);

				    lstHandles.Add(shHandle);
			    }
			    return lstHandles;

		    }

		    /// <summary>
		    /// Internal method for detaching from the currently attached process
		    /// </summary>
		    /// <param name="clearCallbacks">If set to true, all detours will be cleared and restored upon detaching</param>
		    /// <returns></returns>
			public static void Detach(bool clearCallbacks = true)
		    {
			    try
			    {
				    IntPtr backup = ProcessHandle;
				    bCallbackThreadExitFlag = true;
				    if (CallbackThread.Join(5000))
				    {
					    bCallbackThreadExitFlag = false;
					    Log("Callback thread aborted successfully!");
					}
				    else
				    {
					    Debug.WriteLine("Callback thread did not .Join() within the set time span (5000 ms)");
				    }
				    
				    ProcessObject = null;

				    if (clearCallbacks)
				    {
					    for (int i = ActiveCallbacks.Count - 1; i >= 0; i--)
					    {
							ActiveCallbacks[i].class_TrampolineInfo.Restore();
						    ActiveCallbacks.Remove(ActiveCallbacks[i]);
					    }
				    }

				    ProcessHandle = IntPtr.Zero;
					if (backup != IntPtr.Zero)
					    CloseHandle(backup);
					Debug.WriteLine("Detach routine finished and callback thread has been aborted!");
			    }
			    catch
			    {
				    Debug.WriteLine("[WARNING] Detach might have failed");
			    }
		    }
	    }

		#region Attaching/Detaching

		/// <summary>
		/// Attaches to a remote process
		/// </summary>
		/// <param name="processId">The target process process id</param>
		/// <returns>bool</returns>
		public static bool Attach(int processId)
	    {
		    try
		    {
			    AttachedProcess.ProcessHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, processId);
			    Process first = Process.GetProcessById(processId);
			    AttachedProcess.ProcessObject = first;
			    return AttachedProcess.ProcessHandle != IntPtr.Zero;
		    }
		    finally
		    {
			    if (AttachedProcess.ProcessHandle != IntPtr.Zero)
			    {
				    CallbackThread = new Thread(CallbackLoop);
				    CallbackThread.Start();
				}
					
		    }
		   
	    }

		/// <summary>
		/// Attaches to a remote process
		/// </summary>
		/// <param name="processName">The target process name</param>
		/// <returns>bool</returns>
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
		    finally
		    {
				if (AttachedProcess.ProcessHandle != IntPtr.Zero)
				{
					CallbackThread = new Thread(CallbackLoop);
					CallbackThread.Start();
				}
			}
	    }

		/// <summary>
		/// Detaches from the currently attached process
		/// </summary>
		/// <param name="clearCallbacks">If set to true, all detours will be cleared and restored upon detaching</param>
		/// <returns></returns>
		public static void Detach(bool clearCallbacks = true)
	    {
		    AttachedProcess.Detach(clearCallbacks);
	    }

		#endregion

		#region Pattern Scanner
		#region Main Methods for scanning multiple patterns
		public static Signature[] FindPatternMultiple(byte[] buffer, Signature[] signatures, bool useParallel = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var found = new ConcurrentBag<Signature>();
			if (useParallel)
			{
				Parallel.ForEach(signatures, signature =>
				{
					if (Helper.Find(buffer, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					if (Helper.Find(buffer, signature.Pattern, out signature.FoundOffset))
						found.Add(signature);
				}
			}

			return found.ToArray();
		}
		public static Signature[] FindPatternMultiple(string moduleName, Signature[] signatures, bool useParallel = true)
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
		public static Signature[] FindPatternMultiple(long startAddress, long endAddress, Signature[] signatures, bool useParallel = true)
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

		/// <summary>
		/// Searches byte[] for a sequence of bytes
		/// </summary>
		/// <param name="buffer">The buffer to search through</param>
		/// /// <param name="pattern">The IDA styled pattern</param>
		/// /// <param name="refBufferStartAddress">None</param>
		/// <returns>IntPtr</returns>
		public static IntPtr FindPatternSingle(byte[] buffer, string pattern, int refBufferStartAddress = 0)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
		    if (buffer.Length < 1 || string.IsNullOrEmpty(pattern)) return IntPtr.Zero;
		    var list = new List<byte>();
		    var list2 = new List<bool>();
		    var array = pattern.Split(' ');

		    var num = 0;
		    if (0 < array.Length)
			    do
			    {
				    var text = array[num];
				    if (!String.IsNullOrEmpty(text))
					    if (text != "?" && text != "??")
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

		/// <summary>
		/// Searches byte[] for a sequence of bytes
		/// </summary>
		/// <param name="processModule">ProcModule instance containing the start and end region for the desired process module</param>
		/// /// <param name="pattern">The IDA styled pattern</param>
		/// /// <param name="resultAbsolute">None</param>
		/// <returns>IntPtr</returns>
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

		/// <summary>
		/// Searches byte[] for a sequence of bytes
		/// </summary>
		/// <param name="startAddress">The address to start the search from</param>
		/// /// <param name="endAddress">The address where to end the search</param>
		/// /// /// <param name="pattern">The IDA styled pattern</param>
		/// /// <param name="resultAbsolute">None</param>
		/// <returns>IntPtr</returns>
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
		/// <summary>
		/// Reads n amount of bytes from the remote process
		/// </summary>
		/// <param name="address">Start address where to read the bytes from</param>
		/// <param name="byteCount">Amount of bytes to read</param>
		/// <returns>byte[]</returns>
		public static byte[] ReadBytes(long address, int byteCount)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var buffer = new byte[byteCount];
			ReadProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, byteCount, ref m_iNumberOfBytesRead);
			return buffer;
		}

		/// <summary>
		/// Read a string from memory
		/// </summary>
		/// <param name="address">Start address where to read the string from</param>
		/// <param name="defaultEncoding">Which encoding to use</param>
		/// <param name="maxLength">Cuts the string this amount of characters</param>
		/// <param name="zeroTerminated">Stops the read at the first occurence of a null char</param>
		/// <returns>string</returns>
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

		/// <summary>
		/// Use Marshalling to read any value type from memory
		/// </summary>
		/// <param name="address">Start address where to read the bytes from that will then be marshalled into the type T</param>
		/// <returns>T</returns>
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
		/// <summary>
		/// Write byte[] to a specific address
		/// </summary>
		/// <param name="address">The address to write the bytes to</param>
		/// <param name="buffer">Byte array containing the bytes to write to the desired address</param>
		/// <returns>bool</returns>
		public static bool WriteBytes(long address, byte[] buffer)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			return WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
		}

		/// <summary>
		/// Writes string to a desired address in memory
		/// </summary>
		/// <param name="address">The address to write the string to</param>
		/// <param name="value">The string you want to write</param>
		/// <param name="defaultEncoding">The encoding to use</param>
		/// <returns>bool</returns>
		public static bool WriteString(long address, string value, Encoding defaultEncoding = default(Encoding))
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (value.Length < 1) return false;
			if (defaultEncoding == null) defaultEncoding = Encoding.UTF8;
			var memory = new byte[value.Length];
			memory = defaultEncoding.GetBytes(value);
			return WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, memory, memory.Length, out var numBytesRead);
		}

		public static void WriteMemoryProtected<T>(long address, object value) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(value), 0x40, out var oldProtection);
			var buffer = StructureToByteArray(value);
			WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(value), oldProtection, out oldProtection);
		}
		public static bool WriteMultiLevelPointer<T>(long baseAddress, object value, params int[] offsets) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (offsets.Length == 0)
			{
				WriteMemory<T>(baseAddress, value);
			}
			else
			{
				IntPtr final = ReadMultiLevelPointer<IntPtr>(baseAddress, offsets);
				return WriteMemory<T>((int)final, value);
			}
			return false;
		}

		/// <summary>
		/// Use Marshalling to write any value type to memory
		/// </summary>
		/// <param name="address">Start address where to write the bytes from that will then be marshalled into the type T</param>
		/// <param name="value">The value of type T to write</param>
		/// <returns>bool</returns>
		public static bool WriteMemory<T>(long address, object value) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var buffer = StructureToByteArray(value);
			return WriteProcessMemory((int)AttachedProcess.ProcessHandle, (int)address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
		}
		#endregion

		#region Detouring 
		/// <summary>
		/// Creates a basic trampoline/jmp detour at a desired address/instruction
		/// </summary>
		/// <param name="targetInstructionAddress">The address where to place the initial jmp</param>
		/// <param name="instructionCount">The amount of bytes you're over writing at the target address</param>
		/// <param name="mnemonics">The valid 32bit Flat assembler mnemonics to write into our code cave</param>
		/// <param name="shouldSuspend">Wether or not the program should suspend the remote process during the procedure</param>
		/// <param name="preserveOriginalInstruction">If the original overwritten bytes should be prepended at the start of the code cave</param>
		/// <returns>TrampolineInstance</returns>
		public static TrampolineInstance CreateTrampoline(long targetInstructionAddress, int instructionCount, string[] mnemonics, bool shouldSuspend = true, bool preserveOriginalInstruction = true)
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
				codecaveBytes = FasmNet.Assemble(mnemonics);

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

		    newInstance.optionalHitCounterPointer = IntPtr.Zero;
		    newInstance.optionalRegisterStructPointer = IntPtr.Zero;

			List<byte> JMPOutBytes = new List<byte> { 0xE9 };
			JMPOutBytes.AddRange(BitConverter.GetBytes(relativeJumpBackOutAddress + nopBytes.Length));
			WriteBytes(jumpOutInstructionLocation, JMPOutBytes.ToArray());

			if (IsSuspended)
				ResumeProcess();

		    return newInstance;
	    }

	    public static TrampolineInstance CreateTrampoline64Bit(ulong targetInstructionAddress, int instructionCount, string[] mnemonics64bit, bool shouldSuspend = true, bool preserveOriginalInstruction = true)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) return null;
		    if (instructionCount < 10)
		    {
			    // We need atleast 10 bytes on 64bit
		    }

		    //if (!AttachedProcess.Is64Bit()) // Check if attached process is 64bit
			//    throw new Exception("ddd");

		    if (mnemonics64bit == null || mnemonics64bit.Length < 1)
			    return null;

		    List<string> modified;

		    if (!mnemonics64bit[0].ToLower().StartsWith("use64"))
		    {
			    modified = mnemonics64bit.ToList();
			    modified.Insert(0, "use64");

			    if (!TryAssemble(modified.ToArray(), out byte[] assembledResult)) // See if the provided mnemonics are valid 64bit mnemonics
				    return null; // Invalid 64bit mnemonics according to Flat Assembler
		    }
		    else
		    {
			    modified = mnemonics64bit.ToList();
			    if (!TryAssemble(modified.ToArray(), out byte[] assembledResult)) // See if the provided mnemonics are valid 64bit mnemonics
				    return null; // Invalid 64bit mnemonics according to Flat Assembler
			}

			// Already here add the jmp out instructions to our mnemonics
		    RemoteAllocatedMemory codeCave = AllocateMemory(0x10000);
			modified.InsertRange(mnemonics64bit.Length, new []
			{
				//$"jmp {targetInstructionAddress - (ulong)codeCave.Pointer.ToInt64() + (ulong)instructionCount}",
				$"mov rax,{targetInstructionAddress + (uint)instructionCount}",
				"jmp rax",
			});

		    int nopCount = instructionCount - 12;
		    bool DidSuspend = false;

		    byte[] originalOverwritenBytes = ReadBytes((long)targetInstructionAddress, instructionCount);

			// Calculate jump in offset
		    ulong jumpInOffset = (ulong)codeCave.Pointer.ToInt64() - targetInstructionAddress - 10;
			List<byte> jumpInBytes = new List<byte>(0xE9);
			jumpInBytes.AddRange(BitConverter.GetBytes(jumpInOffset));

		    if (nopCount > 0)
		    {
			    for (int iNopCount = 0; iNopCount < nopCount; iNopCount++)
			    {
				    jumpInBytes.Add(0x90);
			    }
		    }

		    if (shouldSuspend)
		    {
			    SuspendProcess();
			    DidSuspend = true;
		    }


		    byte[] buffer64BitShellcode = FasmNet.Assemble(modified.ToArray());

		    if (preserveOriginalInstruction)
		    {
			    WriteBytes(codeCave.Pointer.ToInt64(), originalOverwritenBytes);
			    WriteBytes(codeCave.Pointer.ToInt64() + originalOverwritenBytes.Length, buffer64BitShellcode);
		    }
		    else
		    {
				WriteBytes(codeCave.Pointer.ToInt64(), buffer64BitShellcode); // Write the contents of our shellcode buffer into the cave
			}

		    WriteBytes((long)targetInstructionAddress, jumpInBytes.ToArray());

		    if (shouldSuspend && DidSuspend)
		    {
			    ResumeProcess();
		    }

		    return new TrampolineInstance
		    {
			    AllocatedMemory = codeCave,
			    Identifier = "64bitsomething",
			    NewBytes = jumpInBytes.ToArray(),
			    optionalHitCounterPointer = IntPtr.Zero,
			    optionalRegisterStructPointer = IntPtr.Zero,
			    OriginalBytes = originalOverwritenBytes,
			    SuspendNeeded = shouldSuspend,
			    TrampolineDestination = preserveOriginalInstruction ? codeCave.Pointer.ToInt64() + originalOverwritenBytes.Length : codeCave.Pointer.ToInt64(),
			    TrampolineJmpOutDestination = (long)targetInstructionAddress + instructionCount,
			    TrampolineJmpOutAddress = 0, // ignore this
		    };
	    }

		public static bool CreateTrampolineAndCallback(IntPtr targetAddress, int targetAddressInstructionCount, string[] mnemonics, CallbackDelegate codeExecutedEventDelegate, out CallbackObject createdObject, string identifier = "", bool shouldSuspend = true, bool preserveOriginalInstruction = false, bool implementCallback = true, bool implementRegisterDump = true)
		{
			#region Function Specific Variables
			RemoteAllocatedMemory callbackPointer = null;
			RemoteAllocatedMemory registerStructurePointer = null;
			RemoteAllocatedMemory codeCavePointer = null;
			int incInstructionIndex = -1;
			int registerDumpInstructions = -1;
			int jmpInstructionNopBytesNeeded = 0;
			byte[] originalInstructionBytes = new byte[] { };
			bool didSuspend = false;
			#endregion

			#region Check - Attached to process
			if (!AttachedProcess.IsAttached())
			{
				// Not Attached to any process
				createdObject = null;
				return false;
			}
			#endregion
			#region Check - Initial mnemonics are valid

			if (mnemonics.Length < 1)
			{
				mnemonics = new [] { "use32", };
			}

			try
			{
				byte[] tmp = FasmNet.Assemble(mnemonics);
			}
			catch
			{
				// Passed mnemonics are not valid
				createdObject = null;
				return false;
			}
			#endregion
			#region Check - Have enough bytes to work with, also calculate nops needed

			if (targetAddressInstructionCount < 5)
			{
				createdObject = null;
				return false;
			}
			jmpInstructionNopBytesNeeded = targetAddressInstructionCount - 5;
			#endregion

			#region Modifying of passed mnemonics
			var baseMnemonics = mnemonics.ToList();

			if (implementCallback)
			{
				callbackPointer = AllocateMemory(4, MemoryProtection.ExecuteReadWrite, AllocationType.Commit | AllocationType.Reserve);
				if (callbackPointer.Pointer == IntPtr.Zero)
					throw new Exception("Failed allocating memory inside the process!\nTrampoline cannot be implemented!");

				if (baseMnemonics[baseMnemonics.Count - 1].ToLower().StartsWith("ret") || baseMnemonics[baseMnemonics.Count - 1].ToLower().StartsWith("retn"))
				{
					incInstructionIndex = baseMnemonics.Count - 1;
					baseMnemonics.Insert(incInstructionIndex, $"inc dword [{callbackPointer.Pointer}]"); // Insert "inc" instruction at the end of our mnemonics
				}
				else
				{
					incInstructionIndex = baseMnemonics.Count;
					baseMnemonics.Insert(incInstructionIndex, $"inc dword [{callbackPointer.Pointer}]"); // Insert "inc" instruction at the end of our mnemonics
				}

				WriteMemory<int>(callbackPointer.Pointer.ToInt64(), 0);
			}

			if (implementRegisterDump)
			{
				//                               8 32bit registers 4byte each OR sizeof(Registers)
				registerStructurePointer = AllocateMemory(32 /* 8 * 4 */, MemoryProtection.ExecuteReadWrite, AllocationType.Commit | AllocationType.Reserve);
				if (registerStructurePointer.Pointer == IntPtr.Zero)
					throw new Exception("Failed allocating memory inside the process!\nTrampoline cannot be implemented!");

				if (implementCallback && incInstructionIndex != -1)
				{
					// Place register dump mnemonics just before the index where the callback "inc" instruction is
					baseMnemonics.InsertRange(incInstructionIndex, new string[]
					{
						$"mov [{registerStructurePointer.Pointer}],eax",
						$"mov [{registerStructurePointer.Pointer + 4}],ebx",
						$"mov [{registerStructurePointer.Pointer + 8}],ecx",
						$"mov [{registerStructurePointer.Pointer + 12}],edx",
						$"mov [{registerStructurePointer.Pointer + 16}],edi",
						$"mov [{registerStructurePointer.Pointer + 20}],esi",
						$"mov [{registerStructurePointer.Pointer + 24}],ebp",
						$"mov [{registerStructurePointer.Pointer + 28}],esp",
					});
				}
				else if (implementCallback && incInstructionIndex == -1)
				{
					if (baseMnemonics[baseMnemonics.Count - 1].ToLower().StartsWith("ret") || baseMnemonics[baseMnemonics.Count - 1].ToLower().StartsWith("retn"))
					{
						baseMnemonics.InsertRange(baseMnemonics.Count - 1, new string[]
						{
							$"mov [{registerStructurePointer.Pointer}],eax",
							$"mov [{registerStructurePointer.Pointer + 4}],ebx",
							$"mov [{registerStructurePointer.Pointer + 8}],ecx",
							$"mov [{registerStructurePointer.Pointer + 12}],edx",
							$"mov [{registerStructurePointer.Pointer + 16}],edi",
							$"mov [{registerStructurePointer.Pointer + 20}],esi",
							$"mov [{registerStructurePointer.Pointer + 24}],ebp",
							$"mov [{registerStructurePointer.Pointer + 28}],esp",
						});
					}
					else
					{
						baseMnemonics.InsertRange(baseMnemonics.Count, new string[]
						{
							$"mov [{registerStructurePointer.Pointer}],eax",
							$"mov [{registerStructurePointer.Pointer + 4}],ebx",
							$"mov [{registerStructurePointer.Pointer + 8}],ecx",
							$"mov [{registerStructurePointer.Pointer + 12}],edx",
							$"mov [{registerStructurePointer.Pointer + 16}],edi",
							$"mov [{registerStructurePointer.Pointer + 20}],esi",
							$"mov [{registerStructurePointer.Pointer + 24}],ebp",
							$"mov [{registerStructurePointer.Pointer + 28}],esp",
						});
					}

				}
			}
			#endregion

			#region Implementing the actual trampoline
			originalInstructionBytes = ReadBytes(targetAddress.ToInt64(), targetAddressInstructionCount);
			
			codeCavePointer = AllocateMemory(0x10000, MemoryProtection.ExecuteReadWrite, AllocationType.Commit | AllocationType.Reserve);
			if (codeCavePointer.Pointer == IntPtr.Zero)
				throw new Exception("Failed allocating memory inside the process!\nTrampoline cannot be implemented!");

			IntPtr relativeOffsetForJmpIn = Helper.CalculateRelativeOffset(targetAddress, codeCavePointer.Pointer - 5);
			List<byte> jmpBytesIn = new List<byte> { 0xE9 };
			jmpBytesIn.AddRange(BitConverter.GetBytes(relativeOffsetForJmpIn.ToInt32()));

			if (jmpInstructionNopBytesNeeded > 0)
			{
				for (int iNopIdx = 0; iNopIdx < jmpInstructionNopBytesNeeded; iNopIdx++)
				{
					jmpBytesIn.Add(0x90);
				}
			}

			if (shouldSuspend)
			{
				SuspendProcess();
				didSuspend = true;
			}

			WriteBytes(targetAddress.ToInt64(), jmpBytesIn.ToArray());
			byte[] codeCaveBytes = FasmNet.Assemble(baseMnemonics.ToArray());

			if (originalInstructionBytes.Length > 0 && preserveOriginalInstruction)
			{
				byte[] combined = new byte[codeCaveBytes.Length + originalInstructionBytes.Length];
				combined = originalInstructionBytes.Concat(codeCaveBytes).ToArray();
				codeCaveBytes = combined;
			}

			WriteBytes(codeCavePointer.Pointer.ToInt64(), codeCaveBytes);

			IntPtr currentPosition = IntPtr.Add(codeCavePointer.Pointer, codeCaveBytes.Length);
			IntPtr relativeOffsetForJmpOut = Helper.CalculateRelativeOffset(currentPosition, targetAddress);

			List<byte> jmpBytesOut = new List<byte> { 0xE9 };
			jmpBytesOut.AddRange(BitConverter.GetBytes(relativeOffsetForJmpOut.ToInt32()));
			WriteBytes(currentPosition.ToInt64(), jmpBytesOut.ToArray()); // Append the jump out instruction at the end of our code cave
			#endregion

			#region Constructing the final return object
			TrampolineInstance trampolineObject = new TrampolineInstance
			{
				AllocatedMemory = codeCavePointer,
				NewBytes = jmpBytesIn.ToArray(),
				OriginalBytes = originalInstructionBytes,
				Identifier = identifier == "" ? "NO_IDENTFIER_PROVIDED" : identifier,
				optionalRegisterStructPointer = registerStructurePointer.Pointer,
				optionalHitCounterPointer = callbackPointer.Pointer,
				TrampolineJmpOutDestination = targetAddress.ToInt32() + targetAddressInstructionCount,
				SuspendNeeded = shouldSuspend,
				TrampolineOrigin = targetAddress.ToInt64(),
				TrampolineDestination = codeCavePointer.Pointer.ToInt64()
			};

			CallbackObject returnObject = new CallbackObject
			{
				class_TrampolineInfo = trampolineObject,
				ptr_HitCounter = callbackPointer.Pointer,
				ObjectCallback = codeExecutedEventDelegate, 
				str_CallbackIdentifier = identifier == "" ? "NO_IDENTFIER_PROVIDED" : identifier,
				LastValue = 0
			};

			#endregion

			string formattedSucessMessage = $"Trampoline successfully injectd at address 0x{targetAddress.ToInt32():X} in process '{AttachedProcess.ProcessObject.ProcessName}'!\n\n" +
											$"	* Dumped Register Values Struct Start Address: 0x{registerStructurePointer.Pointer.ToInt32():X}\n" +
			                                $"	* Hitcount Pointer: 0x{callbackPointer.Pointer.ToInt32():X}\n\n" +

											$"	* Codecave Start Address: 0x{codeCavePointer.Pointer.ToInt32():X}\n" +
											"	* Codecave Allocated Size: 0x10000\n" +
											$"	* Codecave Code Size: 0x{codeCaveBytes.Length + 5}\n" +
			                                $"	* Injected Mnemonics in Codecave(Original overwritten bytes and jmp out excluded):\n\n	{string.Join("	\n	", baseMnemonics.ToArray())}\n\n" +
											$"	* Codecave Return Address: 0x{targetAddress.ToInt32() + 5:X}\n";

			Log(formattedSucessMessage);
			
			if (shouldSuspend && didSuspend)
			{
				ResumeProcess(); // Resume process
			}
			createdObject = returnObject;
			return true;
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
		    catch (FasmAssemblerException fEx)
		    {
			    assembled = null;
			    return false;
		    }
	    }
		#endregion

		#region Process Handles Specific Operations
		/// <summary>
		/// Try closing handle in remote process by its Handle type and the Handle name
		/// </summary>
		/// <param name="strHandleType">The handle type, eg "Mutant" etc</param>
		/// <param name="strHandleName">The handle name</param>
		/// <returns>bool</returns>
		public static bool TryFindDeleteHandle(string strHandleType, string strHandleName)
	    {
			if (AttachedProcess.ProcessHandle == IntPtr.Zero || AttachedProcess.ProcessObject == null) return false;
		    if (!AttachedProcess.IsRunning()) return false;
		    if (string.IsNullOrEmpty(strHandleType) || string.IsNullOrEmpty(strHandleName))
			    return false;

		    List<HandleInformation> matchingHandles = GetHandlesByType(strHandleType);
		    if (matchingHandles.Count < 1) return false;

		    HandleInformation specificHandle = matchingHandles.FirstOrDefault(x => x.HandleName.Contains(strHandleName));
		    if (specificHandle == null) return false;

		    try
		    {
			    var ipHandle = IntPtr.Zero;
			    return DuplicateHandle(Process.GetProcessById(AttachedProcess.ProcessObject.Id).Handle, specificHandle.Advanced.Handle, GetCurrentProcess(), out ipHandle, 0, false, DUPLICATE_CLOSE_SOURCE);
		    }
		    catch (Exception)
		    {
			    Console.WriteLine("ERROR LEL");
			    return false;
		    }
	    }
		#endregion

		#region Suspend Process
	    /// <summary>
	    /// Suspends a remote process
	    /// </summary>
	    /// <returns></returns>
		public static void SuspendProcess()
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) return;
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

	    /// <summary>
	    /// Resumes a remote process
	    /// </summary>
	    /// <returns></returns>
		public static void ResumeProcess()
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) return;
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
		/// <summary>
		/// Allocates some memory in the remote process
		/// </summary>
		/// <param name="size">Amount of memory to allocate</param>
		/// <param name="protectionFlags">See "MemoryProtection" enum: https://www.pinvoke.net/default.aspx/kernel32.virtualalloc </param>
		/// <param name="allocationFlags">See "AllocationType" enum: https://www.pinvoke.net/default.aspx/kernel32.virtualalloc </param>
		/// <returns>IntPtr</returns>
		public static IntPtr AllocateMemory(uint size, uint protectionFlags, uint allocationFlags)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
		    if (!AttachedProcess.IsRunning()) throw new Exception("Game is not running anymore!");
			return VirtualAllocEx(AttachedProcess.ProcessHandle, IntPtr.Zero, new IntPtr(size), allocationFlags, protectionFlags);
		}

		/// <summary>
		/// Allocates some memory in the remote process
		/// </summary>
		/// <param name="size">Amount of memory to allocate</param>
		/// <param name="protectionFlags">See "MemoryProtection" enum: https://www.pinvoke.net/default.aspx/kernel32.virtualalloc </param>
		/// <param name="allocationFlags">See "AllocationType" enum: https://www.pinvoke.net/default.aspx/kernel32.virtualalloc </param>
		/// <returns>RemoteAllocatedMemory Instance</returns>
		public static RemoteAllocatedMemory AllocateMemory(int size, MemoryProtection protectionFlags = MemoryProtection.ExecuteReadWrite, AllocationType allocationFlags = AllocationType.Commit | AllocationType.Reserve)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (!AttachedProcess.IsRunning()) throw new Exception("Game is not running anymore!");
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

		/// <summary>
		/// Tries to free allocated memory in remote process
		/// </summary>
		/// <param name="memoryItem">Not null instace of RemoteAllocatedMemory object</param>
		/// <returns>bool</returns>
		public static bool FreeMemory(RemoteAllocatedMemory memoryItem)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
		    if (!AttachedProcess.IsRunning()) return false;
			try
		    {
			    return VirtualFreeEx(AttachedProcess.ProcessHandle, memoryItem.Pointer, memoryItem.Size, 0x8000);
		    }
		    catch
		    {
			    return false;
		    }
	    }

		/// <summary>
		/// Tries to free allocated memory in remote process
		/// </summary>
		/// <param name="lpBase">Base address of allocated region</param>
		/// <param name="size">Amount of memory to to free</param>
		/// <returns>bool</returns>
		public static bool FreeMemory(IntPtr lpBase, int size)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			return VirtualFreeEx(AttachedProcess.ProcessHandle, lpBase, size, 0x8000);
	    }
		#endregion

		#region Execute Code
		/// <summary>
		/// Converts 32bit Flat assembler valid mnemonics into shellcode and executes said shellcode inside the remote process
		/// </summary>
		/// <param name="mnemonics">Valid 32bit flat assembler mnemonics</param>
		/// <returns></returns>
		public static void ExecuteCode(string[] mnemonics)
	    {
		    if (AttachedProcess.ProcessHandle == IntPtr.Zero) return;
		    if (mnemonics.Length < 1) return;

		    byte[] assembled = Assemble(mnemonics);
		    RemoteAllocatedMemory alloc = AllocateMemory(assembled.Length, MemoryProtection.ExecuteReadWrite, AllocationType.Commit);
		    WriteBytes(alloc.Pointer.ToInt32(), assembled);
		    IntPtr hThread = Native.CreateRemoteThread(MiniMem.AttachedProcess.ProcessHandle,
			    IntPtr.Zero,
			    IntPtr.Zero,
			    alloc.Pointer,
			    IntPtr.Zero /* LP PARAMETER  */,
			    (uint)ThreadCreationFlags.Run,
			    IntPtr.Zero);

		    if (hThread == IntPtr.Zero)
		    {
				FreeMemory(alloc);
			    return;
		    }
		    WaitForSingleObject(hThread, 0xFFFFFFFF);
		    CloseHandle(hThread);
			FreeMemory(alloc);
		}
		#endregion

		#region Modules
		/// <summary>
		/// Finds a specified process module inside a remote process by its module name
		/// </summary>
		/// <param name="name">Module name</param>
		/// <param name="exactMatch">None</param>
		/// <returns>ProcModule</returns>
		public static ProcModule FindProcessModule(string name, bool exactMatch = true)
	    {
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
		    if (string.IsNullOrEmpty(name)) return null;
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
		/// <summary>
		/// Writes a neatly formatted line to the Console
		/// </summary>
		/// <param name="message">The text to write</param>
		/// <param name="messageType">The type of message</param>
		/// <param name="writeToDebug">Also write to Debug output</param>
		/// <param name="writeToFile">Also write to File</param>
		/// <returns></returns>
		public static void Log(string message,MessageType messageType = MessageType.INFO, bool writeToDebug = true, bool writeToFile = false)
	    {
		    if (string.IsNullOrEmpty(message)) return;
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
	}
}
