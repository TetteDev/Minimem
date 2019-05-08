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

		/// <summary>
		/// Main list that handles all the detours, not recommended to touch it
		/// </summary>
		public static List<CallbackObject> ActiveCallbacks = new List<CallbackObject>();
		private static Thread CallbackThread = null;
		private static int CallbackPollingInterval = 100;

		/// <summary>
		/// Contains information about the current process that you have attached too
		/// </summary>
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
				if (ProcessObject == null && ProcessHandle == IntPtr.Zero) return false;

				if (ProcessObject == null) return false;
				bool processObjectStillActive = Process.GetProcesses().FirstOrDefault(x => x.Id == ProcessObject?.Id) != null;
				try
				{
					if (ProcessHandle == IntPtr.Zero) return false;
					byte[] test = ReadBytes(0x00400000, 10);
					if (test.Length != 10) return false;
				}
				catch
				{
					return false;
				}
				return processObjectStillActive;

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
		private static Signature[] FindPatternMultiple(byte[] buffer, Signature[] signatures, bool useParallel = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			var found = new ConcurrentBag<Signature>();
			if (useParallel)
			{
				Parallel.ForEach(signatures, signature =>
				{
					//if (Helper.Find(buffer, signature.Pattern, out signature.FoundOffset))
					//	found.Add(signature);
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					//if (Helper.Find(buffer, signature.Pattern, out signature.FoundOffset))
					//	found.Add(signature);

					if (Helper.Find(buffer, signature.Pattern, out signature.FoundResults))
					{
						found.Add(signature);
					}
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
			ReadProcessMemory((int) AttachedProcess.ProcessHandle, (int) pm.BaseAddress, buffer, buffer.Length, ref m_iNumberOfBytesRead);

			var found = new ConcurrentBag<Signature>();
			if (useParallel && signatures.Length > 1)
			{
				Parallel.ForEach(signatures, signature =>
				{
					if (Find(buffer, signature.Pattern, out signature.FoundResults, signature.ResultOffsettedBy, signature.ResultIsAbsoluteToModuleBase,
						signature.ResultIsAbsoluteToModuleBase ? pm.BaseAddress.ToInt64() : 0L, signature.ReturnType))
					{
						found.Add(signature);
					}
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					if (Find(buffer, signature.Pattern, out signature.FoundResults, signature.ResultOffsettedBy, signature.ResultIsAbsoluteToModuleBase, 
						signature.ResultIsAbsoluteToModuleBase ? pm.BaseAddress.ToInt64() : 0L, signature.ReturnType))
					{
						found.Add(signature);
					}
				}
			}

			return found.ToArray();
		}

		private static Signature[] FindPatternMultiple(long startAddress, long endAddress, Signature[] signatures, bool useParallel = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			byte[] buff = new byte[endAddress - startAddress];
			ReadProcessMemory((int) AttachedProcess.ProcessHandle, (int) startAddress, buff, buff.Length, ref m_iNumberOfBytesRead);

			var found = new ConcurrentBag<Signature>();
			if (useParallel)
			{
				Parallel.ForEach(signatures, signature =>
				{
					//if (Find(buff, signature.Pattern, out signature.FoundOffset))
					//	found.Add(signature);
				});
			}
			else
			{
				foreach (Signature signature in signatures)
				{
					//if (Find(buff, signature.Pattern, out signature.FoundOffset))
					//	found.Add(signature);
				}
			}

			return found.ToArray();
		}

		#endregion

		public static async Task<List<MultiAobResultItem>> MultiAobScan(string[][] byteArrays, bool readable = true, bool writable = false, bool executable = true, long start = 0, long end = 123)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) return new List<MultiAobResultItem>();
			if (byteArrays == null || byteArrays.Length < 1) return new List<MultiAobResultItem>();

			var memRegionList = new List<MemoryRegionResult>();
			var itms = new List<Tuple<MultiAobItem, ConcurrentBag<long>>>();

			foreach (var aob in byteArrays)
			{
				var tmpSplitPattern = aob[0].Split(' ');

				var tmpPattern = new byte[tmpSplitPattern.Length];
				var tmpMask = new byte[tmpSplitPattern.Length];

				for (var i = 0; i < tmpSplitPattern.Length; i++)
				{
					var ba = tmpSplitPattern[i];

					if (ba == "??" || ba.Length == 1 && ba == "?")
					{
						tmpMask[i] = 0x00;
						tmpSplitPattern[i] = "0x00";
					}
					else if (char.IsLetterOrDigit(ba[0]) && ba[1] == '?')
					{
						tmpMask[i] = 0xF0;
						tmpSplitPattern[i] = ba[0] + "0";
					}
					else if (char.IsLetterOrDigit(ba[1]) && ba[0] == '?')
					{
						tmpMask[i] = 0x0F;
						tmpSplitPattern[i] = "0" + ba[1];
					}
					else
					{
						tmpMask[i] = 0xFF;
					}
				}

				for (var i = 0; i < tmpSplitPattern.Length; i++)
					tmpPattern[i] = (byte) (Convert.ToByte(tmpSplitPattern[i], 16) & tmpMask[i]);

				var itm = new MultiAobItem
				{
					ArrayOfBytesString = aob[0],
					Mask = tmpMask,
					Pattern = tmpPattern,
					OptionalIdentifier = string.IsNullOrEmpty(aob[1]) ? "NO_IDENTIFIER_SPECIFIED" : aob[1]
				};

				itms.Add(new Tuple<MultiAobItem, ConcurrentBag<long>>(itm, new ConcurrentBag<long>()));
			}

			GetSystemInfo(out var sys_info);

			var proc_min_address = sys_info.minimumApplicationAddress;
			var proc_max_address = sys_info.maximumApplicationAddress;

			start = start < (long) proc_min_address.ToUInt64() ? (long) proc_min_address.ToUInt64() : start;
			end = end > (long) proc_max_address.ToUInt64() ? (long) proc_max_address.ToUInt64() : end;

			var currentBaseAddress = new UIntPtr((ulong) start);

			uint MEM_COMMIT = 0x00001000;
			uint PAGE_GUARD = 0x100;
			uint PAGE_NOACCESS = 0x01;
			uint MEM_PRIVATE = 0x20000;
			uint MEM_IMAGE = 0x1000000;
			uint PAGE_READONLY = 0x02;
			uint PAGE_READWRITE = 0x04;
			uint PAGE_WRITECOPY = 0x08;
			uint PAGE_EXECUTE_READWRITE = 0x40;
			uint PAGE_EXECUTE_WRITECOPY = 0x80;
			uint PAGE_EXECUTE = 0x10;
			uint PAGE_EXECUTE_READ = 0x20;

			while (VirtualQueryExCustom(AttachedProcess.ProcessHandle, currentBaseAddress, out var memInfo).ToUInt64() != 0 &&
			       currentBaseAddress.ToUInt64() < (ulong) end &&
			       currentBaseAddress.ToUInt64() + memInfo.RegionSize >
			       currentBaseAddress.ToUInt64())
			{
				var isValid = memInfo.State == MEM_COMMIT;
				isValid &= memInfo.BaseAddress.ToUInt64() < proc_max_address.ToUInt64();
				isValid &= (memInfo.Protect & PAGE_GUARD) == 0;
				isValid &= (memInfo.Protect & PAGE_NOACCESS) == 0;
				isValid &= memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_IMAGE;

				if (isValid)
				{
					var isReadable = (memInfo.Protect & PAGE_READONLY) > 0;

					var isWritable = (memInfo.Protect & PAGE_READWRITE) > 0 ||
					                 (memInfo.Protect & PAGE_WRITECOPY) > 0 ||
					                 (memInfo.Protect & PAGE_EXECUTE_READWRITE) > 0 ||
					                 (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) > 0;

					var isExecutable = (memInfo.Protect & PAGE_EXECUTE) > 0 ||
					                   (memInfo.Protect & PAGE_EXECUTE_READ) > 0 ||
					                   (memInfo.Protect & PAGE_EXECUTE_READWRITE) > 0 ||
					                   (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) > 0;

					isReadable &= readable;
					isWritable &= writable;
					isExecutable &= executable;

					isValid &= isReadable || isWritable || isExecutable;
				}

				if (!isValid)
				{
					currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + memInfo.RegionSize);
					continue;
				}

				var memRegion = new MemoryRegionResult
				{
					CurrentBaseAddress = currentBaseAddress,
					RegionSize = memInfo.RegionSize,
					RegionBase = memInfo.BaseAddress
				};

				currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + memInfo.RegionSize);

				if (memRegionList.Count > 0)
				{
					var previousRegion = memRegionList[memRegionList.Count - 1];

					if ((long) previousRegion.RegionBase + previousRegion.RegionSize == (long) memInfo.BaseAddress)
					{
						memRegionList[memRegionList.Count - 1] = new MemoryRegionResult
						{
							CurrentBaseAddress = previousRegion.CurrentBaseAddress,
							RegionBase = previousRegion.RegionBase,
							RegionSize = previousRegion.RegionSize + memInfo.RegionSize
						};

						continue;
					}
				}

				memRegionList.Add(memRegion);
			}

			Parallel.ForEach(memRegionList,
				(item, parallelLoopState, index) => { CompareScanMulti(item, ref itms, AttachedProcess.ProcessHandle); });

			return itms.Select(itm1 => new MultiAobResultItem
			{
				Identifier = itm1.Item1.OptionalIdentifier,
				Pattern = itm1.Item1.ArrayOfBytesString,
				Results = itm1.Item2.OrderBy(c => c).ToList(),
				FirstResultAsLong = itm1.Item2.OrderBy(c => c).ToList().FirstOrDefault() == 0 ? 0 : itm1.Item2.OrderBy(c => c).ToList().FirstOrDefault(),
				FirstResultAsHexString = itm1.Item2.OrderBy(c => c).ToList().FirstOrDefault() == 0 ? "0x0" : $"0x{itm1.Item2.OrderBy(c => c).ToList().FirstOrDefault():X8}"
			}).ToList();
		}

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
				for (;;)
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
				return string.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(processModule.BaseAddress.ToInt64(), (int) processModule.Size), pattern, processModule.BaseAddress.ToInt32());
			}
			return string.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(processModule.BaseAddress.ToInt64(), (int) processModule.Size), pattern, 0);
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
			return String.IsNullOrEmpty(pattern) ? IntPtr.Zero : FindPatternSingle(ReadBytes(startAddress, (int) size), pattern, 0);
		}


		/// <summary>
		/// WIP Port of https://github.com/AlainProvist/EAL/blob/master/src/eal/memorybrowser.cpp#L117
		/// </summary>
		/// <param name="processModule">Process module to search through</param>
		/// <param name="pattern">The IDA styled pattern</param>
		/// <param name="offset">Offset to be added to the returned result</param>
		/// <param name="occurenceIdx">If results for a pattern is more than 1, get a specific result (First result is at index 1, not 0)</param>
		/// <param name="type">How to read the result found</param>
		/// <param name="resultAbsolute">None</param>
		/// <returns>IntPtr</returns>
		public static IntPtr FindPattern(ProcModule processModule, string pattern, int offset = 0, int occurenceIdx = -1, MemoryType type = MemoryType.RT_ADDRESS, bool CheckResult = false ,string RT_LOCATION_Checkbytes = "55 8B EC", bool resultAbsolute = true)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (processModule == null || processModule.BaseAddress == IntPtr.Zero) throw new Exception("Provided 'ProcModule' class was null or invalid!");
			List<IntPtr> lpResults = new List<IntPtr>();
			List<byte> bytesPattern = new List<byte>();
			List<bool> boolMask = new List<bool>();

			byte[] bytesBuffer = ReadBytes(processModule.BaseAddress.ToInt64(), (int) processModule.Size);
			if (bytesBuffer.Length < 1) throw new Exception("Failed reading bytes for region 'processModule'");

			foreach (string s in pattern.Split(' '))
			{
				if (string.IsNullOrEmpty(s)) continue;
				if (s == "?" || s == "??")
				{
					bytesPattern.Add(0x0);
					boolMask.Add(false);
				}
				else
				{
					byte b;
					if (byte.TryParse(s, NumberStyles.HexNumber, CultureInfo.CurrentCulture, out b))
					{
						bytesPattern.Add(Convert.ToByte(s, 16));
						boolMask.Add(true);
					}
					else
					{
						break;
					}
				}
			}

			int intIx, intIy = 0;
			int intPatternLength = bytesPattern.Count;
			int intDataLength = bytesBuffer.Length - intPatternLength;

			for (intIx = 0; intIx < intDataLength; intIx++)
			{
				var boolFound = true;
				for (intIy = 0; intIy < intPatternLength; intIy++)
				{
					if (boolMask[intIy] && bytesPattern[intIy] != bytesBuffer[intIx + intIy])
					{
						boolFound = false;
						break;
					}
				}

				if (boolFound)
				{
					lpResults.Add(!resultAbsolute ? new IntPtr(intIx) : new IntPtr(processModule.BaseAddress.ToInt32() + intIx));
				}
			}
			if (lpResults.Count < 1) return IntPtr.Zero;

			if (occurenceIdx > -1)
			{
				if (occurenceIdx - 1 < 0) occurenceIdx = 0;
				IntPtr lpAddr_occurence = lpResults[occurenceIdx - 1];
				if (offset != 0)
					lpAddr_occurence = IntPtr.Add(lpAddr_occurence, offset);
				
				switch (type)
				{
					case MemoryType.RT_READNEXT4_BYTES_RAW:
						byte[] next4BytesArrRaw = new byte[4];
						Array.Copy(ReadBytes(lpAddr_occurence.ToInt64() + 1, 4), 0, next4BytesArrRaw, 0, 4); // +1 just assumes pattern returns a address where CALL is first instruction
						return new IntPtr(BitConverter.ToInt32(next4BytesArrRaw, 0));
					case MemoryType.RT_READNEXT4_BYTES: // Return Absolute address
						byte[] next4BytesArrAbs = new byte[4];
						Array.Copy(ReadBytes(lpAddr_occurence.ToInt64() + 1, 4), 0, next4BytesArrAbs, 0, 4); // +1 just assumes pattern returns a address where CALL is first instruction
						//if (BitConverter.IsLittleEndian)
						//	Array.Reverse(next4BytesArrAbs);
						return new IntPtr(processModule.BaseAddress.ToInt32() + BitConverter.ToInt32(next4BytesArrAbs, 0) - (processModule.BaseAddress.ToInt32() - lpAddr_occurence.ToInt32() - 5));
					case MemoryType.RT_REL_ADDRESS:
						if (CheckResult)
						{
							byte[] fiveBytes = ReadBytes(lpAddr_occurence.ToInt64() - 1, 5);
							if (fiveBytes[0] == 0xE8) // CALL
								return new IntPtr(lpAddr_occurence.ToInt32() + 4);
							else
							{
								Debug.WriteLine("FindPattern with argument RT_REL_ADDRESS failed as found address was not lead by a CALL(0xE8)");
								return IntPtr.Zero;
							}
						}
						else
							return lpAddr_occurence;
					case MemoryType.RT_ADDRESS:
						return lpAddr_occurence;
					case MemoryType.RT_LOCATION:
						if (CheckResult)
						{
							if (string.IsNullOrEmpty(RT_LOCATION_Checkbytes))
							{
								string[] RT_LOCATION_CheckbytesHardCoded = "55 8B EC".Split(' ');
								int intBytesToRead = RT_LOCATION_CheckbytesHardCoded.Length;
								byte[] bytesCheckBuffer = ReadBytes(lpAddr_occurence.ToInt64(), intBytesToRead);
								for (int intByteIdx = 0; intByteIdx < bytesCheckBuffer.Length; intByteIdx++)
								{
									if (Convert.ToByte(RT_LOCATION_CheckbytesHardCoded[intByteIdx], 16) != bytesCheckBuffer[intByteIdx])
										return IntPtr.Zero;
								}

								return lpAddr_occurence;
							}
							else
							{
								string[] checkBytes = RT_LOCATION_Checkbytes.Split(' ');
								int intBytesToRead = checkBytes.Length;
								byte[] bytesCheckBuffer = ReadBytes(lpAddr_occurence.ToInt64(), intBytesToRead);
								for (int intByteIdx = 0; intByteIdx < bytesCheckBuffer.Length; intByteIdx++)
								{
									if (Convert.ToByte(checkBytes[intByteIdx], 16) != bytesCheckBuffer[intByteIdx])
										return IntPtr.Zero;
								}

								return lpAddr_occurence;
							}
						}
						else
							return lpAddr_occurence;
					default:
						return lpAddr_occurence;
				}
			}

			IntPtr lpAddr_first = lpResults[0];
			if (offset != 0)
				lpAddr_first = IntPtr.Add(lpAddr_first, offset);

			switch (type)
			{
				case MemoryType.RT_READNEXT4_BYTES_RAW:
					byte[] next4BytesArrRaw = new byte[4];
					Array.Copy(ReadBytes(lpAddr_first.ToInt64() + 1, 4), 0, next4BytesArrRaw, 0, 4); // +1 just assumes pattern returns a address where CALL is first instruction
					return new IntPtr(BitConverter.ToInt32(next4BytesArrRaw, 0));
				case MemoryType.RT_READNEXT4_BYTES: // Return Absolute address
					byte[] next4BytesArrAbs = new byte[4];
					Array.Copy(ReadBytes(lpAddr_first.ToInt64() + 1, 4), 0, next4BytesArrAbs, 0, 4); // +1 just assumes pattern returns a address where CALL is first instruction
					return new IntPtr(processModule.BaseAddress.ToInt32() + BitConverter.ToInt32(next4BytesArrAbs, 0) - (processModule.BaseAddress.ToInt32() - lpAddr_first.ToInt32() - 5));
				case MemoryType.RT_REL_ADDRESS:
					if (CheckResult)
					{
						byte[] fiveBytes = ReadBytes(lpAddr_first.ToInt64() - 1, 5);
						if (fiveBytes[0] == 0xE8) // CALL
						{
							return new IntPtr(lpAddr_first.ToInt32() + 5);
						}
						else
						{
							throw new Exception("MemoryType 'RT_RELATIVE' was passed as a argument but result was not a CALL instruction!");
						}
					}
					else
						return lpAddr_first;
					
				case MemoryType.RT_ADDRESS:
					return lpAddr_first;
				case MemoryType.RT_LOCATION:
					if (CheckResult)
					{
						if (string.IsNullOrEmpty(RT_LOCATION_Checkbytes))
						{
							string[] RT_LOCATION_CheckbytesHardCoded = "55 8B EC".Split(' ');
							int intBytesToRead = RT_LOCATION_CheckbytesHardCoded.Length;
							byte[] bytesCheckBuffer = ReadBytes(lpAddr_first.ToInt64(), intBytesToRead);
							for (int intByteIdx = 0; intByteIdx < bytesCheckBuffer.Length; intByteIdx++)
							{
								if (Convert.ToByte(RT_LOCATION_CheckbytesHardCoded[intByteIdx], 16) != bytesCheckBuffer[intByteIdx])
									return IntPtr.Zero;
							}
							return lpAddr_first;
						}
						else
						{
							string[] checkBytes = RT_LOCATION_Checkbytes.Split(' ');
							int intBytesToRead = checkBytes.Length;
							byte[] bytesCheckBuffer = ReadBytes(lpAddr_first.ToInt64(), intBytesToRead);
							for (int intByteIdx = 0; intByteIdx < bytesCheckBuffer.Length; intByteIdx++)
							{
								if (Convert.ToByte(checkBytes[intByteIdx], 16) != bytesCheckBuffer[intByteIdx])
									return IntPtr.Zero;
							}
							return lpAddr_first;
						}
					}
					else
						return lpAddr_first;
					
				default:
					return lpAddr_first;
			}
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
			ReadProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buffer, byteCount, ref m_iNumberOfBytesRead);
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
			ReadProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buff, buff.Length, ref numBytesRead);
			return zeroTerminated ? defaultEncoding.GetString(buff).Split('\0')[0] : Encoding.UTF8.GetString(buff);
		}

		public static T ReadMultiLevelPointer<T>(long baseAddress, params int[] offsets) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (offsets.Length == 0) return ReadMemory<T>(baseAddress);
			var temp = ReadMemory<IntPtr>(baseAddress);
			for (int i = 0; i < offsets.Length - 1; i++)
			{
				temp = ReadMemory<IntPtr>((int) temp + offsets[i]);
			}
			return ReadMemory<T>((int) temp + (int) offsets[offsets.Length - 1]);
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
			ReadProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buffer, buffer.Length, ref m_iNumberOfBytesRead);
			return ByteArrayToStructure<T>(buffer);
		}

		public static T ReadMemoryProtected<T>(long address) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(typeof(T)), 0x40, out var oldProtection);
			var buffer = new byte[Marshal.SizeOf(typeof(T))];
			ReadProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buffer, buffer.Length, ref m_iNumberOfBytesRead);
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(typeof(T)), oldProtection, out oldProtection);
			return ByteArrayToStructure<T>(buffer);
		}

		/// <summary>
		/// Use marshalling to read an array from memory
		/// </summary>
		/// <param name="address">Start address where to read the bytes from that will then be marshalled into the type T[]</param>
		/// <param name="length">The length of the array to return</param>
		/// <param name="optionalSpacing">A fixed amount to jump inbetween each read</param>
		/// <returns>T</returns>
		public static T[] ReadArray<T>(long address, int length, int optionalSpacing = -1) where T : struct 
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (length < 1) return null;

			var itemSize = Marshal.SizeOf(typeof(T)) + (optionalSpacing > 0 ? optionalSpacing : 0);
			var bufferSize = itemSize * length;
			byte[] buff = ReadBytes(address, bufferSize);
			if (buff.Length < 1) return null;
			T[] retArr = new T[length];

			int byteIdx = 0;
			int arrIdx = 0;
			while (arrIdx < retArr.Length)
			{
				byte[] copied = new byte[Marshal.SizeOf(typeof(T))];
				Array.Copy(buff, byteIdx, copied, 0, Marshal.SizeOf(typeof(T)));
				Debug.WriteLine($"Read {Marshal.SizeOf(typeof(T))} bytes at address 0x{(address + byteIdx):X8}");
				retArr[arrIdx] = ByteArrayToStructure<T>(copied);

				byteIdx += itemSize;
				arrIdx++;
			}

			return retArr;
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
			return WriteProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
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
			return WriteProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, memory, memory.Length, out var numBytesRead);
		}

		public static void WriteMemoryProtected<T>(long address, object value) where T : struct
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			VirtualProtectEx(AttachedProcess.ProcessHandle, new IntPtr(address), Marshal.SizeOf(value), 0x40, out var oldProtection);
			var buffer = StructureToByteArray(value);
			WriteProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
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
				return WriteMemory<T>((int) final, value);
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
			return WriteProcessMemory((int) AttachedProcess.ProcessHandle, (int) address, buffer, buffer.Length, out m_iNumberOfBytesWritten);
		}

		public static void WriteArray<T>(long address, T[] arr)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) throw new Exception("Memory module has not been attached to any process!");
			if (arr == null || arr.Length < 1) return;


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


			List<byte> JMPInBytes = new List<byte> {0xE9};
			// Relative JMP
			JMPInBytes.AddRange(BitConverter.GetBytes((memoryRegion.Pointer.ToInt32() - (int) targetInstructionAddress) - 5)); // DEST - ORIGIN = Offset to codecave
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
			int relativeJumpBackOutAddress = jumpOutInstructionLocation > (int) targetInstructionAddress ? (int) targetInstructionAddress - jumpOutInstructionLocation : jumpOutInstructionLocation - (int) targetInstructionAddress;
			newInstance.TrampolineJmpOutDestination = relativeJumpBackOutAddress + nopBytes.Length;

			newInstance.optionalHitCounterPointer = IntPtr.Zero;
			newInstance.optionalRegisterStructPointer = IntPtr.Zero;

			List<byte> JMPOutBytes = new List<byte> {0xE9};
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

				if (!TryAssemble(modified.ToArray(), false, out byte[] assembledResult)) // See if the provided mnemonics are valid 64bit mnemonics
					return null; // Invalid 64bit mnemonics according to Flat Assembler
			}
			else
			{
				modified = mnemonics64bit.ToList();
				if (!TryAssemble(modified.ToArray(), false, out byte[] assembledResult)) // See if the provided mnemonics are valid 64bit mnemonics
					return null; // Invalid 64bit mnemonics according to Flat Assembler
			}

			// Already here add the jmp out instructions to our mnemonics
			RemoteAllocatedMemory codeCave = AllocateMemory(0x10000);
			modified.InsertRange(mnemonics64bit.Length, new[]
			{
				//$"jmp {targetInstructionAddress - (ulong)codeCave.Pointer.ToInt64() + (ulong)instructionCount}",
				$"mov rax,{targetInstructionAddress + (uint) instructionCount}",
				"jmp rax",
			});

			int nopCount = instructionCount - 12;
			bool DidSuspend = false;

			byte[] originalOverwritenBytes = ReadBytes((long) targetInstructionAddress, instructionCount);

			// Calculate jump in offset
			ulong jumpInOffset = (ulong) codeCave.Pointer.ToInt64() - targetInstructionAddress - 10;
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

			WriteBytes((long) targetInstructionAddress, jumpInBytes.ToArray());

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
				TrampolineJmpOutDestination = (long) targetInstructionAddress + instructionCount,
				TrampolineJmpOutAddress = 0, // ignore this
			};
		}

		public static bool CreateTrampolineAndCallback(IntPtr targetAddress, int targetAddressInstructionCount, string[] mnemonics, CallbackDelegate codeExecutedEventDelegate, out CallbackObject createdObject,
			string identifier = "", bool shouldSuspend = true, bool preserveOriginalInstruction = false, bool implementCallback = true, bool implementRegisterDump = true, bool printDebugDetourData = false)
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
				mnemonics = new[] {"use32",};
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
			List<byte> jmpBytesIn = new List<byte> {0xE9};
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
				// if (put_original_bytes_after_new_code)
				//	do that here
				// else {
				byte[] combined = new byte[codeCaveBytes.Length + originalInstructionBytes.Length];
				combined = originalInstructionBytes.Concat(codeCaveBytes).ToArray();
				codeCaveBytes = combined;
				// }
			}

			WriteBytes(codeCavePointer.Pointer.ToInt64(), codeCaveBytes);

			IntPtr currentPosition = IntPtr.Add(codeCavePointer.Pointer, codeCaveBytes.Length);
			IntPtr relativeOffsetForJmpOut = CalculateRelativeOffset(currentPosition, targetAddress);

			List<byte> jmpBytesOut = new List<byte> {0xE9};
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

			List<string> completeMnemonics = baseMnemonics.ToList();
			int idx = completeMnemonics.IndexOf("use32");
			if (idx != -1)
				completeMnemonics.RemoveAt(idx);
			
			completeMnemonics.Add($"jmp {BitConverter.ToInt32(jmpBytesOut.ToArray(), 1)} // JMP back to original code (0x{targetAddress.ToInt32() + targetAddressInstructionCount:X})");

			if (printDebugDetourData)
			{
				string formattedSucessMessage = $"Trampoline successfully injected at address 0x{targetAddress.ToInt32():X} in process '{AttachedProcess.ProcessObject.ProcessName}'!\n\n" +
				                                $"	* Dumped Register Values Struct Start Address: 0x{registerStructurePointer.Pointer.ToInt32():X}\n" +
				                                $"	* Hitcount Pointer: 0x{callbackPointer.Pointer.ToInt32():X}\n\n" +
				                                $"	* Codecave Start Address: 0x{codeCavePointer.Pointer.ToInt32():X}\n" +
				                                $"	* Codecave Allocated Size: 0x{codeCavePointer.Size:X8}\n" +
				                                $"	* Codecave Code Size: 0x{codeCaveBytes.Length + 5}\n" +
				                                $"	* Injected Mnemonics in Codecave(Original overwritten bytes excluded):\n\n	{string.Join("	\n	", completeMnemonics.ToArray())}\n\n" +
				                                $"	* Codecave Return Address: 0x{targetAddress.ToInt32() + targetAddressInstructionCount:X}\n";

				Log(formattedSucessMessage);
			}
			
			if (shouldSuspend && didSuspend)
			{
				ResumeProcess(); // Resume process
			}
			createdObject = returnObject;
			return true;
		}


		public static bool RestoreDetour(string identifier)
		{
			if (string.IsNullOrEmpty(identifier)) return false;
			if (ActiveCallbacks.Count < 1) return false;
			var toClear = ActiveCallbacks.FirstOrDefault(x => x.str_CallbackIdentifier == identifier);

			if (toClear != null)
			{
				if (toClear.class_TrampolineInfo.OriginalBytes == null || toClear.class_TrampolineInfo.OriginalBytes.Length < 1) return false;
				WriteBytes(toClear.class_TrampolineInfo.TrampolineOrigin, toClear.class_TrampolineInfo.OriginalBytes);
				FreeMemory(toClear.class_TrampolineInfo.AllocatedMemory);
				return true;
			}
			return false;
		}

		#endregion

		#region FASM

		public static byte[] Assemble(string mnemonics)
		{
			return FasmNet.Assemble(mnemonics);
		}

		public static byte[] Assemble(string[] mnemonics, bool rebase = false, int rebaseOrig = 0)
		{
			if (rebase)
			{
				FasmNet var = new FasmNet();
				foreach (string mnem in mnemonics)
				{
					var.AddLine(mnem);
				}

				byte[] tmp = var.Assemble();
				byte[] real = var.Assemble(rebaseOrig);
				return real;
			}
			else
			{
				return FasmNet.Assemble(mnemonics);
			}
		}

		public static bool TryAssemble(string[] mnemonics, bool rebase, out byte[] assembled)
		{
			try
			{
				byte[] t = Assemble(mnemonics, rebase);
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

			if (process.ProcessName == string.Empty || process == null)
			{
				Log("Warning, process object was null in function SuspendProcess()", MessageType.ERROR);
				return;
			}
				

			foreach (ProcessThread pT in process.Threads)
			{
				IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint) pT.Id);

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

			if (process.ProcessName == string.Empty || process == null)
			{
				Log("Warning, process object was null in function ResumeProcess()", MessageType.ERROR);
				return;
			}
				

			foreach (ProcessThread pT in process.Threads)
			{
				IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint) pT.Id);

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
		public static void ExecuteCode(string[] mnemonics, bool rebase = true, int rebaseOrigin = 0)
		{
			if (AttachedProcess.ProcessHandle == IntPtr.Zero) return;
			if (mnemonics.Length < 1) return;
			RemoteAllocatedMemory alloc = AllocateMemory(0x10000, MemoryProtection.ExecuteReadWrite, AllocationType.Commit);
			byte[] assembled = Assemble(mnemonics, rebase, rebaseOrigin);

			WriteBytes(alloc.Pointer.ToInt32(), assembled);
			IntPtr hThread = Native.CreateRemoteThread(MiniMem.AttachedProcess.ProcessHandle,
				IntPtr.Zero,
				IntPtr.Zero,
				alloc.Pointer,
				IntPtr.Zero /* LP PARAMETER  */,
				(uint) ThreadCreationFlags.Run,
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

		/// <summary>
		/// Converts 32bit Flat assembler valid mnemonics into shellcode and executes said shellcode inside the remote process and returns the specified value in desired register
		/// </summary>
		/// <param name="mnemonics">Valid 32bit flat assembler mnemonics</param>
		/// <param name="returnValue">Return value from desired register</param>
		/// <param name="optionalRegisterReturn">Register to return</param>
		/// <returns></returns>
		public static bool ExecuteCode<T>(string[] mnemonics, out T returnValue, string optionalRegisterReturn = "eax", bool flag = false, string insertPattern = "<return>") where T : struct
		{
			if (mnemonics == null || mnemonics.Length < 1)
			{
				returnValue = default(T);
				return false;
			}

			RemoteAllocatedMemory eaxReturnValue = AllocateMemory(sizeof(int));
			if (eaxReturnValue.Pointer == IntPtr.Zero)
			{
				returnValue = default(T);
				return false;
			}

			List<string> mnemonicsList = mnemonics.ToList();
			if (flag && insertPattern != "")
			{
				int idx = mnemonicsList.IndexOf(insertPattern);
				if (idx != -1)
				{
					mnemonicsList.Insert(idx,
						$"mov [{eaxReturnValue.Pointer}],{optionalRegisterReturn}");
					mnemonicsList.RemoveAt(idx + 1);
				}
				else
				{
					throw new Exception($"{nameof(flag)} was set to true but could not find an instance of '{insertPattern}' in the provided mnemonics");
				}
			}
			else
			{
				if (insertPattern != "" && mnemonicsList.Contains(insertPattern))
				{
					int idx = mnemonicsList.IndexOf(insertPattern);
					if (idx != -1)
					{
						mnemonicsList.RemoveAt(idx);
					}
				}
				mnemonicsList.Add($"mov [{eaxReturnValue.Pointer}],{optionalRegisterReturn}");
			}

			if (!TryAssemble(mnemonicsList.ToArray(), false, out byte[] assembledBytes))
			{
				throw new Exception("Invalid Mnemonics!");
			}

			RemoteAllocatedMemory alloc = AllocateMemory(assembledBytes.Length, MemoryProtection.ExecuteReadWrite, AllocationType.Commit);
			if (alloc.Pointer == IntPtr.Zero)
			{
				returnValue = default(T);
				return false;
			}
			WriteBytes(alloc.Pointer.ToInt32(), assembledBytes);
			IntPtr hThread = Native.CreateRemoteThread(AttachedProcess.ProcessHandle,
				IntPtr.Zero,
				IntPtr.Zero,
				alloc.Pointer,
				IntPtr.Zero /* LP PARAMETER  */,
				(uint) ThreadCreationFlags.Run,
				IntPtr.Zero);

			if (hThread == IntPtr.Zero)
			{
				FreeMemory(alloc);
				FreeMemory(eaxReturnValue);
				returnValue = default(T);
				return false;
			}
			WaitForSingleObject(hThread, 0xFFFFFFFF);
			CloseHandle(hThread);
			FreeMemory(alloc);

			try
			{
				returnValue = ReadMemory<T>(eaxReturnValue.Pointer.ToInt64());
				return true;
			}
			finally
			{
				FreeMemory(eaxReturnValue);
			}
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
						ret.Size = (uint) pm.ModuleMemorySize;
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
						ret.Size = (uint) pm.ModuleMemorySize;
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
		public static void Log(string message, MessageType messageType = MessageType.INFO, bool writeToDebug = true, bool writeToFile = false)
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
					File.AppendAllLines("logs.txt", new[] {Environment.NewLine + formattedMessage});
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