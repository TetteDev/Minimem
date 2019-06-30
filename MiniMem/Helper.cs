using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static MiniMem.Constants;
using Byte = MiniMem.Constants.Byte;

namespace MiniMem
{
	public static class IntPtrExtensions
	{
		public static bool IsValid(this IntPtr ptr, ProcModule module = null)
		{
			if (MiniMem.AttachedProcess.ProcessHandle == IntPtr.Zero)
				throw new Exception("Please attach to the game first!");

			if (ptr == IntPtr.Zero) return false;

			if (module != null)
			{
				return ptr.ToInt32() >= module.BaseAddress.ToInt32() &&
				       ptr.ToInt32() <= module.EndAddress.ToInt32();
			}

			ProcModule pm = MiniMem.FindProcessModule(MiniMem.AttachedProcess.ProcessObject.ProcessName); // Get "main" module
			if (pm != null)
			{
				return ptr.ToInt32() >= pm.BaseAddress.ToInt32() &&
				       ptr.ToInt32() <= pm.EndAddress.ToInt32();
			}

			return ptr != IntPtr.Zero;
		}
	}
	public static class StructExtensions
	{
		public static int GetOffset<T>(this T structObject, string offsetname)
		{
			return string.IsNullOrEmpty(offsetname) ? 0 : Marshal.OffsetOf<T>(offsetname).ToInt32();
		}
	}
	public static class StringExtensions
	{
		public static void Cout(this string strObject)
		{
			Console.WriteLine(strObject);
			Debug.WriteLine(strObject);
		}
	}

	public class Helper
	{
		public static bool bCallbackThreadExitFlag = false;

		public static void CompareScanMulti(MemoryRegionResult item, ref List<Tuple<MultiAobItem, ConcurrentBag<long>>> aobCollection, IntPtr processHandle)
		{
			if (processHandle == IntPtr.Zero) return;
			foreach (var aobToSearchFor in aobCollection)
			{
				if (aobToSearchFor.Item1.Mask.Length != aobToSearchFor.Item1.Pattern.Length)
					throw new ArgumentException($"{nameof(aobToSearchFor.Item1.Pattern)}.Length != {nameof(aobToSearchFor.Item1.Mask)}.Length");
			}

			IntPtr buffer = Marshal.AllocHGlobal((int)item.RegionSize);
			ReadProcessMemory(processHandle, item.CurrentBaseAddress, buffer, (UIntPtr)item.RegionSize, out ulong bytesRead);

			foreach (var aobPattern in aobCollection)
			{
				int result = 0 - aobPattern.Item1.Pattern.Length;
				unsafe
				{
					do
					{

						result = FindPattern((byte*)buffer.ToPointer(), (int)bytesRead, aobPattern.Item1.Pattern, aobPattern.Item1.Mask, result + aobPattern.Item1.Pattern.Length);

						if (result >= 0)
							aobPattern.Item2.Add((long)item.CurrentBaseAddress + result);

					} while (result != -1);
				}
			}

			Marshal.FreeHGlobal(buffer);
		}


		[DllImport("kernel32.dll")]
		private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] IntPtr lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);
		private static unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0)
		{
			int foundIndex = -1;

			if (bodyLength <= 0 || pattern.Length <= 0 || start > bodyLength - pattern.Length ||
			    pattern.Length > bodyLength) return foundIndex;

			for (int index = start; index <= bodyLength - pattern.Length; index++)
			{
				if (((body[index] & masks[0]) != (pattern[0] & masks[0]))) continue;

				var match = true;
				for (int index2 = 1; index2 <= pattern.Length - 1; index2++)
				{
					if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2])) continue;
					match = false;
					break;

				}

				if (!match) continue;

				foundIndex = index;
				break;
			}

			return foundIndex;
		}

		public static string Format(string pattern)
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
		public static int hexChToInt(char ch)
		{
			if (ch >= '0' && ch <= '9')
				return ch - '0';
			if (ch >= 'A' && ch <= 'F')
				return ch - 'A' + 10;
			if (ch >= 'a' && ch <= 'f')
				return ch - 'a' + 10;
			return -1;
		}
		public static bool matchByte(byte b, ref Byte p)
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
		public static bool Find(byte[] data, Byte[] pattern, out List<long> offsetsFound, long optionalOffsetResult = 0, bool optionalAbsoluteResult = false, long moduleBase = 0L, ReturnType returnType = ReturnType.ADDRESS)
		{
			int HARD_CAP_RESULT_AMOUNT = 25;
			var offsetsFoundInternal = new List<long>();
			if (data == null || pattern == null)
			{
				offsetsFound = null;
				return false;
			}
				
			var patternSize = pattern.LongLength;
			if (data.LongLength == 0 || patternSize == 0)
			{
				offsetsFound = null;
				return false;
			}
				

			for (long i = 0, pos = 0; i < data.LongLength; i++)
			{
				if (matchByte(data[i], ref pattern[pos])) //check if the current data byte matches the current pattern byte
				{
					pos++;
					if (pos != patternSize) continue;
					var internalOffsetFound = i - patternSize + 1;
					if (optionalAbsoluteResult)
					{
						internalOffsetFound += moduleBase;
					}

					if (optionalOffsetResult != 0)
						internalOffsetFound += optionalOffsetResult;
					switch (returnType)
					{
						case ReturnType.ADDRESS:
							offsetsFoundInternal.Add(internalOffsetFound);
							break;
						case ReturnType.READ4BYTES:
							byte[] byteSequence4 = MiniMem.ReadBytes(optionalAbsoluteResult ? internalOffsetFound : moduleBase + internalOffsetFound, 4);
							offsetsFoundInternal.Add((long)BitConverter.ToInt32(byteSequence4, 0));
							break;
						case ReturnType.READ8BYTES:
							byte[] byteSequence9 = MiniMem.ReadBytes(optionalAbsoluteResult ? internalOffsetFound : moduleBase + internalOffsetFound, 8);
							offsetsFoundInternal.Add(BitConverter.ToInt64(byteSequence9, 0));
							break;
					}
					pos = 0;
					if (offsetsFoundInternal.Count >= HARD_CAP_RESULT_AMOUNT)
					{
						Debug.WriteLine($"Hard cap of {HARD_CAP_RESULT_AMOUNT} addresses have been hit so far with {data.LongLength - i} bytes left unread in buffer, stopping procedure ...");
						break;
					}
				}
				else
				{
					i -= pos;
					pos = 0; //reset current pattern position
				}
			}

			offsetsFound = offsetsFoundInternal;
			return offsetsFound.Count > 0;
			//return false;
		}

		public static void CallbackLoop()
		{
			while (!bCallbackThreadExitFlag)
			{
				if (MiniMem.ActiveCallbacks.Count < 1 || MiniMem.AttachedProcess.ProcessHandle == IntPtr.Zero)
				{
					Thread.Sleep(500);
					continue;
				}

				Debug.WriteLine($"[CALLBACK MONITOR] {MiniMem.ActiveCallbacks.Count} registered item(s) in Callback Monitor");

				for (int i = MiniMem.ActiveCallbacks.Count - 1; i >= 0; i--)
				{
					if (bCallbackThreadExitFlag)
						break;

					CallbackObject cObj = MiniMem.ActiveCallbacks[i];
					if (cObj.ObjectCallback == null) continue;
					if (cObj.ptr_HitCounter == IntPtr.Zero) continue;

					if (MiniMem.AttachedProcess.ProcessHandle == IntPtr.Zero) continue;
					uint r = MiniMem.ReadMemory<uint>(cObj.ptr_HitCounter.ToInt64());
					if (r != cObj.LastValue)
					{
						MiniMem.ActiveCallbacks.Remove(cObj);

						cObj.LastValue = r;
						MiniMem.ActiveCallbacks.Add(cObj);
						cObj.ObjectCallback?.Invoke(cObj);
					}
				}
				if (bCallbackThreadExitFlag)
					break;
					
				Thread.Sleep(25);
			}

			bCallbackThreadExitFlag = false;
		}

		// Marshalling for the Read Methods
		public static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
		{
			var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
			try
			{
				return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
			}
			finally
			{
				handle.Free();
			}
		}

		// Marshalling for the Write Methods
		public static byte[] StructureToByteArray(object obj)
		{
			var length = Marshal.SizeOf(obj);

			var array = new byte[length];

			var pointer = Marshal.AllocHGlobal(length);

			Marshal.StructureToPtr(obj, pointer, true);
			Marshal.Copy(pointer, array, 0, length);
			Marshal.FreeHGlobal(pointer);

			return array;
		}

		public static int CalculateLowestAlignedSize(byte[] buff, int extraBytes = 0)
		{
			if (buff == null) return 0x10000; // Yolo it and return 0x10000;

			int ret = buff.Length + extraBytes;
			while (ret % 0x10000 != 0)
			{
				ret += 1;
			}

			return ret;
		}

		/*
		private IntPtr FindFreeBlockForRegion(IntPtr baseAddress, int size)
		{
			IntPtr minAddress = IntPtr.Subtract(baseAddress, 0x70000000);
			IntPtr maxAddress = IntPtr.Add(baseAddress, 0x70000000);

			IntPtr ret = IntPtr.Zero;
			IntPtr tmpAddress = IntPtr.Zero;

			Native.GetSystemInfo(out Constants.SYSTEM_INFO si);

			if (MiniMem.AttachedProcess.Is64Bit())
			{
				if ((long)minAddress > (long)si.maximumApplicationAddress ||
					(long)minAddress < (long)si.minimumApplicationAddress)
					minAddress = si.minimumApplicationAddress;

				if ((long)maxAddress < (long)si.minimumApplicationAddress ||
					(long)maxAddress > (long)si.maximumApplicationAddress)
					maxAddress = si.maximumApplicationAddress;
			}
			else
			{
				minAddress = si.minimumApplicationAddress;
				maxAddress = si.maximumApplicationAddress;
			}

			IntPtr current = minAddress;
			IntPtr previous = current;

			while (Native.VirtualQueryEx(MiniMem.AttachedProcess.ProcessHandle, current, out var mbi, (uint)new IntPtr(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>())) != 0)
			{
				if ((long)mbi.BaseAddress > (long)maxAddress)
					return IntPtr.Zero;  // No memory found, let windows handle

				//              MEM_FREE
				if (mbi.State == 0x10000 && mbi.RegionSize.ToInt32() > size)
				{
					if ((long)mbi.BaseAddress % si.allocationGranularity > 0)
					{
						// The whole size can not be used
						tmpAddress = mbi.BaseAddress;
						int offset = (int)(si.allocationGranularity -
										   ((long)tmpAddress % si.allocationGranularity));

						// Check if there is enough left
						if ((mbi.RegionSize.ToInt32() - offset) >= size)
						{
							// yup there is enough
							tmpAddress = IntPtr.Add(tmpAddress, offset);

							if ((long)tmpAddress < (long)baseAddress)
							{
								tmpAddress = IntPtr.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

								if ((long)tmpAddress > (long)baseAddress)
									tmpAddress = baseAddress;

								// decrease tmpAddress until its alligned properly
								tmpAddress = IntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
							}

							// if the difference is closer then use that
							if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
								ret = tmpAddress;
						}
					}
					else
					{
						tmpAddress = mbi.BaseAddress;

						if ((long)tmpAddress < (long)baseAddress) // try to get it the cloest possible 
																  // (so to the end of the region - size and
																  // aligned by system allocation granularity)
						{
							tmpAddress = IntPtr.Add(tmpAddress, (int)(mbi.RegionSize - size));

							if ((long)tmpAddress > (long)baseAddress)
								tmpAddress = baseAddress;

							// decrease until aligned properly
							tmpAddress =
								IntPtr.Subtract(tmpAddress, (int)((long)tmpAddress % si.allocationGranularity));
						}

						if (Math.Abs((long)tmpAddress - (long)baseAddress) < Math.Abs((long)ret - (long)baseAddress))
							ret = tmpAddress;
					}
				}

				if (mbi.RegionSize.ToInt32() % si.allocationGranularity > 0)
					mbi.RegionSize += si.allocationGranularity - (mbi.RegionSize.ToInt32() % si.allocationGranularity);

				previous = current;
				current = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);

				if ((long)current > (long)maxAddress)
					return ret;

				if ((long)previous > (long)current)
					return ret; // Overflow
			}

			return ret;
		}

	*/
		public static IntPtr CalculateRelativeOffset(IntPtr origin, IntPtr dest)
		{
			// Use this for relative instructions such as JMP or CALL etc etc

			if (origin == IntPtr.Zero || dest == IntPtr.Zero)
			{
				if (origin == IntPtr.Zero)
				{
					throw new Exception($"IntPtr Origin was Zero!");
				} else if (dest == IntPtr.Zero)
				{
					throw new Exception($"IntPtr Dest was Zero!");
				}
			}
				

			return IntPtr.Subtract(dest, origin.ToInt32());
		}

		public static string getObjectTypeName(SYSTEM_HANDLE_INFORMATION shHandle, Process process)
		{
			var m_ipProcessHwnd = Native.OpenProcess((int)ProcessAccessFlags.All, false, process.Id);
			var ipHandle = IntPtr.Zero;
			var objBasic = new OBJECT_BASIC_INFORMATION();
			var ipBasic = IntPtr.Zero;
			var objObjectType = new OBJECT_TYPE_INFORMATION();
			var ipObjectType = IntPtr.Zero;
			var ipObjectName = IntPtr.Zero;
			var strObjectTypeName = "";
			var nLength = 0;
			var nReturn = 0;
			var ipTemp = IntPtr.Zero;

			if (!Native.DuplicateHandle(m_ipProcessHwnd, shHandle.Handle,
				Native.GetCurrentProcess(), out ipHandle,
				0, false, DUPLICATE_SAME_ACCESS))
				return null;

			ipBasic = Marshal.AllocHGlobal(Marshal.SizeOf(objBasic));
			Native.NtQueryObject(ipHandle, (int)ObjectInformationClass.ObjectBasicInformation,
				ipBasic, Marshal.SizeOf(objBasic), ref nLength);
			objBasic = (OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(ipBasic, objBasic.GetType());
			Marshal.FreeHGlobal(ipBasic);

			ipObjectType = Marshal.AllocHGlobal(objBasic.TypeInformationLength);
			nLength = objBasic.TypeInformationLength;
			while ((uint)(nReturn = Native.NtQueryObject(
					   ipHandle, (int)ObjectInformationClass.ObjectTypeInformation, ipObjectType,
					   nLength, ref nLength)) ==
				   STATUS_INFO_LENGTH_MISMATCH)
			{
				Marshal.FreeHGlobal(ipObjectType);
				ipObjectType = Marshal.AllocHGlobal(nLength);
			}

			objObjectType = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(ipObjectType, objObjectType.GetType());
			if (Is64Bits())
				ipTemp = new IntPtr(Convert.ToInt64(objObjectType.Name.Buffer.ToString(), 10) >> 32);
			else
				ipTemp = objObjectType.Name.Buffer;

			strObjectTypeName = Marshal.PtrToStringUni(ipTemp, objObjectType.Name.Length >> 1);
			Marshal.FreeHGlobal(ipObjectType);
			return strObjectTypeName;
		}
		public static string getObjectName( SYSTEM_HANDLE_INFORMATION shHandle, Process process)
		{
			var m_ipProcessHwnd = Native.OpenProcess((int)ProcessAccessFlags.All, false, process.Id);
			var ipHandle = IntPtr.Zero;
			var objBasic = new OBJECT_BASIC_INFORMATION();
			var ipBasic = IntPtr.Zero;
			var ipObjectType = IntPtr.Zero;
			var objObjectName = new OBJECT_NAME_INFORMATION();
			var ipObjectName = IntPtr.Zero;
			var strObjectName = "";
			var nLength = 0;
			var nReturn = 0;
			var ipTemp = IntPtr.Zero;

			if (!Native.DuplicateHandle(m_ipProcessHwnd, shHandle.Handle, Native.GetCurrentProcess(),
				out ipHandle, 0, false, DUPLICATE_SAME_ACCESS))
				return null;

			ipBasic = Marshal.AllocHGlobal(Marshal.SizeOf(objBasic));
			Native.NtQueryObject(ipHandle, (int)ObjectInformationClass.ObjectBasicInformation,
				ipBasic, Marshal.SizeOf(objBasic), ref nLength);
			objBasic = (OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(ipBasic, objBasic.GetType());
			Marshal.FreeHGlobal(ipBasic);


			nLength = objBasic.NameInformationLength;

			ipObjectName = Marshal.AllocHGlobal(nLength);
			while ((uint)(nReturn = Native.NtQueryObject(
					   ipHandle, (int)ObjectInformationClass.ObjectNameInformation,
					   ipObjectName, nLength, ref nLength))
				   == STATUS_INFO_LENGTH_MISMATCH)
			{
				Marshal.FreeHGlobal(ipObjectName);
				ipObjectName = Marshal.AllocHGlobal(nLength);
			}
			objObjectName = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ipObjectName, objObjectName.GetType());

			ipTemp = Is64Bits() ? new IntPtr(Convert.ToInt64(objObjectName.Name.Buffer.ToString(), 10) >> 32) : objObjectName.Name.Buffer;

			if (ipTemp != IntPtr.Zero)
			{
				var baTemp2 = new byte[nLength];
				try
				{
					Marshal.Copy(ipTemp, baTemp2, 0, nLength);

					strObjectName = Marshal.PtrToStringUni(Is64Bits() ? new IntPtr(ipTemp.ToInt64()) : new IntPtr(ipTemp.ToInt32()));
					return strObjectName;
				}
				catch (AccessViolationException)
				{
					Console.WriteLine("[WARNING] Access violation!");
					return null;
				}
				finally
				{
					Marshal.FreeHGlobal(ipObjectName);
					Native.CloseHandle(ipHandle);
				}
			}

			return null;
		}
		public static List<HandleInformation> GetHandlesByType(string strHandleType = "Directory")
		{
			uint nStatus;
			var nHandleInfoSize = 0x10000;
			var ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
			var nLength = 0;
			var ipHandle = IntPtr.Zero;

			while ((nStatus = Native.NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ipHandlePointer,
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

			List<HandleInformation> toReturn = new List<HandleInformation>();
			SYSTEM_HANDLE_INFORMATION shHandle;
			HandleInformation realInfo;

			for (long lIndex = 0; lIndex < lHandleCount; lIndex++)
			{
				shHandle = new SYSTEM_HANDLE_INFORMATION();
				realInfo = new HandleInformation();

				if (Is64Bits())
				{
					shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
					ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
				}
				else
				{
					ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
					shHandle = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
				}

				if (MiniMem.AttachedProcess.ProcessObject != null)
					if (shHandle.ProcessID != MiniMem.AttachedProcess.ProcessObject.Id) continue;

				if (strHandleType != null)
				{
					var strObjectTypeName = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
					if (strObjectTypeName != strHandleType) continue;
				}

				realInfo.HandleName = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
				realInfo.Advanced = shHandle;

				if (realInfo.HandleName == null) continue;

				toReturn.Add(realInfo);
			}
			return toReturn;
		}
		public static bool Is64Bits()
		{
			return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
		}
	}
}
