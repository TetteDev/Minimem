﻿using System;
using System.Reflection;
using System.Runtime.InteropServices;
using static MiniMem.Constants;

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
			else
			{
				ProcModule pm = MiniMem.FindProcessModule(MiniMem.AttachedProcess.ProcessObject.ProcessName); // Get "main" module
				if (pm != null)
				{
					return ptr.ToInt32() >= pm.BaseAddress.ToInt32() &&
					       ptr.ToInt32() <= pm.EndAddress.ToInt32();
				}
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

	public class Helper
	{
		public class MarshalCache<T>
		{
			// Token: 0x0600008B RID: 139 RVA: 0x000010EC File Offset: 0x000004EC
			// Note: this type is marked as 'beforefieldinit'.
			static MarshalCache()
			{
				Type typeFromHandle = typeof(T);
				MarshalCache<T>.TypeCode = Type.GetTypeCode(typeFromHandle);
				if (typeFromHandle == typeof(bool))
				{
					MarshalCache<T>.Size = 1;
					MarshalCache<T>.RealType = typeFromHandle;
				}
				else if (typeFromHandle.IsEnum)
				{
					Type enumUnderlyingType = typeFromHandle.GetEnumUnderlyingType();
					MarshalCache<T>.Size = Marshal.SizeOf(enumUnderlyingType);
					MarshalCache<T>.RealType = enumUnderlyingType;
					MarshalCache<T>.TypeCode = Type.GetTypeCode(MarshalCache<T>.RealType);
				}
				else
				{
					MarshalCache<T>.RealType = typeFromHandle;
					MarshalCache<T>.Size = Marshal.SizeOf(MarshalCache<T>.RealType);
				}
				MarshalCache<T>.IsIntPtr = (MarshalCache<T>.RealType == typeof(IntPtr));
				MarshalCache<T>.SizeU = (uint)MarshalCache<T>.Size;
				MarshalCache<T>.TypeRequireMarshal = MarshalCache<T>.IsTypeRequireMarshal(MarshalCache<T>.RealType);
			}

			// Token: 0x0600008C RID: 140 RVA: 0x00005AB4 File Offset: 0x00004EB4
			[return: MarshalAs(UnmanagedType.U1)]
			private static bool IsTypeRequireMarshal(Type t)
			{
				FieldInfo[] fields = t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
				int num = 0;
				if (0 < fields.Length)
				{
					while (fields[num].GetCustomAttributes(typeof(MarshalAsAttribute), true).Length <= 0)
					{
						num++;
						if (num >= fields.Length)
						{
							return false;
						}
					}
					return true;
				}
				return false;
			}

			// Token: 0x04000094 RID: 148
			public static Type RealType;

			// Token: 0x04000095 RID: 149
			public static int Size;

			// Token: 0x04000096 RID: 150
			public static uint SizeU;

			// Token: 0x04000097 RID: 151
			public static TypeCode TypeCode;

			// Token: 0x04000098 RID: 152
			public static bool TypeRequireMarshal;

			// Token: 0x04000099 RID: 153
			public static bool IsIntPtr;
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
	}
}
