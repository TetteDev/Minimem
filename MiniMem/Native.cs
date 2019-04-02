using System;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using Microsoft.VisualBasic.CompilerServices;

namespace MiniMem
{
	public class Native
	{
		public delegate IntPtr OpenProcessDelegate(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
		public static OpenProcessDelegate OpenProcess = CreateAPI<OpenProcessDelegate>("kernel32.dll", "OpenProcess");

		public delegate bool ReadProcessMemoryDelegate(int hProcess, IntPtr lpBaseAddress, byte[] buffer, int size, ref int lpNumberOfBytesRead);
		public static ReadProcessMemoryDelegate ReadProcessMemory = CreateAPI<ReadProcessMemoryDelegate>("kernel32.dll", "ReadProcessMemory");

		public delegate bool WriteProcessMemoryDelegate(int hProcess, int lpBaseAddress, byte[] buffer, int size, out int lpNumberOfBytesWritten);
		public static WriteProcessMemoryDelegate WriteProcessMemory = CreateAPI<WriteProcessMemoryDelegate>("kernel32.dll", "WriteProcessMemory");

		public delegate bool VirtualProtectExDelegate(IntPtr hProcess, IntPtr lpAddress, int nSize, uint flNewProtect, out uint lpflOldProtect);
		public static VirtualProtectExDelegate VirtualProtectEx = CreateAPI<VirtualProtectExDelegate>("kernel32.dll", "VirtualProtectEx");

		public delegate bool VirtualFreeExDelegate(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);
		public static VirtualFreeExDelegate VirtualFreeEx = CreateAPI<VirtualFreeExDelegate>("kernel32.dll", "VirtualFreeEx");

		public delegate bool CloseHandleDelegate(IntPtr handle);
		public static CloseHandleDelegate CloseHandle = CreateAPI<CloseHandleDelegate>("kernel32.dll", "CloseHandle");

		public delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
		public static VirtualAllocExDelegate VirtualAllocEx = CreateAPI<VirtualAllocExDelegate>("kernel32.dll", "VirtualAllocEx");

		public delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
		public static CreateRemoteThreadDelegate CreateRemoteThread = CreateAPI<CreateRemoteThreadDelegate>("kernel32.dll", "CreateRemoteThread");

		public delegate uint WaitForSingleObjectDelegate(IntPtr hProcess, uint dwMilliseconds);
		public static WaitForSingleObjectDelegate WaitForSingleObject = CreateAPI<WaitForSingleObjectDelegate>("kernel32.dll", "WaitForSingleObject");

		public delegate int VirtualQueryExDelegate(IntPtr hProcess, IntPtr lpAddress, out Constants.MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
		public static VirtualQueryExDelegate VirtualQueryEx = CreateAPI<VirtualQueryExDelegate>("kernel32.dll", "VirtualQueryEx");

		[DllImport("ntdll.dll")]
		public static extern uint NtQuerySystemInformation(
			int systemInformationClass,
			IntPtr systemInformation,
			int systemInformationLength,
			ref int returnLength);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
			ushort hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
			uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

		[DllImport("ntdll.dll")]
		public static extern int NtQueryObject(IntPtr ObjectHandle, int
				ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength,
			ref int returnLength);

		[DllImport("kernel32.dll")]
		public static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll")]
		public static extern uint SuspendThread(IntPtr hThread);
		[DllImport("kernel32.dll")]
		public static extern int ResumeThread(IntPtr hThread);
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenThread(Constants.ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

		[DllImport("kernel32.dll")]
		public static extern void GetSystemInfo(out Constants.SYSTEM_INFO lpSystemInfo);


		[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool IsWow64Process([In] IntPtr processHandle,
			[Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

		public static T CreateAPI<T>(string containingDll, string methodName)
		{
			var asmb = AppDomain.CurrentDomain.DefineDynamicAssembly(new AssemblyName(Assembly.GetExecutingAssembly().FullName), AssemblyBuilderAccess.RunAndSave);
			var modb = asmb.DefineDynamicModule(MethodBase.GetCurrentMethod().Name);
			var declaringType = MethodBase.GetCurrentMethod().DeclaringType;
			if (declaringType == null) throw new InvalidOperationException();
			var tb = modb.DefineType(declaringType.Name, TypeAttributes.Public);
			var mi = typeof(T).GetMethods()[0];

			var mb = tb.DefinePInvokeMethod(methodName,
				containingDll,
				MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl,
				CallingConventions.Standard,
				mi.ReturnType, mi.GetParameters().Select(pI => pI.ParameterType).ToArray(),
				CallingConvention.Winapi,
				CharSet.Ansi);

			mb.SetImplementationFlags(mb.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);

			return Conversions.ToGenericParameter<T>(Delegate.CreateDelegate(typeof(T), tb.CreateType().GetMethod(methodName) ?? throw new InvalidOperationException()));
		}
	}
}
