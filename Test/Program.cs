using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using static MiniMem.Constants;
using MiniMem;
using static MiniMem.Helper;
using Mem = MiniMem.MiniMem;
using System.Windows.Forms;

namespace Test
{
	class Program
	{
		[StructLayout(LayoutKind.Explicit)]
		public struct CharacterWnd
		{
			[FieldOffset(0x28)] public int DEF;
			[FieldOffset(0x24)] public int MaxHP;
			[FieldOffset(0x8)] public int CurrentHP;
			[FieldOffset(0x10)] public int Level;
			[FieldOffset(0x48)] public int DMG;
			[FieldOffset(0x2C)] public int EVA;
			[FieldOffset(0x30)] public int CritDMG;
			[FieldOffset(0x20)] public int SPD;
			[FieldOffset(0x1C)] public int CRIT;
			[FieldOffset(0x18)] public int MovementSpeedPercentage;
			//[FieldOffset(0x14)] public IntPtr floatMovementSpeedPointer;

			[FieldOffset(0xE4)] public int FishingDurability;
			[FieldOffset(0x54)] public int Gearscore;

			[FieldOffset(0x130), MarshalAs(UnmanagedType.LPUTF8Str)]
			public string PlayerName;
		}

		[StructLayout(LayoutKind.Explicit)]
		public struct FishingWnd
		{
			[MarshalAs(UnmanagedType.LPUTF8Str)]
			[FieldOffset(0x8)]
			public string WindowName;

			[FieldOffset(0x24c)]
			public float BlueRangeMax;

			[FieldOffset(0x250)]
			public float BlueRangeMin;

			[FieldOffset(0x26C)]
			public float LineValue;
		}
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

		public static IntPtr MovementSpeedAddress = IntPtr.Zero;
		public static IntPtr FisingWndBase = IntPtr.Zero;
		
		[STAThread]
		static void Main(string[] args)
		{
			if (!Mem.Attach("game.bin"))
			{
				Environment.Exit(-1);
			}

			Thread t = new Thread(CallbackLoop);
			t.Start();

			Thread s = new Thread(HackLoop);
			s.Start();


			//InstallCharacterWndHook();
			InstallFishingWndHook();

			Console.WriteLine("Enter anything to remove all hooks:");
			Console.Title = "Enter anything and press enter to remove all hooks";
			string resp = Console.ReadLine();

			if (!string.IsNullOrWhiteSpace(resp))
			{
				s.Abort();
				t.Abort();

				foreach (CallbackObject obj in Mem.ActiveCallbacks)
				{
					Mem.WriteBytes(obj.class_TrampolineInfo.TrampolineOrigin, obj.class_TrampolineInfo.OriginalBytes);
					Mem.FreeMemory(obj.class_TrampolineInfo.AllocatedMemory);
					Console.WriteLine("Restored stuff for object '" + obj.str_CallbackIdentifier + "'!");
				}
			}
		}

		public static void InstallCharacterWndHook()
		{
			var targetAddress = Mem.FindPatternSingle(
				Mem.FindProcessModule("game.bin", false),
				"E8 ?? ?? ?? ?? 83 C4 04 8B 47 24 8B 4F 08 50 51",
				true);

			if (!targetAddress.IsValid(Mem.FindProcessModule("game.bin", false))) return;

			TrampolineInstance CharacterWnd_Detour = Mem.CreateTrampolineInstance(targetAddress.ToInt64() + 8,
				6, true, true, true
			);

			CallbackObject CharacterWnd_Detour_Object = Mem.CreateCallback(CharacterWnd_Detour, "CharacterWnd");
			CharacterWnd_Detour_Object.ObjectCallback = MovementSpeedCallback;
			Mem.ActiveCallbacks.Add(CharacterWnd_Detour_Object);
		}
		public static void InstallFishingWndHook()
		{
			//ESI
			TrampolineInstance FishingWnd_Detour = Mem.CreateTrampolineInstance(0x00BAF2AD,
				6, true, true, true
			);

			CallbackObject FishingWnd_Detour_Object = Mem.CreateCallback(FishingWnd_Detour, "FishingWnd");
			FishingWnd_Detour_Object.ObjectCallback = FishingWndCallback;
			Mem.ActiveCallbacks.Add(FishingWnd_Detour_Object);
		}

		public static void MovementSpeedCallback(object obj)
		{
			if (obj == null) return;
			CallbackObject cast = (CallbackObject) obj;

			Registers Read = Mem.ReadMemory<Registers>(cast.class_TrampolineInfo.optionalRegisterStructPointer.ToInt64());

			if (Read.EDI > 0)
			{
				IntPtr movTmp = new IntPtr(Read.EDI + 20);
				if (MovementSpeedAddress != movTmp || MovementSpeedAddress == IntPtr.Zero)
				{
					MovementSpeedAddress = movTmp;
				} 
			}

			PrintProperties(Read, true);
			Console.WriteLine(Environment.NewLine);
		}
		public static void FishingWndCallback(object obj)
		{
			if (obj == null) return;
			CallbackObject cast = (CallbackObject)obj;

			Registers Read = Mem.ReadMemory<Registers>(cast.class_TrampolineInfo.optionalRegisterStructPointer.ToInt64());
			if (Read.ESI > 0)
			{
				IntPtr tmp = new IntPtr(Read.ESI);
				if (FisingWndBase != tmp)
				{
					FisingWndBase = tmp;
				}
			}
		}

		public static void HackLoop()
		{
			while (true)
			{
				if (MovementSpeedAddress != IntPtr.Zero) 
					Mem.WriteMemory<float>(MovementSpeedAddress.ToInt64(), 18f);

				if (FisingWndBase != IntPtr.Zero)
				{
					FishingWnd f = Mem.ReadMemory<FishingWnd>(FisingWndBase.ToInt64());
					float center = (f.BlueRangeMin + f.BlueRangeMax) / 2f;
					Mem.Log("Center Value is " + center);
					Mem.WriteMemory<float>(FisingWndBase.ToInt64() + 0x26c, center);
				}

				Thread.Sleep(25);
			}
		}

		public static void CallbackLoop()
		{
			while (true)
			{
				if (Mem.ActiveCallbacks.Count < 1)
				{
					Thread.Sleep(25);
					continue;
				}

				for (int i = Mem.ActiveCallbacks.Count - 1; i >= 0; i--)
				{
					CallbackObject cObj = Mem.ActiveCallbacks[i];
					if (cObj.ObjectCallback == null) continue;
					if (cObj.ptr_HitCounter == IntPtr.Zero) continue;

					uint r = Mem.ReadMemory<uint>(cObj.ptr_HitCounter.ToInt64());
					if (r != cObj.LastValue)
					{
#if DEBUG
						//Mem.Log($"Callback triggered for callback object '{cObj.str_CallbackIdentifier}' (HitCount: {r})");
#endif
						Mem.ActiveCallbacks.Remove(cObj);

						cObj.LastValue = r;
						Mem.ActiveCallbacks.Add(cObj);
						cObj.ObjectCallback?.Invoke(cObj);
					}
				}
				Thread.Sleep(750);
			}
		}


	

		public static void CallbackCharWnd(object callbackObject)
		{
			/*
			if (callbackObject == null) return;
			Registers Registers = new Registers();

			CallbackObject obj = (CallbackObject) callbackObject;
			while (true)
			{
				uint CurrentHitCountValue = Mem.ReadMemory<uint>(obj.ptr_HitCounter.ToInt64());
				if (CurrentHitCountValue == 0)
				{
					Console.WriteLine("Please press 'C' ingame once!");
					Thread.Sleep(1000);
					continue;
				}

				if (LastHitCountValue != CurrentHitCountValue)
				{
					// Our function executed and the "dumped" registers have been updated

					// Read the registers from memory
					Registers = Mem.ReadMemory<Registers>(obj.class_TrampolineInfo.optionalRegisterStructPointer.ToInt64());
					//LastHitCountValue = CurrentHitCountValue;
				}

				if (Registers.EDI != 0)
				{
					Console.WriteLine($"Movement Speed Address 0x{(Registers.EDI + 20):X}");
					Mem.WriteBytes(obj.class_TrampolineInfo.TrampolineOrigin, obj.class_TrampolineInfo.OriginalBytes);
					break;
				}

				Thread.Sleep(25);
			}

			Mem.FreeMemory(obj.class_TrampolineInfo.AllocatedMemory);
			Console.WriteLine("Patch has been undone and thread has exited!");
			Console.ReadLine();
			*/
		}
		public static void DumpRegistersDetour()
		{
			/*
			var targetAddress = Mem.FindPatternSingle(
				Mem.FindProcessModule("game.bin", false),
				"E8 ?? ?? ?? ?? 83 C4 04 8B 47 24 8B 4F 08 50 51",
				true);

			//var targetAddress = Mem.FindPatternSingle(Mem.FindProcessModule("game.bin", false),
			//"8B 4F 08 50 51 8D 55 D0 68 ? ? ? ? 52", true);
			if (targetAddress == IntPtr.Zero) throw new Exception("OUTDATED PATTERN");
			//Constants.RegisterDump result = Mem.DumpRegisters(targetAddress.ToInt64() + 8, 6, true);

			if (result.RegisterPointer != IntPtr.Zero)
			{
				Console.WriteLine("Successfully placed register dump detour!");

				Constants.Registers read = new Constants.Registers();
				while (read.EDI == 0)
				{
					read = Mem.ReadMemory<Constants.Registers>(result.RegisterPointer.ToInt64());
					Thread.Sleep(1000);
					Console.WriteLine("Re-reading struct location (0x" + result.RegisterPointer.ToInt32().ToString("X") + ")");
				}

				object threadParameters = new object[2] { result.HitcountPtr, result.RegisterPointer };
				Thread t = new Thread(new ParameterizedThreadStart(Callback));
				t.Start(threadParameters); // Start callback thread
				PrintProperties(read, true);

				Console.WriteLine("HitCount Address: 0x" + result.HitcountPtr.ToString("X"));
				Console.WriteLine("Do you wanna remove the detour?: ");
				string resp = Console.ReadLine();
				if (resp.ToLower().StartsWith("y"))
				{
					//bool restoreResult = Mem.TryRestoreTrampolineState(result.TrampolineInformation);
					Console.WriteLine("Did remove trampoline successfully: " + restoreResult.ToString());
				}

				int x = 1;
			}
			else
			{
				Console.WriteLine("[error] Something went wrong");
			}
			int y = 1;
			*/
		}
		public static void BasicDetourEDI()
		{
			// Backup: 8B 4F 08 50 51 8D 55 D0 68 ? ? ? ? 52 (No offset needed)
			var targetAddress = Mem.FindPatternSingle(
				Mem.FindProcessModule("game.bin", false),
				"E8 ?? ?? ?? ?? 83 C4 04 8B 47 24 8B 4F 08 50 51",
				true);

			//var targetAddress = Mem.FindPatternSingle(Mem.FindProcessModule("game.bin", false),
			//"8B 4F 08 50 51 8D 55 D0 68 ? ? ? ? 52", true);
			if (targetAddress == IntPtr.Zero) throw new Exception("OUTDATED PATTERN");

			var ptrCharWnd = Mem.AllocateMemory(Marshal.SizeOf(typeof(int)), Constants.MemoryProtection.ExecuteReadWrite,
				Constants.AllocationType.Commit | Constants.AllocationType.Reserve);
			if (ptrCharWnd.Pointer == IntPtr.Zero) throw new Exception("VIRTUAL ALLOC FAILED");

			byte[] code = Mem.Assemble(new[]
			{
				"use32",
				$"mov [{ptrCharWnd.Pointer}],edi"
			});

			/*
			var ret = Mem.CreateTrampoline(
				targetAddress: targetAddress.ToInt32() + 8,
				instructionCount: 6,
				codecaveBytes: code,
				preserveOriginalInstruction: true,
				shouldSuspend: true,
				identifier: "localplayer");
			*/

			Console.WriteLine("Trampoline done!"); // Put breakpoint here
			// When the breakpoint hits, open the address of 'ptrCharWnd' in CE and send me a screenshot

			while (Mem.ReadMemory<int>(ptrCharWnd.Pointer.ToInt64()) == 0)
			{
				Thread.Sleep(500);
				Console.WriteLine("Open character window once ingame! ('C' Key)");
			}

			CharacterWnd read = Mem.ReadMemory<CharacterWnd>(Mem.ReadMemory<int>(ptrCharWnd.Pointer.ToInt64()));
			Console.WriteLine("\n\nChar Window Pointer: 0x" + ptrCharWnd.Pointer.ToString("X"));
			Console.WriteLine("Movespeed Pointer: 0x" + (ptrCharWnd.Pointer.ToInt32() + 14).ToString("X"));

			PrintProperties(read);
			Console.ReadLine();
		}
	}
}
