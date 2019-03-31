using System;
using static MiniMem.Constants;
using Mem = MiniMem.MiniMem;

namespace Test
{
	class Program
	{
		[STAThread]
		static void Main(string[] args)
		{
			if (!Mem.Attach("game.bin"))
			{
				Environment.Exit(-1);
			}

			

			CallbackObject obj;
			CallbackDelegate CodeExecutedEvent = MyCallbackEvent;

			IntPtr addr = Mem.FindPatternSingle(Mem.FindProcessModule("game.bin", false), "33 FF 39 78 08 0F 8E ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0");
			if (addr == IntPtr.Zero) return;
			bool result = Mem.CreateTrampolineAndCallback(
				addr, // Target Address,
				5, // targetAddressInstructionCount
				new string [] // Mnemonics to be injected
				{
					
					// here will our register dump mnemonic be placed is ImplementRegisterDump is true
					// Here will the inc instruction will be placed in our case if ImplementCallback is true
					// Here will the jump back out to (Target Address + 5) be placed
				},
				CodeExecutedEvent, // codeExecutedEventDelegate
				out  obj,// Created Callback Object
				"CharWnd",
				true, // ShouldSuspend
				true, // PreserveOriginalInstruction
				true, // ImplementCallback
				true // ImplementRegisterDump
			);

			if (obj != null && result)
			{
				Mem.ActiveCallbacks.Add(obj);

				Console.ReadLine();
				Mem.Detach();
			}
			
			/*
			Thread t = new Thread(CallbackLoop);
			t.Start();

			Thread s = new Thread(HackLoop);
			s.Start();


			//InstallCharacterWndHook();
			//InstallFishingWndHook();

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
			*/
		}

		
		public static void MyCallbackEvent(object callbackObject)
		{
			
			if (callbackObject == null) return;
			CallbackObject obj = (CallbackObject)callbackObject;

			Registers r = Mem.ReadMemory<Registers>(obj.class_TrampolineInfo.optionalRegisterStructPointer.ToInt64());
			Console.WriteLine($"EAX VALUE: 0x{r.EAX:X}");
		}

	}
}
